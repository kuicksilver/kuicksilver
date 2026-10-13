// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(ExperimentalKuicksilverApi::class)

package io.kuicksilver.quic.core

import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.quic.ConnectionCore
import io.kuicksilver.quic.ConnectionEvent
import io.kuicksilver.quic.ConnectionState
import io.kuicksilver.quic.PathState
import io.kuicksilver.quic.QuicException
import io.kuicksilver.quic.TimeMark
import io.kuicksilver.quic.TransportError
import io.kuicksilver.quic.VersionProfile
import io.kuicksilver.quic.recovery.LossDetection
import io.kuicksilver.quic.recovery.Pacer
import io.kuicksilver.quic.recovery.SpaceId
import io.kuicksilver.quic.wire.ConnectionId
import io.kuicksilver.quic.wire.QuicWireException
import io.kuicksilver.quic.wire.TransportParameters
import io.kuicksilver.quic.wire.TransportParametersCodec
import io.kuicksilver.quic.wire.VersionNegotiationValidator
import io.kuicksilver.quic.wire.localTransportParameters
import io.kuicksilver.tls.Aead
import io.kuicksilver.tls.Certificate
import io.kuicksilver.tls.Direction
import io.kuicksilver.tls.EarlyDataState
import io.kuicksilver.tls.PacketProtector
import io.kuicksilver.tls.QuicSessionTicket
import io.kuicksilver.tls.TlsException
import io.kuicksilver.tls.TlsRole
import kotlin.time.Duration.Companion.milliseconds

// The handshake half of [ConnectionCore]: transport parameters, Initial keys, Retry, TLS driving, key limits, space discard,
// handshake confirmation and version negotiation (RFC 9000 sections 6, 7 and 17.2.5; RFC 9001; RFC 9368).

internal fun ConnectionCore.buildLocalTp(): TransportParameters {
    val tp = config.localTransportParameters(role, localCid, if (role == TlsRole.Server) odcid else null)
    // RFC 9000 section 18.2: the token of the handshake connection ID
    if (role == TlsRole.Server) tp.statelessResetToken = cids.localToken(0)
    if (role ==
        TlsRole.Server
    ) {
        retryScid?.let {
            tp.retrySourceConnectionId =
                if (testForgeRetryScid) ConnectionId(ByteArray(8) { 0x66 }) else it
        }
    }
    if (testForgeInitialSourceCid) tp.initialSourceConnectionId = ConnectionId(ByteArray(8) { 0x77 })
    if (testForgeChosenVersion &&
        tp.availableVersions != null
    ) {
        tp.chosenVersion = tp.availableVersions!!.first { it != tp.chosenVersion }
    }
    if (testAdvertisePreferredAddress) tp.preferredAddressPresent = true
    // client: Chosen Version is the one in use (after a Version Negotiation restart it differs from the configured head); server: ksl rewrites it to the negotiated one
    if (role == TlsRole.Client && tp.availableVersions != null && !testForgeChosenVersion) tp.chosenVersion = version.version
    return tp
}

/** Re-encodes the local transport parameters (test hooks set after construction, before the first drive). */
internal fun ConnectionCore.refreshLocalTp() {
    handshake.session.setTransportParameters(TransportParametersCodec.encode(buildLocalTp(), role, 27))
}

internal fun ConnectionCore.installInitialKeys(profile: VersionProfile) {
    val (r, w) = crypto.initialProtectors(initialKeyCid.toByteArray(), profile.version, role)
    readKeys[0]?.close()
    writeKeys[0]?.close()
    readKeys[0] = r
    writeKeys[0] = w
}

/**
 * The client accepted a Retry (RFC 9000 section 17.2.5.2): new Initial keys from the Retry SCID, the token travels
 * in every following Initial, the first flight leaves the loss and congestion state without counting as loss
 * (RFC 9002 section 6.3) and its CRYPTO data is queued again; packet numbers continue.
 */
internal fun ConnectionCore.onRetry(
    scid: ConnectionId,
    token: ByteArray,
) {
    retryScid = scid
    retryToken = token
    remoteCid = scid
    // the Retry SCID is only the DCID of our next Initials, never a peer connection ID of its own: the server's Initial SCID becomes
    // sequence 0 (RFC 9000 sections 7.2, 5.1.1)
    initialKeyCid = scid
    val sp = loss.space(SpaceId.Initial)
    for (p in sp.sent) {
        val f = p.frames
        for (i in 0 until f.cryptoCount) cryptoStreams.send[f.cryptoLevel[i]].onLost(f.cryptoOffset[i], f.cryptoLength[i])
    }
    loss.discard(SpaceId.Initial, now)
    // 0-RTT sent before the Retry reached a server that kept no state: send it again (RFC 9001 section 4.6.2 allows 0-RTT after a Retry)
    loss.discardZeroRtt { p -> streams.onFramesLost(p.frames) }
    installInitialKeys(version)
    receiver.reset()
}

internal fun ConnectionCore.driveTls(now: TimeMark) {
    if (state == ConnectionState.Closing || state == ConnectionState.Draining || state == ConnectionState.Closed) return
    try {
        handshake.drive()
    } catch (e: QuicWireException) {
        fail(e.code, e.frameType, e.message ?: "", null)
    }
}

/** Counts one AEAD failure of [aead]; closes with AEAD_LIMIT_REACHED at the integrity limit. */
internal fun ConnectionCore.onAuthenticationFailure(aead: Aead) {
    authenticationFailures++
    val limit = if (aead == Aead.CHACHA20_POLY1305) config.limits.integrityLimitChaCha else config.limits.integrityLimitAesGcm
    if (authenticationFailures >= limit) fail(TransportError.AEAD_LIMIT_REACHED, 0, "AEAD integrity limit reached", null)
}

/** After sealing a 1-RTT packet: updates keys at 7/8 of the confidentiality limit, closes when the limit is hit with no update possible. */
internal fun ConnectionCore.onOneRttPacketSealed(pn: Long) {
    if (++oneRttSinceRotation >= config.limits.cidRotationPackets &&
        state == ConnectionState.Confirmed
    ) {
        oneRttSinceRotation = 0
        if (cids.rotatePeerCid()) remoteCid = cids.activePeerCid()
    } // rotate the peer's connection ID every 10 000 packets (RFC 9000 section 9.5: unlinkability)
    val kp = keyPhase ?: return
    kp.onPacketSent(pn)
    if (kp.write.aead == Aead.CHACHA20_POLY1305) return // 2^62 packets: unreachable in practice (RFC 9001 section 6.6)
    val limit = config.limits.confidentialityLimitAesGcm
    if (kp.packetsProtected >=
        limit
    ) {
        fail(TransportError.AEAD_LIMIT_REACHED, 0, "AEAD confidentiality limit reached without a possible key update", null)
        return
    }
    if (kp.packetsProtected >= limit - limit / 8 && kp.canInitiate(state == ConnectionState.Confirmed)) kp.initiate(now, pto())
}

internal fun ConnectionCore.discardSpace(space: SpaceId) {
    val i = space.ordinal
    if (spaceDiscarded[i]) return
    spaceDiscarded[i] = true
    val level = if (space == SpaceId.Initial) 0 else 2
    readKeys[level]?.close()
    writeKeys[level]?.close()
    readKeys[level] = null
    writeKeys[level] = null
    if (space == SpaceId.Initial) {
        initialReadOriginal?.close()
        initialReadOriginal = null
    }
    loss.discard(space, now)
    cryptoStreams.discard(level)
    receiver.dropBuffered(space)
}

internal fun ConnectionCore.onPeerInitialCid(cid: ConnectionId) {
    remoteCid = cid
    cids.adoptInitialPeerCid(cid)
}

internal fun ConnectionCore.confirmHandshake() {
    if (handshakeConfirmedAt != null || state == ConnectionState.Closing || state == ConnectionState.Draining ||
        state == ConnectionState.Closed
    ) {
        return
    }
    handshakeConfirmedAt = now
    state = ConnectionState.Confirmed
    loss.handshakeConfirmed = true
    loss.peerAddressValidated = true
    paths.all[0].let {
        if (it.state != PathState.Validated &&
            !(it.state == PathState.Validating && it.handshakeValidated)
        ) {
            it.state = PathState.Validated
            it.validatedAt = now
            paths.lastValidated =
                it
        }
        // the handshake validated the first path (RFC 9000 section 8.1); a challenge sent after a handshake-time rebind stays outstanding
        // until answered or settled
    }
    discardHandshakeKeysAfterPacket = true
}

/** Server side of a compatible upgrade (RFC 9368 section 2.3): send everything in [chosen] while still reading the client's Original Version Initials. */
internal fun ConnectionCore.switchServerVersion(chosen: VersionProfile) {
    version = chosen
    initialReadOriginal = readKeys[0]
    readKeys[0] = null
    val (r, w) = crypto.initialProtectors(initialKeyCid.toByteArray(), chosen.version, role)
    writeKeys[0]?.close()
    readKeys[0] = r
    writeKeys[0] = w
}

/** A Version Negotiation packet (RFC 9000 section 6.2): ignored after any server packet, after one we already acted on, or when it lists our version; otherwise restart or give up. */
internal fun ConnectionCore.onVersionNegotiation(offered: IntArray) {
    // section 6.2: at most one Version Negotiation is acted on
    if (role != TlsRole.Client || anyPeerPacket || state != ConnectionState.Handshaking || receivedVnVersions != null) return
    if (offered.contains(version.version)) return
    val next = config.versions.firstOrNull { offered.contains(it.version) }
    if (next ==
        null
    ) {
        silentClose(QuicException.ConnectionLost.VersionNegotiation(offered.toList(), config.versions.map { it.version }))
        return
    }
    receivedVnVersions = offered
    // the restarted handshake has no ticket left: 0-RTT data waits for 1-RTT, and the limits it used are checked at completion
    loss.discardZeroRtt { p -> streams.onFramesLost(p.frames) }
    for (i in 0 until 4) {
        readKeys[i]?.close()
        writeKeys[i]?.close()
        readKeys[i] = null
        writeKeys[i] = null
    }
    handshake.session.close()
    version = next
    handshake = HandshakeDriver(crypto.newSession(tlsConfig, earlyMode != EarlyDataState.Disabled), ConnectionHandshakeSink(this))
    handshake.session.setTransportParameters(TransportParametersCodec.encode(buildLocalTp(), role, 27))
    handshake.session.setQuicVersion(next.version)
    loss = LossDetection(rtt, config, role, ConnectionLossListener(this))
    path.cc = config.congestionController()
    path.pacer = Pacer()
    cryptoStreams =
        // the abandoned version's flight leaves the congestion state too
        CryptoStreams(config.limits.cryptoOutOfOrderPerLevel, config.limits.cryptoPostHandshake)
    for (i in 0 until 3) spaceDiscarded[i] = false
    receiver.reset()
    installInitialKeys(next)
    tlsDirty = true
}

/** Client side: the server's Initial arrived in another configured version (RFC 9368 section 2.2). */
internal fun ConnectionCore.switchClientVersion(profile: VersionProfile): Boolean {
    if (readKeys[2] != null || profile !in config.versions) return false
    handshake.session.setQuicVersion(profile.version)
    version = profile
    installInitialKeys(profile)
    return true
}

internal class ConnectionHandshakeSink(
    private val core: ConnectionCore,
) : HandshakeSink {
    override fun onCryptoData(
        level: Int,
        data: ByteArray,
    ) {
        core.cryptoStreams.send[level].enqueue(data, 0, data.size, false)
    }

    override fun onKeys(
        level: Int,
        direction: Direction,
        protector: PacketProtector,
    ) {
        val space =
            if (level == 0) {
                0
            } else if (level == 2) {
                1
            } else {
                2
            }
        if (core.spaceDiscarded[space]) {
            protector.close()
            return
        }
        if (level == 1 && (core.state != ConnectionState.Handshaking || (direction == Direction.Write) != (core.role == TlsRole.Client))) {
            protector.close()
            return
        } // 0-RTT keys: written by a client, read by a server, only during the handshake
        if (direction ==
            Direction.Read
        ) {
            core.readKeys[level]?.close()
            core.readKeys[level] = protector
        } else {
            core.writeKeys[level]?.close()
            core.writeKeys[level] =
                protector
        }
        if (level == 3 && core.keyPhase == null && core.readKeys[3] != null &&
            core.writeKeys[3] != null
        ) {
            core.keyPhase =
                KeyPhase(core.readKeys[3]!!, core.writeKeys[3]!!) { r, w ->
                    core.readKeys[3] = r
                    core.writeKeys[3] = w
                }
        }
        if (level == 3 && direction == Direction.Write && core.writeKeys[1] != null) {
            core.writeKeys[1]?.close()
            core.writeKeys[1] = null
        } // RFC 9001 section 4.9.3: a client drops its 0-RTT key as soon as it has the 1-RTT one
        if (level == 1 && core.role == TlsRole.Server) core.events += ConnectionEvent.EarlyDataAccepted
        // 1-RTT packets that arrived before the keys (the server's 0.5-RTT flight with its NEW_CONNECTION_ID frames) are opened through
        // the key phase, which exists once both directions are installed: replay them then, whichever direction came last, or they sit
        // in the buffer until the peer's loss recovery resends their frames
        if (direction == Direction.Read && level != 3) core.receiver.replayBuffered(level)
        if (level == 3 && core.keyPhase != null) core.receiver.replayBuffered(3)
        if (level == 2) core.loss.handshakeKeysAvailable = true
    }

    override fun onSessionTicket(ticket: QuicSessionTicket) {
        val tp = core.peerTpEncoded
        if (tp == null || core.role != TlsRole.Client) {
            ticket.close()
            return
        }
        ticket.remembered = rememberedBlob(core.negotiatedAlpn, tp)
        core.events += ConnectionEvent.SessionTicket(ticket)
    }

    override fun onPeerTransportParameters(
        encoded: ByteArray,
        negotiatedVersion: Int,
    ) {
        val tp =
            try {
                TransportParametersCodec.decode(
                    encoded,
                    if (core.role ==
                        TlsRole.Client
                    ) {
                        TlsRole.Server
                    } else {
                        TlsRole.Client
                    },
                )
            } catch (e: QuicWireException) {
                throw e
            }
        // authentication of connection IDs (RFC 9000 section 7.3)
        if (tp.initialSourceConnectionId !=
            core.remoteCid
        ) {
            throw QuicWireException(
                TransportError.TRANSPORT_PARAMETER_ERROR,
                0,
                "initial_source_connection_id does not match the peer's Source Connection ID",
            )
        }
        if (core.role == TlsRole.Client) {
            if (tp.originalDestinationConnectionId !=
                core.odcid
            ) {
                throw QuicWireException(TransportError.TRANSPORT_PARAMETER_ERROR, 0, "original_destination_connection_id mismatch")
            }
            if (tp.retrySourceConnectionId !=
                core.retryScid
            ) {
                throw QuicWireException(
                    TransportError.TRANSPORT_PARAMETER_ERROR,
                    0,
                    if (core.retryScid ==
                        null
                    ) {
                        "retry_source_connection_id without a Retry"
                    } else {
                        "retry_source_connection_id does not match the Retry"
                    },
                )
            }
            VersionNegotiationValidator.clientCheck(
                core.originalVersion.version,
                core.version.version,
                tp,
                core.receivedVnVersions,
                core.config.versions,
            )
        } else {
            VersionNegotiationValidator.serverCheck(core.originalVersion.version, negotiatedVersion, tp)
            val chosen =
                VersionProfile.of(negotiatedVersion)
                    ?: throw QuicWireException(TransportError.VERSION_NEGOTIATION_ERROR, 0, "negotiated version unknown")
            if (chosen != core.version) core.switchServerVersion(chosen)
        }
        core.peerTp = tp
        core.peerTpEncoded = encoded
        tp.statelessResetToken?.let { core.cids.setPeerResetToken(0, it) }
        core.streams.applyPeerParameters(
            tp.initialMaxStreamDataBidiLocal,
            tp.initialMaxStreamDataBidiRemote,
            tp.initialMaxStreamDataUni,
            tp.initialMaxStreamsBidi,
            tp.initialMaxStreamsUni,
        )
        core.connSend.onMaxUpdate(tp.initialMaxData)
        core.loss.peerAckDelayExponent = tp.ackDelayExponent
        core.loss.peerMaxAckDelay = tp.maxAckDelayMs.milliseconds
        core.peerGreaseQuicBit = tp.greaseQuicBit
        core.peerIdleMs = tp.maxIdleTimeoutMs
        core.cids.setPeerLimit(tp.activeConnectionIdLimit)
        // RFC 9000 section 14.3: never probe above the peer's max_udp_payload_size
        for (i in 0 until core.paths.all.size) {
            core.paths.all[i]
                .pmtud
                ?.limitUpperBound(core.pmtudUpperBound())
        }
    }

    override fun onHandshakeDone() {
        if (core.state != ConnectionState.Handshaking) return
        if (core.role == TlsRole.Client) {
            core.settleZeroRtt()
            if (core.state != ConnectionState.Handshaking) return
            if (core.earlyAccepted == true) core.events += ConnectionEvent.EarlyDataAccepted
        } else {
            core.earlyAccepted = core.handshake.session.earlyDataAccepted
            if (core.readKeys[1] == null) core.receiver.dropBufferedLevel(1) // refused 0-RTT is never processed (RFC 9001 section 4.6.2)
        }
        core.state = ConnectionState.Established
        core.qlog?.connectionStateUpdated(core.state, core.now)
        core.events += ConnectionEvent.HandshakeCompleted
        if (core.role == TlsRole.Server) {
            core.sendHandshakeDone = true
            core.confirmHandshake()
        }
    }

    override fun onVerifyRequested(chain: List<Certificate>) {
        core.events += ConnectionEvent.VerifyRequested(chain, core.handshake.session)
    }

    override fun onTlsFailure(
        exception: TlsException,
        alert: Int?,
    ) {
        core.fail(
            TransportError.crypto(alert ?: 80),
            0,
            exception.message ?: "TLS failure",
            exception,
        )
    }
}
