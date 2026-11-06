// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic

import io.ktor.network.sockets.InetSocketAddress
import io.kuicksilver.native.PacketBuffer
import io.kuicksilver.quic.EndpointCore.Stateless
import io.kuicksilver.quic.core.AddressClass
import io.kuicksilver.quic.core.refreshLocalTp
import io.kuicksilver.quic.core.release
import io.kuicksilver.quic.core.serverWithKeys
import io.kuicksilver.quic.endpoint.AdmissionQueue
import io.kuicksilver.quic.endpoint.CidIssuance
import io.kuicksilver.quic.endpoint.IssuedCid
import io.kuicksilver.quic.endpoint.QuicLbRoute
import io.kuicksilver.quic.endpoint.StatelessClose
import io.kuicksilver.quic.endpoint.TokenCheck
import io.kuicksilver.quic.wire.ConnectionId
import io.kuicksilver.quic.wire.PacketHeaderCodec
import io.kuicksilver.quic.wire.PacketType
import io.kuicksilver.quic.wire.RetryPacket
import io.kuicksilver.quic.wire.VersionNegotiationPacket

// Admission of a queued client Initial by an [EndpointCore] (threat-model 3.1 and 3.2): Retry token check, hard limits, the
// admission policy, and the stateless answers it may produce instead of a connection (Retry, Initial CONNECTION_CLOSE, Version
// Negotiation; RFC 9000 sections 6, 8.1 and 10.2.3).

/** One queued Initial; true when a connection was created from it. */
internal fun EndpointCore.admitOne(
    e: AdmissionQueue.Entry,
    now: TimeMark,
    inflight: Int,
    handshakeBuffer: Long,
): Boolean {
    val data = e.buffer
    val length = e.length
    val from = e.from
    if (!PacketHeaderCodec.parse(data, 0, length, cidLength, hv) || hv.type != PacketType.Initial) return false
    registry.lookup(data, hv.dcidOff, hv.dcidLen)?.let {
        deliver(it, data, length, from, e.ecn, now)
        return false
    } // the second datagram of a flight whose first one just became a connection
    val profile = VersionProfile.of(hv.version) ?: return false
    val tokens = addressTokens!!
    var check = if (hv.tokenLen == 0) TokenCheck.Absent else tokens.check(data, hv.tokenOff, hv.tokenLen, from, hv.version, now)
    if (check == TokenCheck.NewTokenRejected) {
        // RFC 9000 section 8.1.3: a NEW_TOKEN token that does not validate is treated as no token, never refused (the client may
        // hold a stale one, or one for another server behind the same name)
        newTokensRejected++
        check = TokenCheck.Absent
    }
    if (check == TokenCheck.Invalid || check == TokenCheck.Expired) { // RFC 9000 section 8.1.3: refuse with INVALID_TOKEN, statelessly
        invalidTokens++
        statelessInitialClose(data, profile, from, TransportError.INVALID_TOKEN, now)
        return false
    }
    if (check is TokenCheck.Valid && !check.retryScid.contentEquals(data, hv.dcidOff, hv.dcidLen)) {
        // RFC 9000 sections 8.1.2-8.1.4 and 17.2.5.3: the token belongs to the Initial whose DCID is the Retry SCID; under another
        // DCID it is a replay (or a copy), refused the same way
        invalidTokens++
        statelessInitialClose(data, profile, from, TransportError.INVALID_TOKEN, now)
        return false
    }
    if (shuttingDown) {
        // QuicEndpoint.shutdown: the refusal of a full accept queue (RFC 9000 section 5.2.2), for every new client
        refusedShutdown++
        statelessInitialClose(data, profile, from, TransportError.CONNECTION_REFUSED, now)
        return false
    }
    // ---- hard limits: no policy may lift them ----
    if (connections.size >= config.maxConnections) {
        initialsDropped++
        refusedLimits++
        return false
    }
    if (acceptBacklog() >= config.acceptQueue) {
        // RFC 9000 section 5.2.2: refuse before any handshake state, statelessly and under the rate limit (quic-go
        // sendConnectionRefused); only connections waiting for accept() count, never handshakes in flight (threat-model 3.2)
        acceptQueueRefusals++
        statelessInitialClose(data, profile, from, TransportError.CONNECTION_REFUSED, now)
        return false
    }
    val ipKey = AddressClass.ipKey(from)
    val fromIp = perIp[ipKey] ?: 0
    config.maxConnectionsPerIp?.let {
        if (fromIp >= it) {
            initialsDropped++
            refusedLimits++
            return false
        }
    }
    // the replay register last, after the hard limits: a token is spent only by an attempt the policy gets to see (RFC 9000 section 8.1.4)
    val newTokenNonce = (check as? TokenCheck.NewTokenValid)?.nonce
    if (newTokenNonce != null) {
        if (tokens.admitNewToken(newTokenNonce, now)) {
            newTokensAccepted++
        } else {
            newTokensRejected++ // a replay, or the register is full: fail closed, as a client without a token
            check = TokenCheck.Absent
        }
    }
    val created = admitValidated(e, data, length, from, now, inflight, handshakeBuffer, profile, check, fromIp, ipKey)
    if (!created && check is TokenCheck.NewTokenValid) tokens.releaseNewToken(check.nonce) // the client may show it again
    return created
}

/** The policy's decision and the connection for an attempt past the token check and the hard limits; true when a connection was created. */
private fun EndpointCore.admitValidated(
    e: AdmissionQueue.Entry,
    data: io.kuicksilver.native.PacketBuffer,
    length: Int,
    from: InetSocketAddress,
    now: TimeMark,
    inflight: Int,
    handshakeBuffer: Long,
    profile: VersionProfile,
    check: TokenCheck,
    fromIp: Int,
    ipKey: Any,
): Boolean {
    val server = config.server!!
    val tokens = addressTokens!!
    val validated = check is TokenCheck.Valid || check is TokenCheck.NewTokenValid
    val decision =
        try {
            config.admission.admit(ConnectionAttempt(from, inflight, connections.size, fromIp, handshakeBuffer, validated))
        } catch (
            t: Throwable,
        ) {
            // a CancellationException too: admit() is not suspending, so it is the policy's failure, never the loop's cancellation
            admissionContractViolations++
            AdmissionDecision.Drop
        } // fail closed
    when (decision) {
        AdmissionDecision.Allow -> {}

        AdmissionDecision.Drop -> {
            initialsDropped++
            refusedAdmission++
            return false
        }

        is AdmissionDecision.Close -> {
            refusedAdmission++
            statelessInitialClose(data, profile, from, decision.code, now)
            return false
        }

        AdmissionDecision.Retry -> {
            // RFC 9000 section 8.1.2: never a second Retry for a client that answered one (quinn CVE-2024-45311); a NEW_TOKEN
            // holder may get one
            if (check is TokenCheck.Valid) {
                admissionContractViolations++
                initialsDropped++
                return false
            }
            if (!limiter.allow(from, now)) {
                statelessRateLimited++
                droppedStateless++
                return false
            }
            val clientDcid = ConnectionId(ByteArray(hv.dcidLen).also { data.copyTo(it, hv.dcidOff, 0, hv.dcidLen) })
            val clientScid = ConnectionId(ByteArray(hv.scidLen).also { data.copyTo(it, hv.scidOff, 0, hv.scidLen) })
            // the ID this connection will use if the client comes back: a stateless one, which takes no owner exception (nothing
            // would release it if the client never returns)
            val ourScid = route.issueStateless(random)
            val token =
                tokens.mint(clientDcid, ourScid, from, hv.version, now) ?: run {
                    initialsDropped++ // this key's nonces are spent (2^55 tokens or more): no Retry rather than a repeated nonce
                    return false
                }
            val n = RetryPacket.write(vnBuffer, profile, clientScid, ourScid, token, clientDcid, config.crypto, random.nextInt(16))
            stateless +=
                Stateless(ByteArray(n).also { vnBuffer.copyTo(it, 0, 0, n) }, from, rxLocal)
            retriesSent++
            return false
        }
    }
    var originalDcid: ConnectionId? = null
    var retryScid: ConnectionId? = null
    val issued: IssuedCid =
        if (check is TokenCheck.Valid) {
            originalDcid = check.odcid
            val rs = ConnectionId(ByteArray(hv.dcidLen).also { data.copyTo(it, hv.dcidOff, 0, hv.dcidLen) })
            retryScid = rs
            // the Retry SCID is the connection's ID (one server ID for the client: draft-ietf-quic-load-balancers-21 sections
            // 3.2 and 9) when its first octet still tells what it allows: 0b111, or the current or previous codepoint. A
            // codepoint that went away since the Retry gets a fresh ID, the Retry SCID staying an alias for the client's Initials
            // an unroutable Retry SCID made while no nonce was reserved gets a routable one now if it can (a temporary state
            // must not become the connection's for good)
            val known = if (testFreshCidAfterRetry) null else route.knownIssuance(rs)
            if (known != null && !(known == CidIssuance.SingleNoMigration && route.canIssueRoutable())) {
                IssuedCid(rs, known)
            } else {
                testBetweenRetryChecks?.invoke()
                val fresh = route.issue(random, client = false)
                // the nonces ran out again in between: a second unroutable ID would be a second server ID for the client
                // (section 3.2: exactly one); keep the Retry SCID, which the change below moves to a routable one later
                if (known == CidIssuance.SingleNoMigration && fresh.issuance == CidIssuance.SingleNoMigration) {
                    IssuedCid(rs, CidIssuance.SingleNoMigration)
                } else {
                    fresh
                }
            }
        } // our Retry SCID is this connection's ID
        else {
            route.issue(random, client = false)
        }
    val cid = issued.cid
    val core =
        try {
            ConnectionCore.serverWithKeys(
                server.quic,
                server.tls,
                config.crypto,
                from,
                random,
                now,
                data,
                length,
                cid.toByteArray(),
                resetKey,
                originalDcid,
                retryScid,
                serverEarly,
                tokenValidated = check is TokenCheck.NewTokenValid,
            )
        } catch (e: Throwable) {
            route.release(cid) // an owner exception taken for it goes with it
            throw e
        } ?: run {
            route.release(cid)
            return false
        }
    // the address the client's Initial reached: every reply leaves from it. Unknown (a socket that does not report destinations, or one
    // that is no address to answer from, such as a broadcast) leaves the connection on the route's choice of source, as before 0.3.0
    core.paths.active.local = core.serverLocal(rxLocal)
    if (tokens.newTokenLifetime != null) {
        core.newTokenMinter = { client ->
            newTokensIssued++
            tokens.mintNewToken(client, core.now)
        }
    }
    config.maxConnectionLifetime?.let { core.lifetimeDeadline = now + it }
    attach(core, issued.issuance)
    // after attach: the sequence-1 ID a preferred address issues must route here (the registrar is set) before the first packet;
    // one re-encoding of the transport parameters for both changes. A preferred socket that failed is no longer offered
    // ... nor to a connection whose QUIC-LB ID is plaintext or unroutable: it hands out no second ID (draft-ietf-quic-load-balancers-21
    // sections 3.2 and 9), and an unroutable one asks the client not to migrate
    val preferred = server.preferredAddress?.takeIf { !preferredDown && !core.cids.singleCid }
    if (preferred != null) core.preferredAddress = preferred
    if (testForgeRetryScidInTp && retryScid != null) core.testForgeRetryScid = true
    if (preferred != null || core.testForgeRetryScid || core.unroutableCid) core.refreshLocalTp()
    // a Retry SCID of the previous configuration (or an unroutable one) adopted after the last change moved the connections:
    // this one moves too (draft-ietf-quic-load-balancers-21 section 3.1: update the client with IDs of the new configuration
    // and retire the old ones)
    if (!route.isCurrent(cid)) core.cids.requestReissue()
    if (retryScid == null) {
        registry.add(core.odcid, core)
    } else if (retryScid != cid) {
        // the client keeps using the original DCID (or the Retry SCID) until it learns ours (RFC 9000 section 7.2)
        registry.add(retryScid, core)
    }
    deliver(core, data, length, from, e.ecn, now)
    if (!core.anyPeerPacket) {
        remove(core)
        core.release()
        droppedUndecryptable++
        return false
    } // the Initial did not decrypt: no state for a datagram anyone can forge (threat-model 3.2)
    connectionsCreated++ // only now: a forged Initial creates nothing
    core.admissionIpKey = ipKey
    perIp[ipKey] = fromIp + 1
    accepted += core
    if (serverEarly != null) replayEarly(core, core.initialKeyCid, now)
    return true
}

/**
 * A stateless Initial CONNECTION_CLOSE to the client of the Initial in [data] (RFC 9000 section 10.2.3), under the rate limit:
 * well under a third of the at least 1200-byte Initial it answers (section 8.1).
 */
internal fun EndpointCore.statelessInitialClose(
    data: PacketBuffer,
    profile: VersionProfile,
    from: InetSocketAddress,
    code: Long,
    now: TimeMark,
) {
    if (!limiter.allow(from, now)) {
        statelessRateLimited++
        droppedStateless++
        return
    }
    val clientDcid = ConnectionId(ByteArray(hv.dcidLen).also { data.copyTo(it, hv.dcidOff, 0, hv.dcidLen) })
    val clientScid = ConnectionId(ByteArray(hv.scidLen).also { data.copyTo(it, hv.scidOff, 0, hv.scidLen) })
    val n = StatelessClose.writeInitialClose(vnBuffer, profile, clientDcid, clientScid, code, config.crypto)
    stateless +=
        Stateless(ByteArray(n).also { vnBuffer.copyTo(it, 0, 0, n) }, from, rxLocal)
}

internal fun EndpointCore.queueVersionNegotiation(
    data: PacketBuffer,
    length: Int,
    from: InetSocketAddress,
    quic: QuicConfig,
    now: TimeMark,
) {
    if (!limiter.allow(from, now)) {
        statelessRateLimited++
        droppedStateless++
        return
    }
    val versions = IntArray(quic.versions.size) { quic.versions[it].version }
    val n =
        VersionNegotiationPacket.write(
            vnBuffer,
            data,
            hv.scidOff,
            hv.scidLen,
            data,
            hv.dcidOff,
            hv.dcidLen,
            versions,
            random.nextInt(256),
            length,
        )
    val bytes = ByteArray(n)
    vnBuffer.copyTo(bytes, 0, 0, n)
    stateless += Stateless(bytes, from, rxLocal)
    versionNegotiations++
}
