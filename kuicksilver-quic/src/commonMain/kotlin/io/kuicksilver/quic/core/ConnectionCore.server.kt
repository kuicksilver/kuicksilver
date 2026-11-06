// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0

package io.kuicksilver.quic.core

import io.ktor.network.sockets.InetSocketAddress
import io.kuicksilver.native.PacketBuffer
import io.kuicksilver.quic.ConnectionCore
import io.kuicksilver.quic.QuicConfig
import io.kuicksilver.quic.TimeMark
import io.kuicksilver.quic.VersionProfile
import io.kuicksilver.quic.wire.ConnectionId
import io.kuicksilver.quic.wire.PacketHeaderCodec
import io.kuicksilver.quic.wire.PacketHeaderView
import io.kuicksilver.quic.wire.PacketType
import io.kuicksilver.tls.QuicCrypto
import io.kuicksilver.tls.ResetKey
import io.kuicksilver.tls.TlsConfig
import io.kuicksilver.tls.TlsRole
import kotlin.random.Random

// A server connection from a client's first Initial (RFC 9000 section 7.2, 17.2.2).

internal fun ConnectionCore.Companion.serverWithKeys(
    config: QuicConfig,
    tls: TlsConfig,
    crypto: QuicCrypto,
    remote: InetSocketAddress,
    random: Random,
    now: TimeMark,
    data: PacketBuffer,
    length: Int,
    localCidBytes: ByteArray?,
    resetKey: ResetKey?,
    originalDcid: ConnectionId? = null,
    retryScid: ConnectionId? = null,
    early: io.kuicksilver.quic.core.ServerEarlyData? = null,
    tokenValidated: Boolean = false,
): ConnectionCore? {
    require(tls.role == TlsRole.Server) { "a server connection needs a server TlsConfig" }
    val hv = PacketHeaderView()
    if (length < 1200 || !PacketHeaderCodec.parse(data, 0, length, config.connectionIdLength, hv) ||
        hv.type != PacketType.Initial
    ) {
        return null
    }
    val profile = VersionProfile.of(hv.version) ?: return null
    if (profile !in config.versions) return null
    val packetDcid = ConnectionId(ByteArray(hv.dcidLen).also { data.copyTo(it, hv.dcidOff, 0, hv.dcidLen) })
    // after a Retry the client's DCID is our Retry SCID; the original one comes from the token (RFC 9000 section 7.3)
    val odcid = originalDcid ?: packetDcid
    val remoteCid = ConnectionId(ByteArray(hv.scidLen).also { data.copyTo(it, hv.scidOff, 0, hv.scidLen) })
    val scid = localCidBytes?.let { ConnectionId(it) } ?: ConnectionId(ByteArray(config.connectionIdLength).also { random.nextBytes(it) })
    val core =
        ConnectionCore(
            TlsRole.Server,
            config,
            tls,
            crypto,
            remote,
            random,
            now,
            odcid,
            scid,
            remoteCid,
            profile,
            resetKey,
            earlyMode = io.kuicksilver.tls.EarlyDataState.Disabled,
            serverEarly = early,
        )
    if (tokenValidated) {
        // a NEW_TOKEN token validated the address (RFC 9000 section 8.1.3): no anti-amplification limit, no Retry state
        core.validatedByToken = true
        core.amplification.validated = true
        core.loss.peerAddressValidated = true
    }
    if (retryScid !=
        null
    ) {
        core.initialKeyCid = packetDcid
        core.retryScid = retryScid
        core.validatedByToken = true
        core.amplification.validated =
            true
        core.loss.peerAddressValidated = true
        core.refreshLocalTp()
    }
    core.installInitialKeys(profile)
    return core
}
