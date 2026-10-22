// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.wire

import io.kuicksilver.quic.QuicConfig
import io.kuicksilver.tls.TlsRole

/** Decoded transport parameters (RFC 9000 section 18.2, RFC 9221, RFC 9287, RFC 9368); absent ones hold the RFC defaults. */
internal class TransportParameters {
    var originalDestinationConnectionId: ConnectionId? = null
    var maxIdleTimeoutMs: Long = 0
    var statelessResetToken: ByteArray? = null
    var maxUdpPayloadSize: Long = 65527
    var initialMaxData: Long = 0
    var initialMaxStreamDataBidiLocal: Long = 0
    var initialMaxStreamDataBidiRemote: Long = 0
    var initialMaxStreamDataUni: Long = 0
    var initialMaxStreamsBidi: Long = 0
    var initialMaxStreamsUni: Long = 0
    var ackDelayExponent: Int = 3
    var maxAckDelayMs: Long = 25
    var disableActiveMigration: Boolean = false

    /** The peer sent `preferred_address`; the addresses are not kept (the server never sends it; the client does not move to it). */
    var preferredAddressPresent: Boolean = false

    /** The connection ID of `preferred_address`, the server's sequence 1 (RFC 9000 section 5.1.1), and its reset token. */
    var preferredAddressCid: ConnectionId? = null
    var preferredAddressToken: ByteArray? = null
    var activeConnectionIdLimit: Long = 2
    var initialSourceConnectionId: ConnectionId? = null
    var retrySourceConnectionId: ConnectionId? = null
    var maxDatagramFrameSize: Long = 0
    var greaseQuicBit: Boolean = false

    /** `reset_stream_at` (draft-ietf-quic-reliable-stream-reset section 3): the sender takes RESET_STREAM_AT frames. */
    var resetStreamAt: Boolean = false

    /** `version_information` (0x11): Chosen Version, or 0 when the parameter is absent. */
    var chosenVersion: Int = 0

    /** Available Versions in the sender's preference order; null when the parameter is absent. */
    var availableVersions: IntArray? = null
}

/**
 * Our transport parameters for a connection (RFC 9000 section 18.2). Choices: `max_udp_payload_size` 1452 advertised;
 * the server disables active migration and sends no stateless reset token; `version_information` is always
 * sent (RFC 9368 section 3 recommends it so downgrade prevention works after a Version Negotiation packet).
 */
internal fun QuicConfig.localTransportParameters(
    role: TlsRole,
    scid: ConnectionId,
    odcid: ConnectionId?,
): TransportParameters =
    TransportParameters().also { tp ->
        tp.maxIdleTimeoutMs = maxIdleTimeout.inWholeMilliseconds
        tp.maxUdpPayloadSize = maxUdpPayloadSize.toLong()
        tp.initialMaxData = initialConnectionWindow
        tp.initialMaxStreamDataBidiLocal = initialStreamWindow
        tp.initialMaxStreamDataBidiRemote = initialStreamWindow
        tp.initialMaxStreamDataUni =
            initialStreamWindow
        tp.initialMaxStreamsBidi = maxBidiStreams
        tp.initialMaxStreamsUni = maxUniStreams
        tp.ackDelayExponent = ackDelayExponent
        tp.maxAckDelayMs = maxAckDelay.inWholeMilliseconds
        tp.activeConnectionIdLimit = activeConnectionIdLimit.toLong()
        tp.initialSourceConnectionId = scid
        tp.greaseQuicBit = greaseQuicBit
        tp.resetStreamAt = resetStreamAt
        tp.maxDatagramFrameSize = maxDatagramFrameSize // RFC 9221 section 3; 0 = absent
        if (role == TlsRole.Server) {
            tp.originalDestinationConnectionId = odcid
            tp.disableActiveMigration = !allowMigration
        } // migration is supported unless the application turns it off
        tp.chosenVersion = firstVersion.version
        tp.availableVersions = IntArray(versions.size) { versions[it].version }
    }
