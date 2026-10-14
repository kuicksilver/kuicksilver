// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.wire

import io.kuicksilver.native.PacketBuffer
import io.kuicksilver.quic.TransportError
import io.kuicksilver.quic.VersionProfile
import io.kuicksilver.tls.TlsRole

private const val TRANSPORT_PARAMETER_ERROR = TransportError.TRANSPORT_PARAMETER_ERROR
private const val VERSION_NEGOTIATION_ERROR = TransportError.VERSION_NEGOTIATION_ERROR

/** Encodes and validates transport parameters (RFC 9000 section 18; RFC 9368 section 3). */
internal object TransportParametersCodec {
    private const val ORIGINAL_DCID = 0x00L
    private const val MAX_IDLE_TIMEOUT = 0x01L
    private const val STATELESS_RESET_TOKEN = 0x02L
    private const val MAX_UDP_PAYLOAD_SIZE = 0x03L
    private const val INITIAL_MAX_DATA = 0x04L
    private const val INITIAL_MAX_STREAM_DATA_BIDI_LOCAL = 0x05L
    private const val INITIAL_MAX_STREAM_DATA_BIDI_REMOTE = 0x06L
    private const val INITIAL_MAX_STREAM_DATA_UNI = 0x07L
    private const val INITIAL_MAX_STREAMS_BIDI = 0x08L
    private const val INITIAL_MAX_STREAMS_UNI = 0x09L
    private const val ACK_DELAY_EXPONENT = 0x0aL
    private const val MAX_ACK_DELAY = 0x0bL
    private const val DISABLE_ACTIVE_MIGRATION = 0x0cL
    private const val PREFERRED_ADDRESS = 0x0dL
    private const val ACTIVE_CONNECTION_ID_LIMIT = 0x0eL
    private const val INITIAL_SCID = 0x0fL
    private const val RETRY_SCID = 0x10L
    private const val VERSION_INFORMATION = 0x11L
    private const val MAX_DATAGRAM_FRAME_SIZE = 0x20L
    private const val GREASE_QUIC_BIT = 0x2ab2L

    private fun fail(msg: String): Nothing = throw QuicWireException(TRANSPORT_PARAMETER_ERROR, 0, msg)

    fun encode(
        tp: TransportParameters,
        sender: TlsRole,
        reservedId: Long,
    ): ByteArray {
        // fixed parameters take well under 1024 bytes; version_information grows with the versions listed (a decoded peer's
        // list is as long as the peer made it)
        val b = PacketBuffer.allocate(1024 + 4 * (tp.availableVersions?.size ?: 0))
        try {
            val w = WireWriter(b, 0, b.capacity)

            fun vi(
                id: Long,
                v: Long,
            ) {
                w.varint(id)
                w.varint(VarInt.size(v).toLong())
                w.varint(v)
            }

            fun bytes(
                id: Long,
                v: ByteArray,
            ) {
                w.varint(id)
                w.varint(v.size.toLong())
                w.bytes(v)
            }

            fun empty(id: Long) {
                w.varint(id)
                w.varint(0)
            }
            if (sender == TlsRole.Server) {
                tp.originalDestinationConnectionId?.let { bytes(ORIGINAL_DCID, it.toByteArray()) }
                tp.statelessResetToken?.let {
                    require(it.size == 16)
                    bytes(STATELESS_RESET_TOKEN, it)
                }
                tp.retrySourceConnectionId?.let { bytes(RETRY_SCID, it.toByteArray()) }
                if (tp.preferredAddressPresent) {
                    bytes(
                        PREFERRED_ADDRESS,
                        ByteArray(4 + 2 + 16 + 2 + 1 + 8 + 16).also {
                            it[24] = 8
                        },
                    ) // zero addresses, 8-byte CID, zero token (tests only: the server never advertises one)
                }
            }
            if (tp.maxIdleTimeoutMs != 0L) vi(MAX_IDLE_TIMEOUT, tp.maxIdleTimeoutMs)
            if (tp.maxUdpPayloadSize != 65527L) vi(MAX_UDP_PAYLOAD_SIZE, tp.maxUdpPayloadSize)
            vi(INITIAL_MAX_DATA, tp.initialMaxData)
            vi(INITIAL_MAX_STREAM_DATA_BIDI_LOCAL, tp.initialMaxStreamDataBidiLocal)
            vi(INITIAL_MAX_STREAM_DATA_BIDI_REMOTE, tp.initialMaxStreamDataBidiRemote)
            vi(INITIAL_MAX_STREAM_DATA_UNI, tp.initialMaxStreamDataUni)
            vi(INITIAL_MAX_STREAMS_BIDI, tp.initialMaxStreamsBidi)
            vi(INITIAL_MAX_STREAMS_UNI, tp.initialMaxStreamsUni)
            if (tp.ackDelayExponent != 3) vi(ACK_DELAY_EXPONENT, tp.ackDelayExponent.toLong())
            if (tp.maxAckDelayMs != 25L) vi(MAX_ACK_DELAY, tp.maxAckDelayMs)
            if (tp.disableActiveMigration) empty(DISABLE_ACTIVE_MIGRATION)
            vi(ACTIVE_CONNECTION_ID_LIMIT, tp.activeConnectionIdLimit)
            tp.initialSourceConnectionId?.let { bytes(INITIAL_SCID, it.toByteArray()) }
            if (tp.maxDatagramFrameSize != 0L) vi(MAX_DATAGRAM_FRAME_SIZE, tp.maxDatagramFrameSize)
            if (tp.greaseQuicBit) empty(GREASE_QUIC_BIT)
            tp.availableVersions?.let { av ->
                w.varint(VERSION_INFORMATION)
                w.varint((4 + 4 * av.size).toLong())
                w.u32(tp.chosenVersion.toLong() and 0xffffffffL)
                for (v in av) w.u32(v.toLong() and 0xffffffffL)
            }
            empty(reservedId)
            return ByteArray(w.pos).also { b.copyTo(it, 0, 0, w.pos) }
        } finally {
            b.close()
        }
    }

    fun decode(
        bytes: ByteArray,
        sender: TlsRole,
    ): TransportParameters {
        val tp = TransportParameters()
        val b = PacketBuffer.allocate(maxOf(bytes.size, 1))
        b.copyFrom(bytes, 0, 0, bytes.size)
        try {
            val r = WireReader(b, 0, bytes.size)
            val seen = HashSet<Long>()
            while (r.remaining > 0) {
                val id = r.varint()
                val len = r.length()
                val end = r.pos + len
                if (!seen.add(id)) fail("duplicate transport parameter 0x${id.toString(16)}")
                if (sender == TlsRole.Client &&
                    (id == ORIGINAL_DCID || id == STATELESS_RESET_TOKEN || id == PREFERRED_ADDRESS || id == RETRY_SCID)
                ) {
                    fail("server-only parameter 0x${id.toString(16)} from the client")
                }

                fun vi(): Long {
                    val v = r.varint()
                    if (r.pos != end) fail("bad value length for 0x${id.toString(16)}")
                    return v
                }

                fun cid(): ConnectionId {
                    if (len >
                        20
                    ) {
                        fail("connection id too long")
                    }
                    val a = ByteArray(len)
                    b.copyTo(a, r.pos, 0, len)
                    r.pos = end
                    return ConnectionId(a)
                }
                when (id) {
                    ORIGINAL_DCID -> {
                        tp.originalDestinationConnectionId = cid()
                    }

                    MAX_IDLE_TIMEOUT -> {
                        tp.maxIdleTimeoutMs = vi()
                    }

                    STATELESS_RESET_TOKEN -> {
                        if (len !=
                            16
                        ) {
                            fail("stateless reset token must be 16 bytes")
                        }
                        tp.statelessResetToken =
                            ByteArray(16).also { b.copyTo(it, r.pos, 0, 16) }
                        r.pos = end
                    }

                    MAX_UDP_PAYLOAD_SIZE -> {
                        tp.maxUdpPayloadSize = vi()
                        if (tp.maxUdpPayloadSize <
                            1200
                        ) {
                            fail("max_udp_payload_size below 1200")
                        }
                    }

                    INITIAL_MAX_DATA -> {
                        tp.initialMaxData = vi()
                    }

                    INITIAL_MAX_STREAM_DATA_BIDI_LOCAL -> {
                        tp.initialMaxStreamDataBidiLocal = vi()
                    }

                    INITIAL_MAX_STREAM_DATA_BIDI_REMOTE -> {
                        tp.initialMaxStreamDataBidiRemote = vi()
                    }

                    INITIAL_MAX_STREAM_DATA_UNI -> {
                        tp.initialMaxStreamDataUni = vi()
                    }

                    INITIAL_MAX_STREAMS_BIDI -> {
                        tp.initialMaxStreamsBidi = vi()
                        if (tp.initialMaxStreamsBidi >
                            (1L shl 60)
                        ) {
                            fail("initial_max_streams_bidi above 2^60")
                        }
                    }

                    INITIAL_MAX_STREAMS_UNI -> {
                        tp.initialMaxStreamsUni = vi()
                        if (tp.initialMaxStreamsUni >
                            (1L shl 60)
                        ) {
                            fail("initial_max_streams_uni above 2^60")
                        }
                    }

                    ACK_DELAY_EXPONENT -> {
                        val v = vi()
                        if (v > 20) fail("ack_delay_exponent above 20")
                        tp.ackDelayExponent = v.toInt()
                    }

                    MAX_ACK_DELAY -> {
                        tp.maxAckDelayMs = vi()
                        if (tp.maxAckDelayMs >= 16384) fail("max_ack_delay at least 2^14")
                    }

                    DISABLE_ACTIVE_MIGRATION -> {
                        if (len !=
                            0
                        ) {
                            fail("disable_active_migration carries a value")
                        }
                        tp.disableActiveMigration = true
                    }

                    PREFERRED_ADDRESS -> {
                        if (len <
                            41
                        ) {
                            fail("preferred_address too short")
                        }
                        tp.preferredAddressPresent = true
                        r.pos = end
                    }

                    ACTIVE_CONNECTION_ID_LIMIT -> {
                        tp.activeConnectionIdLimit = vi()
                        if (tp.activeConnectionIdLimit <
                            2
                        ) {
                            fail("active_connection_id_limit below 2")
                        }
                    }

                    INITIAL_SCID -> {
                        tp.initialSourceConnectionId = cid()
                    }

                    RETRY_SCID -> {
                        tp.retrySourceConnectionId = cid()
                    }

                    MAX_DATAGRAM_FRAME_SIZE -> {
                        tp.maxDatagramFrameSize = vi()
                    }

                    GREASE_QUIC_BIT -> {
                        if (len != 0) fail("grease_quic_bit carries a value")
                        tp.greaseQuicBit = true
                    }

                    VERSION_INFORMATION -> {
                        if (len < 4 || len % 4 != 0) fail("version_information length $len")
                        val chosen = r.u32().toInt()
                        if (chosen == 0) fail("version_information chosen version is zero")
                        val n = (len - 4) / 4
                        val av = IntArray(n) { r.u32().toInt() }
                        // RFC 9368 section 4: parsing failures; a server's own list may omit its Chosen Version or be empty (section 3)
                        if (av.contains(0)) fail("version_information available version is zero")
                        if (sender == TlsRole.Client &&
                            !av.contains(chosen)
                        ) {
                            fail("version_information chosen version not among the available ones")
                        }
                        tp.chosenVersion = chosen
                        tp.availableVersions = av
                    }

                    else -> {
                        r.pos = end
                    } // reserved (31 x N + 27) and unknown parameters are ignored (RFC 9000 section 18.1)
                }
            }
            return tp
        } catch (e: QuicWireException) {
            if (e.code == TRANSPORT_PARAMETER_ERROR) throw e
            throw QuicWireException(TRANSPORT_PARAMETER_ERROR, 0, "malformed transport parameters: ${e.message}")
        } finally {
            b.close()
        }
    }
}

/**
 * RFC 9368 section 2.3 as implemented in `ksl` for the server: the first of our Available Versions (our Chosen Version
 * heads the order) that the client lists, else the client's Original Version. The Kotlin copy serves `NullTlsSession`.
 */
internal fun chooseVersion(
    ourAvailable: IntArray,
    clientOriginal: Int,
    clientAvailable: IntArray?,
): Int {
    if (clientAvailable == null) return clientOriginal
    for (v in ourAvailable) if (clientAvailable.contains(v)) return v
    return clientOriginal
}

/** The downgrade checks of RFC 9368 section 4; a violation is VERSION_NEGOTIATION_ERROR (0x11). */
internal object VersionNegotiationValidator {
    private fun fail(msg: String): Nothing = throw QuicWireException(VERSION_NEGOTIATION_ERROR, 0, msg)

    /**
     * Client side, on the server's transport parameters: [sentInitialVersion] is the version of our very first Initial,
     * [currentVersion] the version of the server's packets, [receivedVnVersions] the list from a Version Negotiation
     * packet we acted on (null when none), [configured] our preference order.
     */
    fun clientCheck(
        sentInitialVersion: Int,
        currentVersion: Int,
        server: TransportParameters,
        receivedVnVersions: IntArray?,
        configured: List<VersionProfile>,
    ) {
        val av = server.availableVersions
        if (av == null) {
            if (receivedVnVersions != null) fail("server sent Version Negotiation but no version_information")
            return
        }
        if (server.chosenVersion !=
            currentVersion
        ) {
            fail(
                "server Chosen Version 0x${server.chosenVersion.toUInt().toString(
                    16,
                )} differs from its packet version 0x${currentVersion.toUInt().toString(16)}",
            )
        }
        if (receivedVnVersions != null) {
            // we restarted with currentVersion after a VN packet: the server must not support the version of our first Initial
            // nor any version we rank above the current one, and must list some (RFC 9368 section 4)
            if (av.isEmpty()) fail("server Available Versions empty after Version Negotiation")
            if (sentInitialVersion != currentVersion &&
                av.contains(sentInitialVersion)
            ) {
                fail("downgrade: server supports our original version 0x${sentInitialVersion.toUInt().toString(16)}")
            }
            for (p in configured) {
                if (p.version ==
                    currentVersion
                ) {
                    break
                }
                if (av.contains(p.version)) fail("downgrade: server supports preferred version 0x${p.version.toUInt().toString(16)}")
            }
        }
        if (sentInitialVersion != currentVersion && receivedVnVersions == null &&
            !configured.any { it.version == currentVersion }
        ) {
            fail("server chose a version we did not offer")
        }
    }

    /** Server side: the client's Chosen Version must be the version of its Initial packets. */
    fun serverCheck(
        initialVersion: Int,
        chosen: Int,
        client: TransportParameters,
    ) {
        if (client.availableVersions == null) return
        if (client.chosenVersion !=
            initialVersion
        ) {
            fail("client Chosen Version 0x${client.chosenVersion.toUInt().toString(16)} differs from its Initial version")
        }
        if (chosen != initialVersion && !client.availableVersions!!.contains(chosen)) fail("negotiated version not offered by the client")
    }
}
