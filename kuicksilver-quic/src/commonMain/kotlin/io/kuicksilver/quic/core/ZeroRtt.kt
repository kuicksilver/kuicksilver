// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(ExperimentalKuicksilverApi::class)

package io.kuicksilver.quic.core

import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.native.PacketBuffer
import io.kuicksilver.quic.ConnectionCore
import io.kuicksilver.quic.ConnectionEvent
import io.kuicksilver.quic.QuicConfig
import io.kuicksilver.quic.QuicException
import io.kuicksilver.quic.TransportError
import io.kuicksilver.quic.endpoint.SipHash
import io.kuicksilver.quic.endpoint.ZeroRttReplayRegister
import io.kuicksilver.quic.wire.QuicWireException
import io.kuicksilver.quic.wire.TransportParameters
import io.kuicksilver.quic.wire.TransportParametersCodec
import io.kuicksilver.quic.wire.WireWriter
import io.kuicksilver.tls.EarlyDataAdmission
import io.kuicksilver.tls.EarlyDataState
import io.kuicksilver.tls.QuicSessionTicket
import io.kuicksilver.tls.TlsRole

// 0-RTT in the core (RFC 9000 sections 4.6.1, 7.4.1; RFC 9001 sections 4.6, 4.9.3; ADR-0015): the client's remembered
// transport parameters, acceptance and rejection, and the server's early-data context and replay register.

/**
 * A server's 0-RTT setup: [context] binds tickets to this configuration (RFC 9001 section 4.6.3), [register] is the
 * replay register (RFC 8446 section 8.2; the process's one in production) and [clock] the time it is kept in (the
 * process's monotonic clock in production; null: the connection's clock, for tests in virtual time) and [wallClock] the
 * wall clock in milliseconds OpenSSL judges ticket ages by (null: [clock]'s, no steps).
 */
internal class ServerEarlyData(
    val context: ByteArray,
    val register: ZeroRttReplayRegister,
    val clock: (() -> io.kuicksilver.quic.TimeMark)? = null,
    val wallClock: (() -> Long)? = null,
) {
    companion object {
        /**
         * The context: the ALPN list, the transport parameters a client may rely on in 0-RTT (RFC 9000 section 7.4.1:
         * the limits, idle timeout, `max_udp_payload_size`, `disable_active_migration`, `max_datagram_frame_size`) and the
         * application's blob (HTTP/3 SETTINGS), as two SipHash-64 values. The ticket is encrypted and authenticated, so the
         * digest only has to tell configurations apart; any change refuses 0-RTT once.
         */
        fun of(
            quic: QuicConfig,
            alpn: List<String>,
            application: ByteArray?,
            register: ZeroRttReplayRegister,
            clock: (() -> io.kuicksilver.quic.TimeMark)? = null,
            wallClock: (() -> Long)? = null,
        ): ServerEarlyData {
            val b = PacketBuffer.allocate(512 + (application?.size ?: 0))
            try {
                val w = WireWriter(b, 0, b.capacity)
                for (a in alpn) {
                    val bytes = a.encodeToByteArray()
                    w.varint(bytes.size.toLong())
                    w.bytes(bytes, 0, bytes.size)
                }
                w.varint(quic.initialConnectionWindow)
                w.varint(quic.initialStreamWindow)
                w.varint(quic.maxBidiStreams)
                w.varint(quic.maxUniStreams)
                w.varint(quic.activeConnectionIdLimit.toLong())
                w.varint(quic.maxIdleTimeout.inWholeMilliseconds)
                w.varint(quic.maxUdpPayloadSize.toLong())
                w.varint(if (quic.allowMigration) 0 else 1)
                w.varint(quic.maxDatagramFrameSize)
                val app = application ?: ByteArray(0)
                w.varint(app.size.toLong())
                w.bytes(app, 0, app.size)
                val n = w.pos
                val ctx = ByteArray(16)
                val h0 = SipHash.hash24(0x6b75696b73696c76L, 0x30727474636f6e74L, b, 0, n)
                val h1 = SipHash.hash24(0x0123456789abcdefL, 0x7fedcba987654321L, b, 0, n)
                for (i in 0 until 8) {
                    ctx[i] = (h0 ushr (8 * i)).toByte()
                    ctx[8 + i] = (h1 ushr (8 * i)).toByte()
                }
                return ServerEarlyData(ctx, register, clock, wallClock)
            } finally {
                b.close()
            }
        }
    }
}

/** What a ticket remembers: the negotiated ALPN and the server's encoded transport parameters. */
internal fun rememberedBlob(
    alpn: String?,
    tp: ByteArray,
): ByteArray {
    val a = (alpn ?: "").encodeToByteArray()
    return byteArrayOf(a.size.toByte()) + a + tp
}

internal fun rememberedAlpn(blob: ByteArray): String = blob.decodeToString(1, 1 + (blob[0].toInt() and 0xff))

internal fun rememberedTp(blob: ByteArray): ByteArray = blob.copyOfRange(1 + (blob[0].toInt() and 0xff), blob.size)

/** The ALPN and the server's transport parameters a ticket remembers ([rememberedBlob]), or null when [blob] does not hold them. */
internal fun rememberedParameters(blob: ByteArray): Pair<String, TransportParameters>? {
    val tp =
        try {
            TransportParametersCodec.decode(rememberedTp(blob), TlsRole.Server)
        } catch (_: QuicWireException) {
            return null
        }
    return rememberedAlpn(blob) to tp
}

internal fun withTp(
    blob: ByteArray,
    tp: ByteArray,
): ByteArray = rememberedBlob(rememberedAlpn(blob), tp)

/** Server: hands the TLS session the context and an admission backed by the replay register at its clock. */
internal fun ConnectionCore.enableServerEarlyData(early: ServerEarlyData) {
    val core = this
    handshake.session.enableEarlyData(
        early.context,
        object : EarlyDataAdmission {
            override fun admit(ticketId: ByteArray): Boolean {
                val now = early.clock?.invoke() ?: core.now
                return early.register.admit(ticketId, now, early.wallClock?.invoke() ?: (now.nanos / 1_000_000))
            }

            override fun release(ticketId: ByteArray) = early.register.release(ticketId)
        },
    )
}

/**
 * Client, before the first [ConnectionCore.poll]: resumes [ticket] and, when it allows early data and remembers the
 * server's transport parameters, applies them as the limits of 0-RTT (RFC 9000 section 7.4.1). True when 0-RTT is on.
 */
internal fun ConnectionCore.useTicket(ticket: QuicSessionTicket): Boolean {
    check(role == TlsRole.Client && earlyMode != EarlyDataState.Disabled) { "0-RTT needs a client core with early data" }
    val blob = ticket.remembered
    if (!handshake.session.resume(ticket) || blob == null) return false
    val (alpn, tp) = rememberedParameters(blob) ?: return false
    if (!handshake.session.enableEarlyData(null, null)) return false
    remembered = tp
    rememberedAlpn = alpn
    // section 7.4.1: never the remembered ack_delay_exponent, max_ack_delay, connection IDs, preferred_address or reset token
    streams.applyPeerParameters(
        tp.initialMaxStreamDataBidiLocal,
        tp.initialMaxStreamDataBidiRemote,
        tp.initialMaxStreamDataUni,
        tp.initialMaxStreamsBidi,
        tp.initialMaxStreamsUni,
    )
    connSend.onMaxUpdate(tp.initialMaxData)
    return true
}

/** The connection may still send 0-RTT packets: a 0-RTT write key and no 1-RTT one yet. */
internal val ConnectionCore.zeroRttWritable: Boolean get() = writeKeys[1] != null && writeKeys[3] == null

/**
 * Client, at handshake completion: the server's answer to our 0-RTT (RFC 9001 section 4.6.2). Accepted: the new limits
 * must not be lower than the remembered ones (RFC 9000 section 7.4.1; PROTOCOL_VIOLATION, as quic-go). Rejected: the
 * 0-RTT packets leave flight without a congestion signal and their frames are queued again for 1-RTT, provided the ALPN
 * is the same and the new limits cover what was already sent; otherwise (and always under [EarlyDataState.Required]) the
 * connection closes with [QuicException.ConnectionLost.ZeroRttRejected].
 */
internal fun ConnectionCore.settleZeroRtt() {
    val old = remembered ?: return
    remembered = null
    val tp = peerTp ?: return
    val accepted = handshake.session.earlyDataAccepted == true
    earlyAccepted = accepted
    if (accepted) {
        val lower =
            tp.activeConnectionIdLimit < old.activeConnectionIdLimit ||
                tp.initialMaxData < old.initialMaxData ||
                tp.initialMaxStreamDataBidiLocal < old.initialMaxStreamDataBidiLocal ||
                tp.initialMaxStreamDataBidiRemote < old.initialMaxStreamDataBidiRemote ||
                tp.initialMaxStreamDataUni < old.initialMaxStreamDataUni ||
                tp.initialMaxStreamsBidi < old.initialMaxStreamsBidi ||
                tp.initialMaxStreamsUni < old.initialMaxStreamsUni
        if (lower) {
            fail(TransportError.PROTOCOL_VIOLATION, 0, "server accepted 0-RTT with transport parameters below the remembered ones", null)
            return
        }
        // section 7.4.1: streams opened in 0-RTT get the new initial limits
        streams.raiseLocalSendLimits(tp.initialMaxStreamDataBidiRemote, tp.initialMaxStreamDataUni)
        return
    }
    val fits =
        earlyMode != EarlyDataState.Required &&
            (rememberedAlpn ?: "") == (negotiatedAlpn ?: "") &&
            connSend.used <= tp.initialMaxData &&
            streams.localSendFits(
                tp.initialMaxStreamDataBidiRemote,
                tp.initialMaxStreamDataUni,
                tp.initialMaxStreamsBidi,
                tp.initialMaxStreamsUni,
            )
    loss.discardZeroRtt { p -> if (fits) streams.onFramesLost(p.frames) }
    if (!fits) {
        closeZeroRttRejected()
        return
    }
    // the remembered limits no longer hold: the server's new ones replace them, also where lower (RFC 9000 section 7.4.1)
    connSend.resetLimit(tp.initialMaxData)
    streams.adoptLocalSendLimits(
        tp.initialMaxStreamDataBidiRemote,
        tp.initialMaxStreamDataUni,
        tp.initialMaxStreamsBidi,
        tp.initialMaxStreamsUni,
    )
    events += ConnectionEvent.EarlyDataRejected
}

/** Closes with NO_ERROR locally reported as [QuicException.ConnectionLost.ZeroRttRejected]. */
internal fun ConnectionCore.closeZeroRttRejected() {
    val reason = "0-RTT rejected".encodeToByteArray()
    closeFrame = ConnectionCore.CloseFrame(false, TransportError.NO_ERROR, 0, reason)
    enterClosing(QuicException.ConnectionLost.ZeroRttRejected())
}

/** Server: the first 1-RTT packet arrived; the 0-RTT read key goes within 3 PTO (RFC 9001 section 4.9.3). */
internal fun ConnectionCore.onFirstOneRttFromClient() {
    if (role != TlsRole.Server || readKeys[1] == null || zeroRttReadDiscardAt != io.kuicksilver.quic.TimeMark.NEVER) return
    zeroRttReadDiscardAt = now + pto() * 3
}

internal fun ConnectionCore.discardZeroRttKeys() {
    readKeys[1]?.close()
    readKeys[1] = null
    writeKeys[1]?.close()
    writeKeys[1] = null
    zeroRttReadDiscardAt = io.kuicksilver.quic.TimeMark.NEVER
    receiver.dropBufferedLevel(1)
}
