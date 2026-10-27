// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.core

import io.kuicksilver.annotations.DelicateKuicksilverApi
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.native.KslLoader
import io.kuicksilver.quic.ConnectionEvent
import io.kuicksilver.quic.CorePair
import io.kuicksilver.quic.QuicException
import io.kuicksilver.quic.StreamPriority
import io.kuicksilver.quic.TransportError
import io.kuicksilver.quic.quicConfig
import kotlinx.io.readByteArray
import kotlin.random.Random
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.seconds

/** RESET_STREAM_AT (draft-ietf-quic-reliable-stream-reset): a reset that still delivers a prefix of the stream. */
@OptIn(ExperimentalKuicksilverApi::class, DelicateKuicksilverApi::class)
class ResetStreamAtTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    private val on = quicConfig { resetStreamAt = true }

    private class Received(
        val bytes: ByteArray,
        val resetCode: Long?,
    )

    /** Reads stream [id] on the server until it ends; the reset's code when it ended with one. */
    private fun CorePair.readAll(
        id: Long,
        until: () -> Boolean = { false },
    ): Received {
        val out = kotlinx.io.Buffer()
        val buf = ByteArray(16384)
        var ended = false
        runUntil(limit = 60.seconds) {
            while (!ended) {
                val n = server!!.readStream(id, buf, 0, buf.size)
                if (n > 0) {
                    out.write(buf, 0, n)
                } else if (n < 0) {
                    ended = true
                } else {
                    break
                }
            }
            ended || until()
        }
        drainEvents(server!!, serverEvents) // what the last read raised
        val reset = serverEvents.filterIsInstance<ConnectionEvent.StreamReset>().firstOrNull { it.id == id }
        return Received(out.readByteArray(), reset?.code)
    }

    private fun CorePair.established() {
        assertTrue(handshake())
    }

    /** Section 3: the bytes below the Reliable Size arrive whatever is lost; then the reset, with its code. */
    @Test fun resetAtDeliversReliablePrefix() {
        val p = CorePair(clientQuic = on, serverQuic = on)
        try {
            p.established()
            val loss = Random(7)
            p.filterToServer = { _, _ -> loss.nextInt(10) != 0 } // 10% loss both ways
            p.filterToClient = { _, _ -> loss.nextInt(10) != 0 }
            val id = p.client.openStream(bidi = false, StreamPriority.Default)
            val data = ByteArray(100_000) { (it * 7).toByte() }
            assertEquals(data.size, p.client.writeStream(id, data, 0, data.size, fin = false))
            p.step() // part of it goes out
            p.client.resetStreamAt(id, 7, 60_000)
            val got = p.readAll(id)
            // bytes read before the reset arrived may go past the reliable size; the reliable ones always arrive
            assertTrue(got.bytes.size >= 60_000, "${got.bytes.size} bytes")
            assertContentEquals(data.copyOf(got.bytes.size), got.bytes)
            assertEquals(7L, got.resetCode)
            // the sending half retires once the reliable bytes are acknowledged
            assertTrue(p.runUntil(limit = 30.seconds) { p.clientEvents.any { it is ConnectionEvent.StreamFinished && it.id == id } })
        } finally {
            p.close()
        }
    }

    /** A Reliable Size above what was written keeps every written byte. */
    @Test fun reliableSizeIsCutToWhatWasWritten() {
        val p = CorePair(clientQuic = on, serverQuic = on)
        try {
            p.established()
            val id = p.client.openStream(bidi = false, StreamPriority.Default)
            p.client.writeStream(id, ByteArray(10) { it.toByte() }, 0, 10, fin = false)
            p.client.resetStreamAt(id, 3, 1_000)
            val got = p.readAll(id)
            assertContentEquals(ByteArray(10) { it.toByte() }, got.bytes)
            assertEquals(3L, got.resetCode)
        } finally {
            p.close()
        }
    }

    /** Without the peer's transport parameter it is a plain RESET_STREAM (the peer would not know the frame). */
    @Test fun fallsBackToResetStreamWithoutPeerSupport() {
        val p = CorePair(clientQuic = on)
        try {
            p.established()
            val id = p.client.openStream(bidi = false, StreamPriority.Default)
            p.client.writeStream(id, ByteArray(100) { 1 }, 0, 100, fin = false)
            p.client.resetStreamAt(id, 9, 50)
            val got = p.readAll(id)
            assertEquals(9L, got.resetCode)
            assertNull(p.closedReason(p.serverEvents))
            assertNull(p.closedReason(p.clientEvents))
        } finally {
            p.close()
        }
    }

    /** The frame from a peer we did not offer the extension to is an unknown frame: FRAME_ENCODING_ERROR. */
    @Test fun negative_resetStreamAtWithoutNegotiationIsFrameEncodingError() {
        val p = CorePair(clientQuic = on)
        try {
            p.established()
            p.client.streams.forceResetStreamAtForTest = true
            val id = p.client.openStream(bidi = false, StreamPriority.Default)
            p.client.writeStream(id, ByteArray(10), 0, 10, fin = false)
            p.client.resetStreamAt(id, 1, 5)
            assertTrue(p.runUntil { p.closedReason(p.clientEvents) != null })
            val reason = assertIs<QuicException.ConnectionLost.TransportClosed>(p.closedReason(p.clientEvents))
            assertEquals(TransportError.FRAME_ENCODING_ERROR, reason.code)
        } finally {
            p.close()
        }
    }

    /** Section 4: a Reliable Size above the Final Size closes the connection with FRAME_ENCODING_ERROR. */
    @Test fun negative_resetStreamAtReliableSizeAboveFinalIsError() {
        val p = CorePair(clientQuic = on, serverQuic = on)
        try {
            p.established()
            p.client.streams.tamperResetStreamAtForTest = { it.c = it.b + 1 } // reliable = final + 1
            val id = p.client.openStream(bidi = false, StreamPriority.Default)
            p.client.writeStream(id, ByteArray(10), 0, 10, fin = false)
            p.client.resetStreamAt(id, 1, 5)
            assertTrue(p.runUntil { p.closedReason(p.clientEvents) != null })
            val reason = assertIs<QuicException.ConnectionLost.TransportClosed>(p.closedReason(p.clientEvents))
            assertEquals(TransportError.FRAME_ENCODING_ERROR, reason.code)
        } finally {
            p.close()
        }
    }

    /** A later RESET_STREAM (here from the peer's STOP_SENDING) ends the reliable delivery: the stream is reset outright. */
    @Test fun stopSendingAfterResetAtEndsTheStream() {
        val p = CorePair(clientQuic = on, serverQuic = on)
        try {
            p.established()
            val id = p.client.openStream(bidi = false, StreamPriority.Default)
            p.client.writeStream(id, ByteArray(200_000), 0, 200_000, fin = false)
            p.client.resetStreamAt(id, 4, 150_000)
            p.step()
            p.server!!.stopSending(id, 6)
            assertTrue(p.runUntil(limit = 30.seconds) { p.clientEvents.any { it is ConnectionEvent.StreamFinished && it.id == id } })
            assertNull(p.closedReason(p.serverEvents))
        } finally {
            p.close()
        }
    }

    /**
     * Section 5.2: "the initiator MUST NOT change the Application Error Code in subsequent RESET_STREAM_AT or RESET_STREAM
     * frames". Our RESET_STREAM_AT with code 4 went out and is not acknowledged yet (the peer's ACKs are held back); a later
     * STOP_SENDING (code 6) or our own reset (code 9) is answered with RESET_STREAM carrying code 4, so the peer sees no
     * STREAM_STATE_ERROR.
     */
    @Test fun laterResetKeepsTheResetStreamAtCode() {
        for (viaStopSending in listOf(true, false)) {
            val p = CorePair(clientQuic = on, serverQuic = on)
            try {
                p.established()
                val id = p.client.openStream(bidi = false, StreamPriority.Default)
                p.filterToClient = { _, _ -> false }
                p.client.writeStream(id, ByteArray(200_000), 0, 200_000, fin = false)
                assertTrue(p.runUntil { p.client.streams.sentEndForTest(id) >= 5_000 })
                p.client.resetStreamAt(id, 4, 3_000)
                p.step() // the RESET_STREAM_AT leaves; nothing of it is acknowledged
                if (viaStopSending) p.client.streams.onStopSending(id, 6) else p.client.resetStream(id, 9)
                val codes = mutableListOf<Long>()
                while (true) {
                    val c = p.client.streams.takeControlFrame() ?: break
                    if (c.id == id && c.kind == io.kuicksilver.quic.stream.ControlKind.ResetStream) codes += c.a
                    p.client.streams.releaseControlFrame(c)
                }
                assertEquals(listOf(4L), codes, "via STOP_SENDING: $viaStopSending")
            } finally {
                p.close()
            }
        }
    }

    /**
     * Bytes past the reliable size were sent, and the ACK of the first flight arrives after the reset (nothing was released
     * before it): the send buffer accounting stays exact and the stream retires.
     */
    @Test fun ackOfBytesPastTheReliableSizeKeepsTheBufferExact() {
        val p = CorePair(clientQuic = on, serverQuic = on)
        try {
            p.established()
            val id = p.client.openStream(bidi = false, StreamPriority.Default)
            p.filterToClient = { _, _ -> false } // the server's ACKs are held back
            p.client.writeStream(id, ByteArray(200_000) { it.toByte() }, 0, 200_000, fin = false)
            assertTrue(p.runUntil { p.client.streams.sentEndForTest(id) >= 5_000 })
            assertEquals(0L, p.client.streams.releasedForTest(id))
            p.client.resetStreamAt(id, 3, 10)
            p.filterToClient = { _, _ -> true }
            var violation: String? = null
            assertTrue(
                p.runUntil(limit = 30.seconds) {
                    violation = violation ?: p.client.streams.invariantViolationForTest()
                    p.clientEvents.any { it is ConnectionEvent.StreamFinished && it.id == id }
                },
            )
            assertNull(violation)
            assertNull(p.client.streams.invariantViolationForTest())
            assertEquals(0L, p.client.streams.sendBufferedBytes)
        } finally {
            p.close()
        }
    }

    /**
     * Section 4: RESET_STREAM_AT must not announce a final size beyond the peer's flow-control limits; it waits until the
     * reliable bytes went out within them, here past a 16 KiB stream window.
     */
    @Test fun resetAtWaitsForFlowControlCredit() {
        val p =
            CorePair(
                clientQuic = on,
                serverQuic =
                    quicConfig {
                        resetStreamAt = true
                        initialStreamWindow = 16_384
                    },
            )
        try {
            p.established()
            val id = p.client.openStream(bidi = false, StreamPriority.Default)
            val data = ByteArray(100_000) { (it * 3).toByte() }
            p.client.writeStream(id, data, 0, data.size, fin = false)
            p.client.resetStreamAt(id, 5, 60_000)
            val got = p.readAll(id)
            assertNull(p.closedReason(p.serverEvents))
            assertNull(p.closedReason(p.clientEvents))
            assertTrue(got.bytes.size >= 60_000, "${got.bytes.size} bytes")
            assertContentEquals(data.copyOf(got.bytes.size), got.bytes)
            assertEquals(5L, got.resetCode)
        } finally {
            p.close()
        }
    }

    /** draft-11 section 5.2: a later reset with another code is STREAM_STATE_ERROR. */
    @Test fun negative_resetCodeChangeIsStreamStateError() {
        val p = CorePair(clientQuic = on, serverQuic = on)
        try {
            p.established()
            val id = p.client.openStream(bidi = false, StreamPriority.Default)
            p.client.writeStream(id, ByteArray(100), 0, 100, fin = false)
            p.client.streams.tamperResetStreamAtForTest = { it.a = 9 } // the frame says 9, the RESET_STREAM below says 1
            p.client.resetStreamAt(id, 1, 50)
            p.step()
            p.step()
            p.client.resetStream(id, 1)
            assertTrue(p.runUntil { p.closedReason(p.clientEvents) != null })
            val reason = assertIs<QuicException.ConnectionLost.TransportClosed>(p.closedReason(p.clientEvents))
            assertEquals(TransportError.STREAM_STATE_ERROR, reason.code)
        } finally {
            p.close()
        }
    }
}
