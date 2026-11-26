// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.core

import io.kuicksilver.annotations.DelicateKuicksilverApi
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.native.KslLoader
import io.kuicksilver.quic.ConnectionEvent
import io.kuicksilver.quic.CorePair
import io.kuicksilver.quic.StreamPriority
import io.kuicksilver.quic.quicConfig
import kotlin.random.Random
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.seconds

/**
 * ConnectionEvent.StreamFinalSize in the core (RFC 9000 section 4.5): raised exactly once per half, with the size the
 * peer counts, whatever frames follow (retransmissions, a reset after the FIN or after RESET_STREAM_AT, STOP_SENDING
 * after our reset).
 */
@OptIn(ExperimentalKuicksilverApi::class, DelicateKuicksilverApi::class)
class StreamFinalSizeTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    private val on = quicConfig { expert { resetStreamAt = true } }

    private fun List<ConnectionEvent>.finals(
        id: Long,
        sending: Boolean,
    ): List<Long> = filterIsInstance<ConnectionEvent.StreamFinalSize>().filter { it.id == id && it.sending == sending }.map { it.size }

    private fun pair(quic: io.kuicksilver.quic.QuicConfig = io.kuicksilver.quic.QuicConfig.Default): CorePair =
        CorePair(clientQuic = quic, serverQuic = quic).also { assertTrue(it.handshake()) }

    /** Reads all [id] holds on the server now. */
    private fun CorePair.drain(id: Long) {
        val b = ByteArray(65536)
        while (true) if (server!!.readStream(id, b, 0, b.size) <= 0) break
    }

    @Test fun negative_retransmittedResetStreamIsReportedOnce() {
        val p = pair()
        try {
            val id = p.client.openStream(bidi = false, StreamPriority.Default)
            p.client.writeStream(id, ByteArray(3000), 0, 3000, fin = false)
            assertTrue(p.runUntil { p.serverEvents.any { it is ConnectionEvent.StreamOpened && it.id == id } })
            p.drain(id)
            val loss = Random(3)
            p.filterToServer = { _, _ -> loss.nextInt(3) != 0 } // a third is lost: RESET_STREAM goes again
            p.client.resetStream(id, 7)
            assertTrue(p.runUntil(limit = 30.seconds) { p.serverEvents.finals(id, sending = false).isNotEmpty() })
            p.runUntil(limit = 5.seconds) { false }
            assertEquals(p.clientEvents.finals(id, sending = true), p.serverEvents.finals(id, sending = false))
            assertEquals(1, p.clientEvents.finals(id, sending = true).size)
        } finally {
            p.close()
        }
    }

    /** A FIN fixes the size when it first goes out; a RESET_STREAM_AT afterwards carries it too and reports nothing more. */
    @Test fun negative_resetAtAfterTheFinIsNotReportedAgain() {
        val p = pair(on)
        try {
            val id = p.client.openStream(bidi = false, StreamPriority.Default)
            p.client.writeStream(id, ByteArray(100), 0, 100, fin = true)
            p.filterToClient = { _, _ -> false } // no acknowledgement: the FIN went out, it is not known to have arrived
            assertTrue(p.runUntil { p.clientEvents.finals(id, sending = true).isNotEmpty() })
            p.client.resetStreamAt(id, 3, 10)
            p.client.resetStream(id, 3)
            p.filterToClient = { _, _ -> true }
            p.runUntil(limit = 5.seconds) { false }
            assertEquals(listOf(100L), p.clientEvents.finals(id, sending = true))
            assertEquals(listOf(100L), p.serverEvents.finals(id, sending = false))
        } finally {
            p.close()
        }
    }

    /** RESET_STREAM after RESET_STREAM_AT: one report, the size the RESET_STREAM_AT announced. */
    @Test fun negative_resetAfterResetAtIsReportedOnce() {
        val p = pair(on)
        try {
            val id = p.client.openStream(bidi = false, StreamPriority.Default)
            p.client.writeStream(id, ByteArray(500), 0, 500, fin = false)
            assertTrue(p.runUntil { p.serverEvents.any { it is ConnectionEvent.StreamOpened && it.id == id } })
            p.client.resetStreamAt(id, 3, 200)
            assertTrue(p.runUntil { p.clientEvents.finals(id, sending = true).isNotEmpty() })
            p.client.resetStream(id, 3)
            p.runUntil(limit = 5.seconds) { false }
            assertEquals(listOf(500L), p.clientEvents.finals(id, sending = true))
            assertEquals(listOf(500L), p.serverEvents.finals(id, sending = false))
        } finally {
            p.close()
        }
    }

    /** The peer's STOP_SENDING after our reset is answered by nothing new: one report. */
    @Test fun negative_stopSendingAfterOurResetIsReportedOnce() {
        val p = pair()
        try {
            val id = p.client.openStream(bidi = true, StreamPriority.Default)
            p.client.writeStream(id, ByteArray(400), 0, 400, fin = false)
            assertTrue(p.runUntil { p.serverEvents.any { it is ConnectionEvent.StreamOpened && it.id == id } })
            p.client.resetStream(id, 1)
            p.server!!.stopSending(id, 2)
            p.runUntil(limit = 5.seconds) { false }
            assertEquals(1, p.clientEvents.finals(id, sending = true).size)
            assertEquals(p.clientEvents.finals(id, sending = true), p.serverEvents.finals(id, sending = false))
        } finally {
            p.close()
        }
    }

    /** The peer's FIN on a half we already stopped still tells its size, once. */
    @Test fun finOnAStoppedHalfIsReported() {
        val p = pair()
        try {
            val id = p.client.openStream(bidi = true, StreamPriority.Default)
            p.client.writeStream(id, ByteArray(10), 0, 10, fin = false)
            assertTrue(p.runUntil { p.serverEvents.any { it is ConnectionEvent.StreamOpened && it.id == id } })
            p.server!!.stopSending(id, 2)
            p.client.writeStream(id, ByteArray(90), 0, 90, fin = true)
            p.runUntil(limit = 5.seconds) { false }
            val got = p.serverEvents.finals(id, sending = false)
            assertEquals(1, got.size)
            assertEquals(p.clientEvents.finals(id, sending = true), got)
        } finally {
            p.close()
        }
    }

    /** A reset after the FIN went out but before its acknowledgement carries every byte written. */
    @Test fun resetAfterAnUnacknowledgedFinCarriesEveryByte() {
        val p = pair()
        try {
            val id = p.client.openStream(bidi = false, StreamPriority.Default)
            p.client.writeStream(id, ByteArray(1234), 0, 1234, fin = true)
            p.filterToClient = { _, _ -> false }
            assertTrue(p.runUntil { p.clientEvents.finals(id, sending = true).isNotEmpty() })
            p.client.resetStream(id, 4)
            p.filterToClient = { _, _ -> true }
            p.runUntil(limit = 5.seconds) { false }
            assertEquals(listOf(1234L), p.clientEvents.finals(id, sending = true))
            assertEquals(listOf(1234L), p.serverEvents.finals(id, sending = false))
        } finally {
            p.close()
        }
    }

    /**
     * RFC 9000 section 3.1: a sender resets from "the "Ready", "Send", or "Data Sent" states". Once every byte and the FIN
     * were acknowledged (Data Recvd) a reset queues no RESET_STREAM.
     */
    @Test fun negative_resetAfterEverythingWasAcknowledgedSendsNothing() {
        val p = pair()
        try {
            val id = p.client.openStream(bidi = true, StreamPriority.Default)
            p.client.writeStream(id, ByteArray(10), 0, 10, fin = true)
            assertTrue(p.runUntil { p.serverEvents.any { it is ConnectionEvent.StreamOpened && it.id == id } })
            p.drain(id)
            // the server's own half stays open, so the stream stays: its sending half is in Data Recvd once acknowledged
            assertTrue(p.runUntil { p.client.streams.sendStateForTest(id) == "DataRecvd" })
            val controlBefore = p.client.streams.sizesForTest()[1]
            p.client.resetStream(id, 9)
            assertEquals(controlBefore, p.client.streams.sizesForTest()[1], "no RESET_STREAM queued")
            p.runUntil(limit = 2.seconds) { false }
            assertTrue(p.serverEvents.none { it is ConnectionEvent.StreamReset && it.id == id })
            assertEquals(listOf(10L), p.clientEvents.finals(id, sending = true))
        } finally {
            p.close()
        }
    }
}
