// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.api

import io.ktor.utils.io.readAvailable
import io.ktor.utils.io.writeFully
import io.kuicksilver.annotations.DelicateKuicksilverApi
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.native.KslLoader
import io.kuicksilver.quic.Datagram
import io.kuicksilver.quic.DatagramPolicy
import io.kuicksilver.quic.DatagramSendResult
import io.kuicksilver.quic.DatagramUnsupportedReason
import io.kuicksilver.quic.QuicConnection
import io.kuicksilver.quic.QuicException
import io.kuicksilver.quic.quicConfig
import kotlinx.coroutines.async
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.collect
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.take
import kotlinx.coroutines.flow.takeWhile
import kotlinx.coroutines.flow.toList
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import kotlinx.coroutines.withTimeoutOrNull
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.seconds

/** RFC 9221: the datagram API over the in-memory network (all platforms). */
@OptIn(ExperimentalKuicksilverApi::class, DelicateKuicksilverApi::class)
class DatagramApiTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    private fun payload(
        i: Int,
        size: Int = 100,
    ) = ByteArray(size) { (i + it).toByte() }

    private fun key(d: Datagram): Int = d.data[0].toInt() and 0xff

    /** Cuts the server's address and fills the client's congestion window with stream data, so datagrams queue up instead of leaving at once; [ApiPair.net].uncut(...) reconnects. */
    private suspend fun congest(
        p: ApiPair,
        c: QuicConnection,
    ): io.kuicksilver.quic.QuicStream {
        p.net.cut(p.server.localAddress)
        val st = c.openBidi()
        val blob = ByteArray(300_000)
        st.output.writeFully(blob, 0, blob.size)
        st.output.flush()
        while (c.stats.bytesInFlight <
            c.stats.cwnd
        ) {
            delay(5)
        }
        return st
    }

    @Test fun echoDatagrams() =
        runBlocking {
            ApiPair.open().use { p ->
                withTimeout(20.seconds) {
                    val (c, s) = p.connect()
                    val echo = launch { s.datagrams.take(50).collect { s.sendDatagram(it.data, DatagramPolicy.Reject) } }
                    val back = async { c.datagrams.take(50).toList() }
                    repeat(50) {
                        c.sendDatagram(payload(it), DatagramPolicy.Reject)
                    } // Reject waits for room: a burst above the 32-datagram queue is lossless; DropOldest may drop the oldest of it
                    val got = back.await()
                    echo.join()
                    assertEquals(50, got.size)
                    assertEquals((0 until 50).toSet(), got.map { key(it) }.toSet())
                    assertContentEquals(
                        payload(7),
                        got
                            .first {
                                key(it) ==
                                    7
                            }.data,
                    )
                    c.close()
                    s.close()
                }
            }
        }

    @Test fun trySendDatagramAfterCloseAnswersClosed() =
        runBlocking {
            ApiPair.open().use { p ->
                withTimeout(30.seconds) {
                    // a try-method answers, it does not throw: a caller that loops on QueueFull must see a terminal answer instead (K4 feedback E9)
                    val (c, s) = p.connect()
                    c.close()
                    c.closed.await()
                    assertEquals(DatagramSendResult.Closed, c.trySendDatagram(payload(1), DatagramPolicy.DropOldest))
                    assertEquals(DatagramSendResult.Closed, c.trySendDatagram(payload(1), DatagramPolicy.Reject))
                    s.close()
                }
            }
        }

    @Test fun negative_datagramQueueCap() =
        runBlocking {
            ApiPair.open().use { p ->
                withTimeout(30.seconds) {
                    val (c, s) = p.connect()
                    congest(p, c)
                    repeat(
                        32,
                    ) {
                        assertEquals(
                            DatagramSendResult.Sent,
                            c.trySendDatagram(payload(it, 1000), DatagramPolicy.Reject),
                            "slot ${it + 1} of 32",
                        )
                    }
                    assertEquals(
                        DatagramSendResult.QueueFull,
                        c.trySendDatagram(payload(99, 1000), DatagramPolicy.Reject),
                        "the 33rd under Reject",
                    )
                    repeat(1000) {
                        assertEquals(DatagramSendResult.Sent, c.trySendDatagram(payload(it, 1000), DatagramPolicy.DropOldest))
                    } // DropOldest never refuses (the queue itself stays at 32: DatagramSendQueueTest)
                    p.net.uncut(p.server.localAddress)
                    // receive side: 1000 datagrams nobody collects → the newest 128 survive in the core's queue
                    repeat(1000) { s.sendDatagram(ByteArray(4) { b -> (it shr (8 * b)).toByte() }, DatagramPolicy.Reject) }
                    withTimeoutOrNull(10.seconds) { while (s.stats.bytesInFlight > 0 || s.core.datagramSender!!.hasPending()) delay(10) }
                    delay(100)
                    val got = withTimeoutOrNull(5.seconds) { c.datagrams.take(128).toList() }!!
                    assertEquals(128, got.size)
                    assertEquals(
                        999,
                        got.last().data.let { (it[0].toInt() and 0xff) or ((it[1].toInt() and 0xff) shl 8) },
                        "the newest arrives last",
                    )
                    assertTrue(c.stats.datagramsDropped >= 800L, "dropped ${c.stats.datagramsDropped}")
                    assertNull(withTimeoutOrNull(300.milliseconds) { c.datagrams.first() }, "nothing more queued")
                    c.close()
                    s.close()
                }
            }
        }

    @Test fun dropOldestFloodStaysBounded() =
        runBlocking {
            ApiPair.open().use { p ->
                withTimeout(60.seconds) {
                    // commands from a tight trySendDatagram loop are bounded too, not only the loop-side queue
                    val (c, s) = p.connect()
                    p.net.cut(p.server.localAddress)
                    val rt = c as io.kuicksilver.quic.runtime.ConnectionRuntime
                    val data = payload(1)
                    var max = 0
                    repeat(1_000_000) {
                        c.trySendDatagram(data, DatagramPolicy.DropOldest)
                        val n = rt.datagramsQueuedForTest
                        if (n > max) max = n
                    }
                    assertTrue(
                        max <= 2 * 32 + 1,
                        "at most twice the 32-datagram cap (plus the one waiting for room) was ever buffered: $max",
                    )
                    c.close()
                    s.close()
                }
            }
        }

    @Test fun latestWinsReplacesByKey() =
        runBlocking {
            ApiPair.open().use { p ->
                withTimeout(20.seconds) {
                    // exact replacement semantics: DatagramSendQueueTest; here end to end — the newest A arrives, and never an older A after it
                    val (c, s) = p.connect()
                    val st = congest(p, c)
                    assertEquals(DatagramSendResult.Sent, c.trySendDatagram(byteArrayOf(1, 1), DatagramPolicy.LatestWins("A")))
                    assertEquals(DatagramSendResult.Sent, c.trySendDatagram(byteArrayOf(2, 1), DatagramPolicy.LatestWins("B")))
                    assertEquals(DatagramSendResult.Sent, c.trySendDatagram(byteArrayOf(1, 2), DatagramPolicy.LatestWins("A")))
                    p.net.uncut(p.server.localAddress)
                    val got = ArrayList<List<Byte>>()
                    withTimeoutOrNull(5.seconds) {
                        s.datagrams
                            .takeWhile {
                                got += it.data.toList()
                                !(
                                    got.contains(listOf<Byte>(2, 1)) &&
                                        got.contains(listOf<Byte>(1, 2))
                                )
                            }.collect()
                    }
                    assertTrue(got.contains(listOf<Byte>(2, 1)) && got.contains(listOf<Byte>(1, 2)), "B and the latest A arrive: $got")
                    assertTrue(
                        got.indexOf(listOf<Byte>(1, 1)).let {
                            it <
                                0 ||
                                it < got.indexOf(listOf<Byte>(1, 2))
                        },
                        "no stale A after the latest: $got",
                    )
                    st.output.flushAndClose()
                    c.close()
                    s.close()
                }
            }
        }

    @Test fun tooLargeResultAndException() =
        runBlocking {
            ApiPair.open().use { p ->
                withTimeout(20.seconds) {
                    val (c, s) = p.connect()
                    val max = c.maxDatagramSize.value
                    assertTrue(max in 1000..1200, "max $max")
                    assertEquals(DatagramSendResult.Sent, c.trySendDatagram(ByteArray(max)))
                    assertEquals(
                        DatagramSendResult.TooLarge(max),
                        c.trySendDatagram(
                            ByteArray(max + 1),
                        ),
                    )
                    val e = assertFailsWith<QuicException.DatagramTooLarge> { c.sendDatagram(ByteArray(max + 1)) }
                    assertEquals(max + 1, e.size)
                    assertEquals(max, e.max)
                    c.close()
                    s.close()
                }
            }
        }

    @Test fun unsupportedWhenPeerDisabled() =
        runBlocking {
            ApiPair.open(serverQuic = quicConfig { maxDatagramFrameSize = 0 }).use { p ->
                withTimeout(20.seconds) {
                    val (c, s) = p.connect()
                    assertEquals(0, c.maxDatagramSize.value)
                    assertEquals(
                        DatagramSendResult.Unsupported(DatagramUnsupportedReason.PeerDoesNotSupport),
                        c.trySendDatagram(ByteArray(10)),
                    )
                    assertEquals(
                        DatagramUnsupportedReason.PeerDoesNotSupport,
                        assertFailsWith<QuicException.DatagramUnsupported> {
                            c.sendDatagram(ByteArray(10))
                        }.reason,
                    )
                    c.close()
                    s.close()
                }
            }
        }

    @Test fun unsupportedWhenLocallyDisabled() =
        runBlocking {
            ApiPair.open().use { p ->
                withTimeout(20.seconds) {
                    val (c, s) = p.connect(quicConfig { maxDatagramFrameSize = 0 })
                    assertEquals(DatagramSendResult.Unsupported(DatagramUnsupportedReason.Disabled), c.trySendDatagram(ByteArray(10)))
                    assertEquals(
                        DatagramUnsupportedReason.Disabled,
                        assertFailsWith<QuicException.DatagramUnsupported> {
                            c.sendDatagram(ByteArray(10))
                        }.reason,
                    )
                    c.close()
                    s.close()
                }
            }
        }

    @Test fun maxDatagramSizeFlowTracksPathMtu() =
        runBlocking {
            ApiPair.open().use { p ->
                withTimeout(20.seconds) {
                    val (c, s) = p.connect()
                    assertEquals(c.core.maxDatagramPayload, c.maxDatagramSize.value)
                    assertEquals(1136, c.maxDatagramSize.value, "1200-byte MTU, 8-byte DCID, 32 bytes kept for an ACK")
                    c.close()
                    s.close()
                }
            }
        }

    @Test fun queuedDatagramsAboveNewMtuDroppedAfterBlackHole() =
        runBlocking {
            ApiPair.open(df = true).use { p ->
                withTimeout(60.seconds) {
                    // review focus 4: the path MTU shrinks under a queue of large datagrams; they can no longer be sent and are dropped instead of blocking the queue
                    val (c, s) = p.connect()
                    withTimeoutOrNull(20.seconds) {
                        while (c.maxDatagramSize.value <
                            1380
                        ) {
                            delay(20)
                        }
                    }
                    assertTrue(c.maxDatagramSize.value >= 1380, "search raised the MTU: ${c.maxDatagramSize.value}")
                    p.net.mtu = 1280
                    val got = async { s.datagrams.first() }
                    repeat(40) {
                        assertEquals(DatagramSendResult.Sent, c.trySendDatagram(ByteArray(1380) { 9 }))
                    } // queued while the path is believed to carry 1452
                    val st = c.openBidi()
                    st.output.writeFully(ByteArray(300_000), 0, 300_000)
                    st.output.flush()
                    withTimeoutOrNull(30.seconds) {
                        while (c.maxDatagramSize.value >=
                            1380
                        ) {
                            delay(20)
                        }
                    }
                    assertTrue(c.maxDatagramSize.value < 1380, "black hole: ${c.maxDatagramSize.value}")
                    assertEquals(DatagramSendResult.Sent, c.trySendDatagram(byteArrayOf(1, 2, 3)))
                    assertContentEquals(
                        byteArrayOf(1, 2, 3),
                        got.await().data,
                        "the small datagram arrives: the oversized ones were dropped, not stuck ahead of it",
                    )
                    assertTrue(c.stats.datagramsDroppedSend >= 1L)
                    c.close()
                    s.close()
                }
            }
        }

    @Test fun sendDatagramUnderRejectSuspendsUntilSpace() =
        runBlocking {
            ApiPair.open().use { p ->
                withTimeout(20.seconds) {
                    val (c, s) = p.connect()
                    congest(p, c)
                    repeat(32) { c.sendDatagram(payload(it), DatagramPolicy.Reject) }
                    val blocked =
                        async {
                            c.sendDatagram(payload(32), DatagramPolicy.Reject)
                            true
                        }
                    kotlinx.coroutines.yield()
                    assertFalse(blocked.isCompleted, "the 33rd waits for room")
                    p.net.uncut(p.server.localAddress)
                    assertTrue(blocked.await(), "room came as datagrams left")
                    assertEquals(
                        33,
                        s.datagrams
                            .take(33)
                            .toList()
                            .size,
                    )
                    c.close()
                    s.close()
                }
            }
        }
}
