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
import io.kuicksilver.quic.core.MIN_WINDOW_DATAGRAM
import io.kuicksilver.quic.quicConfig
import io.kuicksilver.quic.runtime.ConnectionRuntime
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.async
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.collect
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.take
import kotlinx.coroutines.flow.takeWhile
import kotlinx.coroutines.flow.toList
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withContext
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

    /**
     * Holds the server's address and fills the client's congestion window with stream data, so datagrams queue up instead of
     * leaving at once; [reopen] lets everything through. Held, not cut: the window does not stay shut for certain, and a
     * datagram that leaves meanwhile waits on the path instead of vanishing (RFC 9221 section 5.2: a lost DATAGRAM is never
     * resent), so a test counts its queue, not the network. A PTO probe leaves beyond the window (RFC 9002 section 6.2.4),
     * and an ACK the server sent before the hold, read by the client only later, opens it: on a cut path the datagrams that
     * then left were gone (linux-x64 CI, sendDatagramUnderRejectSuspendsUntilSpace). Those late ACKs come every time here:
     * the client's address is held too, from before the server acknowledges the stream's first packets (an ACK at least
     * every second ack-eliciting packet, RFC 9000 section 13.2.2) until [reopen] or [ApiPair.net].release(...).
     */
    private suspend fun congest(
        p: ApiPair,
        c: QuicConnection,
    ): io.kuicksilver.quic.QuicStream {
        p.net.hold(p.clientIo.localAddress)
        val st = c.openBidi()
        val blob = ByteArray(300_000)
        st.output.writeFully(blob, 0, 6000)
        st.output.flush()
        p.net.awaitHeld(p.clientIo.localAddress, 2)
        p.net.hold(p.server.localAddress)
        st.output.writeFully(blob, 6000, blob.size - 6000)
        st.output.flush()
        // full as the core counts it: less room than MIN_WINDOW_DATAGRAM left (not bytes_in_flight >= cwnd, which a window
        // left with 974 bytes reached only at the next PTO, 16 s away in negative_datagramQueueCap)
        while (c.stats.let { it.cwnd - it.bytesInFlight } >= MIN_WINDOW_DATAGRAM) {
            delay(5)
        }
        return st
    }

    /**
     * [c]'s stats once [cond] holds of them, judged on its loop after each of its flushes (the tick a Reject sender waits on,
     * [ConnectionRuntime.newTicker]): every datagram the loop delivers to the connection is followed by one, no sleep.
     */
    private suspend fun awaitStats(
        c: ConnectionRuntime,
        cond: (io.kuicksilver.quic.ConnectionStats) -> Boolean,
    ): io.kuicksilver.quic.ConnectionStats =
        withContext(c.loopDispatcherForTest) {
            val ticker = c.newTicker()
            try {
                var st = c.stats
                while (!cond(st)) {
                    ticker.receive()
                    st = c.stats
                }
                st
            } finally {
                c.removeTicker(ticker)
            }
        }

    /** Ends [congest]: the server's late ACKs reach the client first (the window opens; what leaves waits in the hold), then the server gets everything held. */
    private fun reopen(p: ApiPair) {
        p.net.release(p.clientIo.localAddress)
        p.net.release(p.server.localAddress)
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
                    // a try-method answers, it does not throw: a caller that loops on QueueFull must see a terminal answer instead (early user feedback)
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
            // the server announces the largest max_ack_delay, so the client's first PTO is over 16 s away: a PTO probe may
            // carry a queued datagram (RFC 9002 section 6.2.4), and one that fired while the queue filled made the 33rd fit
            // (run 38287900994, Linux arm64)
            ApiPair.open(serverQuic = quicConfig { maxAckDelay = 16_383.milliseconds }).use { p ->
                withTimeout(30.seconds) {
                    val (c, s) = p.connect()
                    congest(p, c)
                    // the queue holds 32: under Reject, datagrams are accepted until it is full. A PTO probe may carry a queued
                    // datagram past cwnd (RFC 9002 section 6.2.4; max_ack_delay does not delay the PTO of the handshake spaces,
                    // section 6.2.1), freeing a slot, and each packet carries at most one of these 1000-byte datagrams: so at most
                    // 32 plus the packets sent meanwhile are accepted, and never fewer than 32
                    val sentBefore = c.stats.packetsSent
                    var accepted = 0
                    var last: DatagramSendResult = DatagramSendResult.Sent
                    while (accepted < 64) {
                        last = c.trySendDatagram(payload(accepted, 1000), DatagramPolicy.Reject)
                        if (last != DatagramSendResult.Sent) break
                        accepted++
                    }
                    val leftOnTheWire = c.stats.packetsSent - sentBefore
                    assertEquals(DatagramSendResult.QueueFull, last, "Reject ends with QueueFull after $accepted")
                    assertTrue(accepted >= 32, "all 32 slots are usable: $accepted accepted")
                    assertTrue(
                        accepted <= 32 + leftOnTheWire,
                        "never more than 32 queued: $accepted accepted while $leftOnTheWire packets left (ptoCount=${c.stats.ptoCount})",
                    )
                    repeat(1000) {
                        assertEquals(DatagramSendResult.Sent, c.trySendDatagram(payload(it, 1000), DatagramPolicy.DropOldest))
                    } // DropOldest never refuses (the queue itself stays at 32: DatagramSendQueueTest)
                    reopen(p)
                    // receive side: 1000 datagrams nobody collects → the newest 128 survive in the core's queue
                    repeat(1000) { s.sendDatagram(ByteArray(4) { b -> (it shr (8 * b)).toByte() }, DatagramPolicy.Reject) }
                    // settled: the server sent and saw acknowledged all 1000 (so the client received them) and the client evicted 872
                    val sr = s as io.kuicksilver.quic.runtime.ConnectionRuntime
                    val settled =
                        withTimeoutOrNull(10.seconds) {
                            while (sr.datagramsQueuedForTest > 0 || s.stats.bytesInFlight > 0 ||
                                c.stats.datagramsDropped < 1000 - 128
                            ) {
                                delay(10)
                            }
                            true
                        }
                    assertTrue(settled == true, "queued ${sr.datagramsQueuedForTest}, dropped ${c.stats.datagramsDropped}")
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
                    reopen(p)
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
                    assertEquals(false, c.peerSupportsDatagrams)
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

    /** A peer `max_datagram_frame_size` of 3..34 is support for small datagrams (RFC 9221 section 3), not PeerDoesNotSupport. */
    @Test fun aSmallPeerLimitSendsSmallDatagrams() =
        runBlocking {
            ApiPair.open(serverQuic = quicConfig { maxDatagramFrameSize = 10 }).use { p ->
                withTimeout(20.seconds) {
                    val (c, s) = p.connect()
                    assertEquals(8, c.maxDatagramSize.value, "a 10-byte frame: type, 1-byte Length, 8 bytes")
                    val got = async { s.datagrams.take(2).toList() }
                    assertEquals(DatagramSendResult.Sent, c.trySendDatagram(payload(1, 8)))
                    c.sendDatagram(ByteArray(0), DatagramPolicy.Reject)
                    assertEquals(DatagramSendResult.TooLarge(8), c.trySendDatagram(ByteArray(9)))
                    assertEquals(listOf(payload(1, 8).toList(), emptyList()), got.await().map { it.data.toList() })
                    c.close()
                    s.close()
                }
            }
        }

    /** A peer limit of 2 leaves room for an empty datagram only: maxDatagramSize is 0, yet the peer supports datagrams. */
    @Test fun aPeerLimitOfTwoIsSupportForEmptyDatagrams() =
        runBlocking {
            ApiPair.open(serverQuic = quicConfig { maxDatagramFrameSize = 2 }).use { p ->
                withTimeout(20.seconds) {
                    val (c, s) = p.connect()
                    assertEquals(0, c.maxDatagramSize.value)
                    assertEquals(true, c.peerSupportsDatagrams)
                    assertEquals(true, s.peerSupportsDatagrams, "the client advertises the default 65535")
                    val got = async { s.datagrams.take(1).toList() }
                    assertEquals(DatagramSendResult.Sent, c.trySendDatagram(ByteArray(0)))
                    assertEquals(DatagramSendResult.TooLarge(0), c.trySendDatagram(ByteArray(1)))
                    assertEquals(listOf(0), got.await().map { it.data.size })
                    c.close()
                    s.close()
                }
            }
        }

    /** A peer limit of 1 is support (RFC 9221 section 3) that no frame this endpoint writes fits: TooLarge(0) even when empty, not Unsupported. */
    @Test fun aPeerLimitOfOneIsSupportThatNothingFits() =
        runBlocking {
            ApiPair.open(serverQuic = quicConfig { maxDatagramFrameSize = 1 }).use { p ->
                withTimeout(20.seconds) {
                    val (c, s) = p.connect()
                    assertEquals(true, c.peerSupportsDatagrams)
                    assertEquals(0, c.maxDatagramSize.value)
                    assertEquals(DatagramSendResult.TooLarge(0), c.trySendDatagram(ByteArray(0)))
                    assertEquals(0, assertFailsWith<QuicException.DatagramTooLarge> { c.sendDatagram(ByteArray(0)) }.max)
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
                    // a connection's first search begins with its first application data after the handshake was confirmed (RFC 8899
                    // section 4.3, Pmtud.waitsForData): data written before the client saw HANDSHAKE_DONE does not count, so the client
                    // keeps writing a little on a stream of its own until the size rose (a datagram would be read below instead of [1, 2, 3])
                    val warm = c.openBidi()
                    withTimeoutOrNull(20.seconds) {
                        while (c.maxDatagramSize.value <
                            1380
                        ) {
                            warm.output.writeFully(ByteArray(8))
                            warm.output.flush()
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

    /**
     * Reject never drops a datagram of its own: a sender over the 32-datagram queue waits for room, and all 33 arrive. Room comes
     * as a queued datagram leaves: in a PTO probe, which may leave before the server's late ACKs ([congest]) and beyond the window
     * (RFC 9002 section 6.2.4; run 45958310638, JDK 25 Linux, the 33rd got in on a probe 30-330 ms after it began to wait), or on
     * the window those ACKs open. What left waits in the server's hold either way; on a cut path it was lost and the server waited
     * for 33 forever.
     */
    @Test fun sendDatagramUnderRejectSuspendsUntilSpace() =
        runBlocking {
            ApiPair.open().use { p ->
                withTimeout(20.seconds) {
                    val (c, s) = p.connect()
                    congest(p, c)
                    // The 32 and the 33rd go from the connection's loop thread, so the loop sends nothing in between and the
                    // 33rd finds the queue full. UNDISPATCHED runs the 33rd up to its first suspension here, on the loop thread.
                    val scope = this
                    val blocked =
                        withContext((c as ConnectionRuntime).loopDispatcherForTest) {
                            repeat(32) { c.sendDatagram(payload(it), DatagramPolicy.Reject) }
                            val thirtyThird =
                                scope.async(start = CoroutineStart.UNDISPATCHED) {
                                    c.sendDatagram(payload(32), DatagramPolicy.Reject)
                                    true
                                }
                            assertFalse(thirtyThird.isCompleted, "the 33rd waits for room")
                            thirtyThird
                        }
                    // the window and the packet count as the loop sees them; nothing reaches the client before the release, so
                    // neither moves meanwhile (a PTO probe adds to the bytes in flight, never to the window)
                    val before = withContext(c.loopDispatcherForTest) { c.stats }
                    // the server's ACKs reach the client while the server's address is still held: the window opens, datagrams
                    // leave (into the hold) and the 33rd gets in, unless a PTO probe already took one out of the queue
                    val late = p.net.release(p.clientIo.localAddress)
                    assertTrue(late >= 2, "the server's ACKs were held: $late")
                    assertTrue(blocked.await(), "room came as datagrams left")
                    // the late ACKs did come, before the server's release: they acknowledged the stream's first packets while the
                    // window was full (cwnd-limited, section 7.8) and nothing was lost (no recovery period, section 7.3.2), so slow
                    // start grows the window by what they acknowledged (RFC 9002 section 7.3.1). Judged once the client processed
                    // all [late] of them: a packet is counted after its frames ran, on the loop, and the 33rd may have got in on a
                    // probe before the first of them
                    val after = awaitStats(c) { it.packetsReceived >= before.packetsReceived + late }
                    assertEquals(before.lostPackets, after.lostPackets, "nothing was lost: no recovery period")
                    assertTrue(
                        after.cwnd > before.cwnd,
                        "the late ACKs grew the window: ${after.cwnd} after ${before.cwnd} ($late held, ${after.ptoCount} PTOs)",
                    )
                    p.net.release(p.server.localAddress)
                    val got = s.datagrams.take(33).toList()
                    assertEquals((0 until 33).toSet(), got.map { key(it) }.toSet(), "every datagram, the 33rd included")
                    c.close()
                    s.close()
                }
            }
        }
}
