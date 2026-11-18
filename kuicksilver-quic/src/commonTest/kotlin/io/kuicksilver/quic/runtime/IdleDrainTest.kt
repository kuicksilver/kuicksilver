// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(ExperimentalKuicksilverApi::class, DelicateKuicksilverApi::class, kotlinx.coroutines.ExperimentalCoroutinesApi::class)

package io.kuicksilver.quic.runtime

import io.ktor.network.sockets.InetSocketAddress
import io.ktor.utils.io.readByte
import io.ktor.utils.io.writeByte
import io.kuicksilver.annotations.DelicateKuicksilverApi
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.quic.ConnectionState
import io.kuicksilver.quic.CoreFixtures
import io.kuicksilver.quic.MemoryDatagramIo
import io.kuicksilver.quic.MemoryNetwork
import io.kuicksilver.quic.NullCryptoProvider
import io.kuicksilver.quic.QuicClientConfig
import io.kuicksilver.quic.QuicConnection
import io.kuicksilver.quic.QuicEndpoint
import io.kuicksilver.quic.QuicEndpointConfig
import io.kuicksilver.quic.QuicException
import io.kuicksilver.quic.QuicServerConfig
import io.kuicksilver.quic.TimeoutKind
import io.kuicksilver.quic.quicConfig
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.async
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import kotlin.concurrent.Volatile
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertTrue
import kotlin.time.Duration
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.seconds

/**
 * RFC 9000 section 10.1: the idle timer restarts "when a packet from its peer is received and processed successfully". A
 * process frozen past a connection's idle deadline (an Android app freeze or Doze, a sleeping laptop, a stopped debugger)
 * wakes with its timer overdue and the peer's datagrams in the socket's queue. Before an idle timer closes a connection, the
 * loop empties its sockets without waiting and processes what they held; the connection closes only if none of it restarted
 * the timer.
 *
 * The freeze is made deterministic: the client's socket is [MemoryDatagramIo.stalled], so its receive in flight hands nothing
 * back and the datagrams wait in the queue, which only the loop's drain ([io.kuicksilver.quic.QueuedReceive]) empties.
 */
class IdleDrainTest {
    private val serverAddr = InetSocketAddress("10.0.0.2", 2222)
    private val clientAddr = InetSocketAddress("10.0.0.1", 1111)

    /** Datagrams the server sent towards the client, in order (written by the server loop's thread alone, copied on write). */
    @Volatile private var toClient: List<ByteArray> = emptyList()

    /** Datagrams the client sent (the network's count). */
    @Volatile private var clientSends = 0

    /** The server's datagrams to the client are lost (nothing it sends reaches the client's queue). */
    @Volatile private var dropToClient = false

    /**
     * The client connection IDs to take the next short-header datagram for off the network, and where it goes ([captureNext]):
     * the test queues it itself, so "it waits in the client's queue" is a step the test made, never a delivery it raced.
     */
    @Volatile private var capture: Pair<List<ByteArray>, CompletableDeferred<ByteArray>>? = null

    private class Endpoints(
        val net: MemoryNetwork,
        val cio: MemoryDatagramIo,
        val server: QuicEndpoint,
        val client: EndpointLoop,
    )

    private suspend fun endpoints(idle: Duration): Endpoints {
        val net = MemoryNetwork()
        net.lose = { from, to, bytes ->
            if (from == clientAddr) clientSends++
            var taken = false
            if (from == serverAddr && to == clientAddr) {
                record(bytes)
                capture?.let { (cids, into) ->
                    val short = bytes[0].toInt() and 0x80 == 0
                    if (short && cids.any { cid -> bytes.size > cid.size && (cid.indices).all { bytes[1 + it] == cid[it] } }) {
                        capture = null
                        into.complete(bytes.copyOf())
                        taken = true
                    }
                }
            }
            taken || (from == serverAddr && to == clientAddr && dropToClient)
        }
        val sio = net.open(serverAddr)
        val cio = net.open(clientAddr)
        val server =
            QuicEndpoint.bind(
                serverAddr,
                QuicEndpointConfig
                    .Builder()
                    .apply {
                        this.server =
                            QuicServerConfig
                                .Builder(CoreFixtures.server())
                                .apply { quic = quicConfig { maxIdleTimeout = idle } }
                                .build()
                        crypto = NullCryptoProvider
                        io = { sio }
                    }.build(),
            )
        val client =
            QuicEndpoint.bind(
                clientAddr,
                QuicEndpointConfig
                    .Builder()
                    .apply {
                        crypto = NullCryptoProvider
                        io = { cio }
                    }.build(),
            ) as EndpointLoop
        return Endpoints(net, cio, server, client)
    }

    private fun record(bytes: ByteArray) {
        toClient = toClient + bytes.copyOf()
    }

    private fun lastShortHeaderToClient(): ByteArray = toClient.last { it[0].toInt() and 0x80 == 0 }

    private fun clientConfig(idle: Duration) =
        QuicClientConfig
            .Builder(CoreFixtures.client())
            .apply { quic = quicConfig { maxIdleTimeout = idle } }
            .build()

    /** Connects, then one round trip of application data, so that both sides' last activity is this exchange. */
    private suspend fun connect(
        e: Endpoints,
        idle: Duration,
    ): Pair<QuicConnection, QuicConnection> {
        val (c, s) =
            kotlinx.coroutines.coroutineScope {
                val accepted = async { e.server.accept() }
                e.client.connect(serverAddr, clientConfig(idle)) to accepted.await()
            }
        val up = c.openUni()
        up.output.writeByte(1)
        up.output.flush()
        assertEquals(1, s.acceptStream().input.readByte())
        return c to s
    }

    /**
     * The verdict of the drain for each of [cs], taken the first time the loop releases it ([EndpointLoop.onIdleReleasedForTest]):
     * true when the connection outlived its idle timer. A connection kept that way would otherwise reach its next deadline
     * while the test still waits (the acknowledgments it reads only at the drain inflate its RTT and with it the 3 x PTO
     * floor), so the client reads as usual again from the first connection kept.
     */
    private fun verdicts(
        e: Endpoints,
        vararg cs: QuicConnection,
    ): List<CompletableDeferred<Boolean>> {
        val ds = cs.map { CompletableDeferred<Boolean>() }
        val byCore = cs.map { (it as ConnectionRuntime).core }.zip(ds).toMap()
        e.client.onIdleReleasedForTest = { core ->
            val kept = core.state != ConnectionState.Closed
            byCore[core]?.complete(kept)
            if (kept) e.cio.stalled = false
        }
        return ds
    }

    /**
     * Drain rounds stay open until the returned gate completes (the client's receive, once interrupted for a round, hands
     * back only then), and a connection held for a drain stays held as long (the hold limit stretched to a minute): a
     * connection whose idle deadline passed waits for the test's next step however slow the host, and one drain then decides
     * on what the test queued, whether the deadline passed before or after it was queued.
     */
    private fun holdDrains(e: Endpoints): CompletableDeferred<Unit> {
        val gate = CompletableDeferred<Unit>()
        e.client.idleHoldLimitForTest = 60.seconds
        e.cio.interruptGate = gate
        return gate
    }

    /** Completed once [n] connections are held for a drain at once (the hook reports the count as it grows). */
    private fun heldAtOnce(
        e: Endpoints,
        n: Int,
    ): CompletableDeferred<Unit> {
        val d = CompletableDeferred<Unit>()
        e.client.onIdleHeldForTest = { held -> if (held >= n) d.complete(Unit) }
        return d
    }

    /** Takes the next datagram the server's connection [s] sends to the client off the network (by the client's CIDs). */
    private suspend fun captureNext(
        e: Endpoints,
        s: QuicConnection,
    ): CompletableDeferred<ByteArray> {
        val cids =
            kotlinx.coroutines.withContext((e.server as EndpointLoop).dispatcher) {
                (s as ConnectionRuntime)
                    .core.cids
                    .peerTokensForTest()
                    .map { it.first.toByteArray() }
            }
        return CompletableDeferred<ByteArray>().also { capture = cids to it }
    }

    /** Puts [d], from the server, in the client's queue. */
    private fun queue(
        e: Endpoints,
        d: ByteArray,
    ) = assertTrue(
        e.cio.inbox
            .trySend(d to serverAddr)
            .isSuccess,
        "the client's queue took the datagram",
    )

    private fun idleTimeout(why: Throwable?) {
        val t = assertIs<QuicException.ConnectionLost.Timeout>(why, "closed by the idle timer: $why")
        assertEquals(TimeoutKind.Idle, t.kind)
    }

    @Test fun negative_aPeerPacketQueuedAtTheIdleDeadlineKeepsTheConnection(): Unit =
        runBlocking {
            withTimeout(30.seconds) {
                val idle = 400.milliseconds
                val e = endpoints(idle)
                try {
                    val (c, s) = connect(e, idle)
                    val down = s.openUni()
                    val (kept) = verdicts(e, c)
                    val gate = holdDrains(e)
                    val held = heldAtOnce(e, 1)
                    e.cio.stalled = true // from now on the client's receive hands nothing back
                    val packet = captureNext(e, s)
                    down.output.writeByte(7)
                    down.output.flush()
                    queue(e, packet.await()) // the server's datagram waits in the client's socket
                    // the client's idle deadline passes with it unread: the loop holds the connection, takes the datagram
                    // first once the round may end, and it restarts the timer
                    held.await()
                    gate.complete(Unit)
                    assertTrue(kept.await(), "closed: ${runCatching { c.closed.getCompleted() }}")
                    assertEquals(7, c.acceptStream().input.readByte())
                    assertTrue(e.client.idleDrainRoundsForTest >= 1, "the loop drained its socket before the idle close")
                } finally {
                    e.client.close()
                    e.server.close()
                }
            }
        }

    @Test fun negative_anEmptyQueueStillClosesAtTheIdleDeadline(): Unit =
        runBlocking {
            withTimeout(30.seconds) {
                val idle = 300.milliseconds
                val e = endpoints(idle)
                try {
                    val (c, _) = connect(e, idle)
                    dropToClient = true // the server's acknowledgments and probes are lost: the client's queue stays empty
                    e.cio.stalled = true
                    idleTimeout(c.closed.await())
                    assertTrue(e.client.idleDrainRoundsForTest >= 1, "the socket was looked at before the close")
                    assertEquals(0L, e.cio.queuedTaken, "nothing was queued")
                } finally {
                    e.client.close()
                    e.server.close()
                }
            }
        }

    /**
     * Only packets that do not restart the idle timer wait in the queue: a forged copy of a server packet (its AEAD tag
     * changed), a replay of a packet already processed (a duplicate, RFC 9000 section 12.3) and random bytes. Read, processed
     * and discarded, they keep nothing alive: a peer, or anyone on the path, cannot hold a connection open with junk.
     */
    @Test fun negative_onlyUndecryptableDuplicateOrRandomDatagramsQueuedStillClose(): Unit =
        runBlocking {
            withTimeout(30.seconds) {
                val idle = 300.milliseconds
                val e = endpoints(idle)
                try {
                    val (c, _) = connect(e, idle)
                    val seen = lastShortHeaderToClient() // processed by the client during the round trip
                    dropToClient = true // only the datagrams below reach the client's queue
                    e.cio.stalled = true
                    val forged = seen.copyOf().also { it[it.size - 1] = (it[it.size - 1].toInt() xor 0x5a).toByte() }
                    val random = ByteArray(60) { (it * 91 + 17).toByte() }.also { it[0] = 0x41 }
                    for (d in listOf(forged, seen.copyOf(), random)) {
                        assertTrue(
                            e.cio.inbox
                                .trySend(d to serverAddr)
                                .isSuccess,
                        )
                    }
                    idleTimeout(c.closed.await())
                    assertEquals(3L, e.cio.queuedTaken, "all three were read before the close")
                } finally {
                    e.client.close()
                    e.server.close()
                }
            }
        }

    /** A Stateless Reset among the queued datagrams ends the connection as reset (RFC 9000 section 10.3.1), not as idle. */
    @Test fun negative_aStatelessResetAmongTheQueuedDatagramsEndsTheConnectionAsReset(): Unit =
        runBlocking {
            withTimeout(30.seconds) {
                val idle = 300.milliseconds
                val e = endpoints(idle)
                try {
                    val (c, s) = connect(e, idle)
                    val token = assertNotNull((s as ConnectionRuntime).core.cids.localToken(0), "the server's reset token")
                    dropToClient = true
                    e.cio.stalled = true
                    val reset = ByteArray(43) { (it * 37 + 11).toByte() }
                    reset[0] = 0x4b
                    token.copyInto(reset, reset.size - 16)
                    assertTrue(
                        e.cio.inbox
                            .trySend(reset to serverAddr)
                            .isSuccess,
                    )
                    assertIs<QuicException.ConnectionLost.StatelessReset>(c.closed.await())
                } finally {
                    e.client.close()
                    e.server.close()
                }
            }
        }

    /**
     * A queue that never runs dry (a flood, here without end) holds the idle close only for one drain budget: the loop
     * takes at most [BatchReceiver.DRAIN_BUDGET] datagrams for it and then decides.
     */
    @Test fun negative_aQueueThatNeverRunsDryDoesNotHoldTheIdleCloseForever(): Unit =
        runBlocking {
            withTimeout(30.seconds) {
                val idle = 300.milliseconds
                val e = endpoints(idle)
                try {
                    val (c, _) = connect(e, idle)
                    var k = 0
                    e.cio.queuedSource = { serverAddr to ByteArray(50) { (it + k++).toByte() }.also { it[0] = 0x42 } }
                    e.cio.stalled = true
                    idleTimeout(c.closed.await())
                    val rounds = e.client.idleDrainRoundsForTest
                    assertTrue(rounds >= 1)
                    assertTrue(
                        e.cio.queuedTaken <= rounds * BatchReceiver.DRAIN_BUDGET,
                        "${e.cio.queuedTaken} datagrams taken in $rounds rounds",
                    )
                } finally {
                    e.cio.queuedSource = null
                    e.client.close()
                    e.server.close()
                }
            }
        }

    /** The budget is per round: a peer packet behind fewer junk datagrams than the budget is reached, one behind more is not. */
    @Test fun negative_aPeerPacketBehindTheDrainBudgetDoesNotKeepTheConnection(): Unit =
        runBlocking {
            for ((junk, kept) in listOf(BatchReceiver.DRAIN_BUDGET - 1 to true, BatchReceiver.DRAIN_BUDGET to false)) {
                withTimeout(30.seconds) {
                    val idle = 400.milliseconds
                    val e = endpoints(idle)
                    try {
                        val (c, s) = connect(e, idle)
                        val down = s.openUni()
                        val (verdict) = verdicts(e, c)
                        val gate = holdDrains(e)
                        val held = heldAtOnce(e, 1)
                        e.cio.stalled = true
                        repeat(junk) { i ->
                            e.net.deliver(serverAddr, clientAddr, ByteArray(40) { (it * 7 + i).toByte() }.also { it[0] = 0x43 })
                        }
                        val packet = captureNext(e, s)
                        down.output.writeByte(9)
                        down.output.flush()
                        queue(e, packet.await()) // behind the junk
                        held.await()
                        gate.complete(Unit)
                        assertEquals(kept, verdict.await(), "$junk junk datagrams ahead")
                        if (kept) {
                            assertEquals(9, c.acceptStream().input.readByte(), "$junk junk datagrams ahead")
                        } else {
                            idleTimeout(c.closed.await())
                        }
                    } finally {
                        e.client.close()
                        e.server.close()
                    }
                }
            }
        }

    /** Connections sharing the endpoint's socket: the one whose peer's packet waits is kept, the other closes as idle. */
    @Test fun negative_onlyTheConnectionWhosePeerSpokeIsKept(): Unit =
        runBlocking {
            withTimeout(30.seconds) {
                val idle = 400.milliseconds
                val e = endpoints(idle)
                try {
                    val (quiet, _) = connect(e, idle)
                    val (spoke, s) = connect(e, idle)
                    val down = s.openUni()
                    val (spokeKept) = verdicts(e, spoke)
                    val gate = holdDrains(e)
                    val bothHeld = heldAtOnce(e, 2)
                    e.cio.stalled = true
                    val packet = captureNext(e, s)
                    down.output.writeByte(3)
                    down.output.flush()
                    queue(e, packet.await()) // the spoken-to connection's datagram waits
                    bothHeld.await() // both deadlines passed; one drain decides both
                    gate.complete(Unit)
                    idleTimeout(quiet.closed.await())
                    assertTrue(spokeKept.await(), "closed: ${runCatching { spoke.closed.getCompleted() }}")
                    assertEquals(3, spoke.acceptStream().input.readByte())
                } finally {
                    e.client.close()
                    e.server.close()
                }
            }
        }

    /**
     * A receive that hands back late (the accelerated socket's wait slice): while the first connection is held for it, the
     * second one's deadline passes too and is held with it; once the receive returns, one drain decides both.
     */
    @Test fun negative_aSecondDeadlineDuringAnOpenDrainIsHeldWithIt(): Unit =
        runBlocking {
            withTimeout(30.seconds) {
                val idle = 400.milliseconds
                val e = endpoints(idle)
                val gate = CompletableDeferred<Unit>()
                try {
                    val (first, _) = connect(e, idle)
                    val (second, s) = connect(e, idle)
                    val down = s.openUni()
                    val bothHeld = heldAtOnce(e, 2)
                    val (secondKept) = verdicts(e, second)
                    e.client.idleHoldLimitForTest = 60.seconds // only the gate ends the first hold, however slow the host
                    e.cio.interruptGate = gate
                    e.cio.stalled = true
                    val packet = captureNext(e, s)
                    down.output.writeByte(5)
                    down.output.flush()
                    queue(e, packet.await())
                    bothHeld.await() // the first deadline's drain is still open when the second one passes
                    assertFalse(first.closed.isCompleted)
                    gate.complete(Unit)
                    idleTimeout(first.closed.await())
                    assertTrue(secondKept.await(), "closed: ${runCatching { second.closed.getCompleted() }}")
                    assertEquals(5, second.acceptStream().input.readByte())
                } finally {
                    gate.complete(Unit)
                    e.client.close()
                    e.server.close()
                }
            }
        }

    /** A receive that never hands back holds an idle close for [EndpointLoop.IDLE_HOLD_LIMIT] at most. */
    @Test fun negative_aReceiveThatNeverHandsBackDoesNotHoldTheIdleCloseForever(): Unit =
        runBlocking {
            withTimeout(30.seconds) {
                val idle = 300.milliseconds
                val e = endpoints(idle)
                val gate = CompletableDeferred<Unit>()
                try {
                    val (c, s) = connect(e, idle)
                    val down = s.openUni()
                    val held = CompletableDeferred<Unit>()
                    e.client.onIdleHeldForTest = { held.complete(Unit) }
                    e.cio.interruptGate = gate
                    e.cio.stalled = true
                    down.output.writeByte(5)
                    down.output.flush()
                    held.await()
                    idleTimeout(c.closed.await()) // the queued packet was never handed over: the limit decides
                    assertEquals(0L, e.cio.queuedTaken)
                } finally {
                    gate.complete(Unit)
                    e.client.close()
                    e.server.close()
                }
            }
        }

    /**
     * The application writes while its connection is held past the idle deadline (RFC 9000 section 10.1: an ack-eliciting
     * packet sent then would restart the timer). Nothing goes out, and the connection still closes as idle.
     */
    @Test fun negative_aWriteDuringAnOpenHoldStillClosesAsIdle(): Unit =
        runBlocking {
            withTimeout(30.seconds) {
                val idle = 300.milliseconds
                val e = endpoints(idle)
                val gate = CompletableDeferred<Unit>() // never completed: the hold lasts until its limit
                try {
                    val (c, _) = connect(e, idle)
                    val up = c.openUni()
                    val held = CompletableDeferred<Int>()
                    e.client.onIdleHeldForTest = { held.complete(clientSends) }
                    dropToClient = true
                    e.cio.interruptGate = gate
                    e.cio.stalled = true
                    val sentBefore = held.await()
                    runCatching {
                        up.output.writeByte(2)
                        up.output.flush()
                    }
                    idleTimeout(c.closed.await())
                    assertEquals(sentBefore, clientSends, "datagrams sent after the idle deadline")
                } finally {
                    gate.complete(Unit)
                    e.client.close()
                    e.server.close()
                }
            }
        }

    /** A receiver that joins while a hold is open (a migration path's socket) owes the open round too. */
    @Test fun aReceiverJoiningDuringAnOpenHoldDrainsForIt(): Unit =
        runBlocking {
            withTimeout(30.seconds) {
                val idle = 300.milliseconds
                val e = endpoints(idle)
                val gate = CompletableDeferred<Unit>()
                val extra = e.net.open(InetSocketAddress("10.0.0.1", 1112))
                try {
                    connect(e, idle)
                    val held = CompletableDeferred<Unit>()
                    e.client.onIdleHeldForTest = { held.complete(Unit) }
                    e.cio.interruptGate = gate
                    e.cio.stalled = true
                    held.await()
                    kotlinx.coroutines.withContext(e.client.dispatcher) {
                        val r = BatchReceiver(extra, e.client.clock)
                        e.client.registerReceiver(r)
                        try {
                            assertEquals(e.client.drainRound, r.drainRequested, "asked for the open round")
                            assertTrue(r.drainServed < e.client.drainRound, "and not counted as done")
                        } finally {
                            e.client.unregisterReceiver(r)
                        }
                    }
                } finally {
                    gate.complete(Unit)
                    extra.close()
                    e.client.close()
                    e.server.close()
                }
            }
        }

    /** Closing the endpoint while a connection is held for a drain: the close completes and the connection ends with it. */
    @Test fun negative_closingTheEndpointDuringAnOpenDrainEndsTheHeldConnection(): Unit =
        runBlocking {
            withTimeout(30.seconds) {
                val idle = 300.milliseconds
                val e = endpoints(idle)
                val gate = CompletableDeferred<Unit>()
                try {
                    val (c, _) = connect(e, idle)
                    val held = CompletableDeferred<Unit>()
                    e.client.onIdleHeldForTest = { held.complete(Unit) }
                    e.cio.interruptGate = gate
                    e.cio.stalled = true
                    held.await()
                    e.client.closeAndJoin()
                    val why = c.closed.await()
                    assertFalse(why is QuicException.ConnectionLost.Timeout, "ended by the close, not as idle: $why")
                    assertTrue(e.client.writersEndedForTest, "the receiver, interrupted or not, and the timer joined the close")
                    assertEquals(0, e.client.heldForDrainForTest)
                } finally {
                    gate.complete(Unit)
                    e.client.close()
                    e.server.close()
                }
            }
        }
}
