// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.network

import io.ktor.network.selector.SelectorManager
import io.ktor.network.sockets.InetSocketAddress
import io.ktor.network.sockets.Socket
import io.ktor.network.sockets.openReadChannel
import io.ktor.utils.io.discard
import io.kuicksilver.native.KslLoader
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.IO
import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.seconds

/**
 * Closing many sockets of one selector at once runs the release rounds ([releaseClosedChannels]) one at a time, never
 * more rounds than requests, and loses none: once every peer read its socket's end and the rounds are over, no closed
 * socket is still registered with the selector (its descriptor held), and every waker a round opened was closed.
 */
class ReleaseCoalescingTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    @Test fun negative_manyClosesRunOneRoundAtATime(): Unit =
        runBlocking {
            val selector = SelectorManager(Dispatchers.IO)
            val clientSelector = SelectorManager(Dispatchers.IO) // the clients' alone: its rounds are theirs
            try {
                withTimeout(60.seconds) {
                    val listener = bindTcp(selector, "127.0.0.1", 0)
                    val port = (listener.localAddress as InetSocketAddress).port
                    val pairs = ArrayList<Pair<KslNioSocket, Socket>>()
                    repeat(COUNT) {
                        val client = connectTcp(clientSelector, InetSocketAddress("127.0.0.1", port)) as KslNioSocket
                        pairs += client to listener.accept()
                    }
                    for ((client, _) in pairs) client.close()
                    for ((_, peer) in pairs) peer.openReadChannel().discard() // each client sent its end
                    val state = assertNotNull(clientSelector.releaseStateForTest())
                    // the last round may still be finishing its selection: bounded, it ends within its own timeout
                    awaitCondition { state.inFlight.get() == 0 && pairs.none { it.first.isRegisteredForTest } }
                    assertTrue(state.maxInFlight.get() <= 1, "${state.maxInFlight.get()} release rounds ran at once")
                    val rounds = state.rounds.get()
                    val requests = state.requests.get()
                    assertTrue(rounds in 1..requests, "$rounds rounds for $requests requests")
                    assertEquals(0, pairs.count { it.first.isRegisteredForTest }, "closed sockets still registered (held)")
                    val leftOpen = state.wakersOpened.get() - state.wakersClosed.get()
                    assertTrue(leftOpen <= 1, "$leftOpen wakers left open")
                    for ((_, peer) in pairs) peer.close()
                    listener.close()
                }
            } finally {
                selector.close()
                clientSelector.close()
            }
        }

    /** Waits for [done], looking every 10 ms, at most 10 s. */
    private suspend fun awaitCondition(done: () -> Boolean) {
        withTimeout(10.seconds) { while (!done()) delay(10.milliseconds) }
    }

    private companion object {
        const val COUNT = 100
    }
}
