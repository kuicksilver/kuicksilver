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
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import kotlinx.coroutines.yield
import java.lang.management.ManagementFactory
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.seconds

/**
 * Closing many sockets of one selector at once costs a few release rounds ([releaseClosedChannels]), not a waker (a pipe,
 * two descriptors) per close: the rounds are coalesced per selector. Once everything is closed, the process holds no more
 * descriptors than before the sockets were opened, give or take the one waker an idle selector may keep.
 */
class ReleaseCoalescingTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    @Test fun negative_manyClosesCostAFewRounds(): Unit =
        runBlocking {
            val selector = SelectorManager(Dispatchers.IO)
            val clientSelector = SelectorManager(Dispatchers.IO)
            try {
                withTimeout(60.seconds) {
                    val listener = bindTcp(selector, "127.0.0.1", 0)
                    val port = (listener.localAddress as InetSocketAddress).port
                    val before = openDescriptors()
                    val pairs = ArrayList<Pair<Socket, Socket>>()
                    repeat(COUNT) {
                        val client = connectTcp(clientSelector, InetSocketAddress("127.0.0.1", port))
                        pairs += client to listener.accept()
                    }
                    val wakers = releaseWakersOpened.get()
                    for ((client, _) in pairs) client.close() // two release requests each
                    // every client sent its end once its peer read it
                    for ((_, peer) in pairs) peer.openReadChannel().discard()
                    val opened = releaseWakersOpened.get() - wakers
                    assertTrue(opened <= COUNT / 10, "$opened wakers for $COUNT closes: the release rounds are not coalesced")
                    for ((_, peer) in pairs) peer.close()
                    listener.close()
                    // the peers' and listener's closes settle on their own selector's next selections
                    var after = openDescriptors()
                    while (after > before + SLACK) {
                        yield()
                        after = openDescriptors()
                    }
                }
            } finally {
                selector.close()
                clientSelector.close()
            }
        }

    private fun openDescriptors(): Long =
        (ManagementFactory.getOperatingSystemMXBean() as com.sun.management.UnixOperatingSystemMXBean).openFileDescriptorCount

    private companion object {
        const val COUNT = 100

        /** A waker an idle selector may keep, the peers' selector's own deferred closes. */
        const val SLACK = 6
    }
}
