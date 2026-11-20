// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.network

import io.ktor.network.selector.SelectorManager
import io.ktor.network.sockets.InetSocketAddress
import io.ktor.network.sockets.openReadChannel
import io.ktor.network.sockets.openWriteChannel
import io.ktor.utils.io.readAvailable
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.IO
import kotlinx.coroutines.async
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import kotlinx.coroutines.withTimeoutOrNull
import kotlin.test.Test
import kotlin.test.assertNotNull
import kotlin.time.Duration.Companion.seconds

/**
 * A socket closed just before its selector, while its close is still under way (its read loop waiting in the selector,
 * its descriptor not yet released), is released all the same, and so is its listener: an application or a server that
 * closes its sockets and then its selector at once leaks neither.
 */
class SelectorCloseOrderTest {
    @Test fun aSocketClosedAsItsSelectorClosesIsReleased(): Unit =
        runBlocking {
            val selector = SelectorManager(Dispatchers.IO)
            val listener = bindTcp(selector, "127.0.0.1", 0)
            val accepted = async { listener.accept() }
            val client = connectTcp(selector, InetSocketAddress("127.0.0.1", (listener.localAddress as InetSocketAddress).port))
            val s = withTimeout(10.seconds) { accepted.await() }
            // the read loop waits in the selector for bytes that never come; the write loop is attached
            val reading = launch(start = CoroutineStart.UNDISPATCHED) { runCatching { s.openReadChannel().readAvailable(ByteArray(16)) } }
            s.openWriteChannel(autoFlush = true)
            s.close()
            listener.close()
            selector.close() // at once: the socket's close runs after this
            // events, not waits: the jobs complete once everything under them ended; the bound only turns a hang into a failure
            assertNotNull(withTimeoutOrNull(10.seconds) { s.socketContext.join() }, "the socket was never released")
            assertNotNull(withTimeoutOrNull(10.seconds) { listener.socketContext.join() }, "the listener was never released")
            reading.cancel()
            client.close()
        }
}
