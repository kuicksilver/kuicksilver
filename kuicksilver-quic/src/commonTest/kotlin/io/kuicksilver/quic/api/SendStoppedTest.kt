// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.api

import io.ktor.utils.io.readAvailable
import io.ktor.utils.io.writeFully
import io.kuicksilver.annotations.InternalKuicksilverApi
import io.kuicksilver.native.KslLoader
import io.kuicksilver.quic.QuicException
import io.kuicksilver.quic.awaitSendStopped
import kotlinx.coroutines.async
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import kotlinx.coroutines.withTimeoutOrNull
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.time.Duration.Companion.seconds

/**
 * `awaitSendStopped` returns the code of the peer's STOP_SENDING, and ends once its stream can no longer be stopped: a
 * watcher never outlives its stream or its connection (found by the 0-RTT runtime invariant test, where watchers waited
 * forever after the connection ended).
 */
@OptIn(InternalKuicksilverApi::class)
class SendStoppedTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    @Test fun returnsThePeersCode(): Unit =
        runBlocking {
            ApiPair.open().use { p ->
                withTimeout(10.seconds) {
                    val (c, s) = p.connect()
                    val st = c.openBidi()
                    st.output.writeFully(ByteArray(10))
                    st.output.flush()
                    val watcher = async { st.awaitSendStopped() }
                    s.acceptStream().stopSending(42)
                    assertEquals(42L, watcher.await())
                    c.close()
                }
            }
        }

    @Test fun negative_watcherEndsWithTheConnection(): Unit =
        runBlocking {
            ApiPair.open().use { p ->
                withTimeout(10.seconds) {
                    val (c, s) = p.connect()
                    val st = c.openBidi()
                    st.output.writeFully(ByteArray(10))
                    st.output.flush()
                    s.acceptStream()
                    val watcher = async { runCatching { st.awaitSendStopped() }.exceptionOrNull() }
                    c.close(7, "done")
                    val e = withTimeoutOrNull(5.seconds) { watcher.await() }
                    assertIs<QuicException.ConnectionLost.ApplicationClosed>(e, "the watcher ended with the connection's reason")
                }
            }
        }

    @Test fun negative_watcherEndsWithItsStream(): Unit =
        runBlocking {
            ApiPair.open().use { p ->
                withTimeout(10.seconds) {
                    val (c, s) = p.connect()
                    val st = c.openBidi()
                    val watcher = async { runCatching { st.awaitSendStopped() }.exceptionOrNull() }
                    st.output.writeFully(ByteArray(10))
                    st.output.flushAndClose()
                    val ss = s.acceptStream()
                    ss.input.readExactly(10)
                    ss.output.flushAndClose()
                    val b = ByteArray(16)
                    while (st.input.readAvailable(b, 0, b.size) >= 0) { /* to the end */ }
                    // both halves are done: no STOP_SENDING can stop this stream any more, and the watcher learns it
                    val e = withTimeoutOrNull(5.seconds) { watcher.await() }
                    assertIs<IllegalStateException>(e, "the watcher ended with its stream")
                    // and it does not wait for the connection's end either
                    c.close()
                }
            }
        }
}
