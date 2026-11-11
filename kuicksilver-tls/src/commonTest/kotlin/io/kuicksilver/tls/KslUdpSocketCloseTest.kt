// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.tls

import io.kuicksilver.native.KslLoader
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.TimeSource

/** [KslUdpSocket.close] while another thread is inside a native call of the socket. */
class KslUdpSocketCloseTest {
    @BeforeTest fun load() {
        KslLoader.ensureLoaded()
    }

    /**
     * The close waits for a caller still inside (here one that stays 300 ms) without spinning on its core: it looked at the
     * count in a hot loop, millions of times over such a wait, on what is usually an endpoint's loop thread.
     */
    @Test fun closeWaitsForACallerInsideWithoutSpinning() {
        if (!KslUdpSocket.supported) return
        val socket = KslUdpSocket.open(KslUdpSocket.encodeAddress(byteArrayOf(127, 0, 0, 1), 0), 0)
        assertTrue(socket.enterForTest())
        runBlocking {
            val leaving =
                launch(Dispatchers.Default) {
                    delay(300)
                    socket.leaveForTest()
                }
            val started = TimeSource.Monotonic.markNow()
            socket.close()
            assertTrue(started.elapsedNow() >= 250.milliseconds, "the close did not wait for the caller inside")
            leaving.join()
        }
        // about one look per millisecond once it sleeps; a spin made millions
        assertTrue(socket.closeLooksForTest in 1..2_000, "the close looked ${socket.closeLooksForTest} times")
    }
}
