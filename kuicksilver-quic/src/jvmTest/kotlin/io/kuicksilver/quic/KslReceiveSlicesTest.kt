// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.async
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import java.util.Collections
import kotlin.test.Test
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.seconds

/** The accelerated receive returns its blocking thread between 100 ms slices, so idle sockets do not pin Dispatchers.IO; runs everywhere, the socket is simulated. */
class KslReceiveSlicesTest {
    @OptIn(ExperimentalCoroutinesApi::class)
    @Test
    fun idleReceiversShareOneBlockingThread() =
        runBlocking {
            withTimeout(30.seconds) {
                // fewer threads than sockets: the case of 80 endpoints on a 64-thread pool
                val oneThread = Dispatchers.IO.limitedParallelism(1)
                val log = Collections.synchronizedList(ArrayList<Int>())

                fun receiver(id: Int) =
                    async {
                        var slices = 0
                        KslDatagramIo.receiveInSlices(oneThread, { false }) {
                            Thread.sleep(5)
                            log += id
                            if (++slices ==
                                10
                            ) {
                                1
                            } else {
                                0
                            }
                        }
                    }
                val a = receiver(1)
                val b = receiver(2)
                a.await()
                b.await()
                val firstB = log.indexOf(2)
                val lastA = log.lastIndexOf(1)
                assertTrue(firstB in 0 until lastA, "the second socket got a slice before the first one received: $log")
            }
        }
}
