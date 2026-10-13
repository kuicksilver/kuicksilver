// Copyright 2014-2025 JetBrains s.r.o and contributors. Use of this source code is governed by the Apache 2.0 license.
// Modifications Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
// Vendored from Ktor 3.6.0 ktor-client/ktor-client-tests/common/test/io/ktor/client/tests/DownloadTest.kt, adapted to the Kuicksilver engine.
package io.kuicksilver.ktor.client.contract

import io.ktor.client.call.*
import io.ktor.client.request.*
import io.ktor.utils.io.*
import kotlinx.coroutines.delay
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlin.time.Duration
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.minutes
import kotlin.time.Duration.Companion.seconds
import kotlin.time.TimeSource
import kotlin.time.measureTime

class DownloadTest : ClientLoader() {
    @Test
    fun testLocalhostEcho() =
        clientTests {
            val text = "Hello, world"
            test { client ->
                val response =
                    client
                        .post("$TEST_SERVER/echo") {
                            setBody(text)
                        }.body<String>()

                assertEquals(text, response)
            }
        }

    @Test
    fun testDownloadWithSlowConsumer() =
        // Kuicksilver: Ktor's 10 s bound the whole test, the consumer's own delay(1 ms) after each of its ~512 reads included,
        // so the test measured the host's timer rather than the engine: a Windows timer tick is >= 15.6 ms on the JVM and
        // 56-92 ms for Kotlin/Native (Windows 11 VM), coalesced timers on a loaded macOS host took up to ~46 ms, 8-47 s in all,
        // while the transfer itself takes < 1 s. Sampling the timer before the test does not help (it read 1.8 ms where the
        // test's own delays then averaged ~35 ms), so the 10 s now bound the download minus the time the consumer actually
        // spent in its delays, measured as they happen; the harness timeout only stops a hang.
        clientTests(timeout = 2.minutes) {
            test { client ->
                val size = 4 * 1024 * 1024
                val start = TimeSource.Monotonic.markNow()
                var slept = Duration.ZERO
                client.prepareGet("$TEST_SERVER/download?size=$size").body<ByteReadChannel, Unit> { channel ->
                    var received = 0
                    val buffer = ByteArray(8 * 1024)
                    while (true) {
                        val readBytes = channel.readAvailable(buffer)
                        if (readBytes == -1) break
                        received += readBytes
                        slept += measureTime { delay(1.milliseconds) }
                    }
                    assertEquals(size, received)
                }
                val transfer = start.elapsedNow() - slept
                assertTrue(transfer < 10.seconds, "the download took $transfer besides the consumer's $slept of delays")
            }
        }

    @Test
    fun testDownload8175() =
        clientTests {
            test { client ->
                repeat(100) {
                    val url = "$TEST_SERVER/download/8175"
                    client.get(url).body<String>()
                }
            }
        }
}
