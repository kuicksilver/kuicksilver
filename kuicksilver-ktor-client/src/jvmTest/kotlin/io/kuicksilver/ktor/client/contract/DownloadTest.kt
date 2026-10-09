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
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.seconds

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
        clientTests(timeout = 10.seconds) {
            test { client ->
                val size = 4 * 1024 * 1024
                client.prepareGet("$TEST_SERVER/download?size=$size").body<ByteReadChannel, Unit> { channel ->
                    var received = 0
                    val buffer = ByteArray(8 * 1024)
                    while (true) {
                        val readBytes = channel.readAvailable(buffer)
                        if (readBytes == -1) break
                        received += readBytes
                        delay(1.milliseconds)
                    }
                    assertEquals(size, received)
                }
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
