// Copyright 2014-2025 JetBrains s.r.o and contributors. Use of this source code is governed by the Apache 2.0 license.
// Modifications Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
// Vendored from Ktor 3.6.0 ktor-client/ktor-client-tests/common/test/io/ktor/client/tests/PostTest.kt, adapted to the Kuicksilver engine.
package io.kuicksilver.ktor.client.contract

import io.ktor.client.*
import io.ktor.client.call.*
import io.ktor.client.plugins.*
import io.ktor.client.request.*
import io.ktor.http.content.*
import io.ktor.utils.io.*
import kotlinx.coroutines.delay
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.time.Duration.Companion.minutes

class PostTest : ClientLoader() {
    @Test
    fun testPostString() =
        clientTests(except("Js")) {
            test { client ->
                client.postHelper(makeString(777))
            }
        }

    @Test
    fun testHugePost() =
        clientTests(except("Js", "Darwin", "CIO", "Curl", "DarwinLegacy", "WinHttp")) {
            test { client ->
                client.postHelper(makeString(2 * 1024 * 1024))
            }
        }

    @Test
    fun testWithPause() =
        clientTests(except("Js", "Darwin", "CIO", "DarwinLegacy")) {
            config {
                install(HttpTimeout) {
                    socketTimeoutMillis = 1.minutes.inWholeMilliseconds
                }
            }
            test { client ->
                val content = makeString(16 * 1024)

                val response =
                    client
                        .post("$TEST_SERVER/content/echo") {
                            setBody(
                                object : OutgoingContent.WriteChannelContent() {
                                    override suspend fun writeTo(channel: ByteWriteChannel) {
                                        channel.writeStringUtf8(content)
                                        delay(1000)
                                        channel.writeStringUtf8(content)
                                        channel.flushAndClose()
                                    }
                                },
                            )
                        }.body<String>()

                assertEquals(content + content, response)
            }
        }

    private suspend fun HttpClient.postHelper(text: String) {
        val response =
            post("$TEST_SERVER/content/echo") {
                setBody(text)
            }.body<String>()
        assertEquals(text, response)
    }
}
