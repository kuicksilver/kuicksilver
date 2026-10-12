// Copyright 2014-2025 JetBrains s.r.o and contributors. Use of this source code is governed by the Apache 2.0 license.
// Modifications Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
// Vendored from Ktor 3.6.0 ktor-client/ktor-client-tests/common/test/io/ktor/client/tests/UploadTest.kt, adapted to the Kuicksilver engine.
package io.kuicksilver.ktor.client.contract

import io.ktor.client.call.*
import io.ktor.client.request.*
import io.ktor.http.*
import io.ktor.http.content.*
import kotlin.test.Test
import kotlin.test.assertEquals

class UploadTest : ClientLoader() {
    @Test
    fun testUploadWithByteArrayContent() =
        clientTests(except("Android", "Curl", "Darwin", "DarwinLegacy")) {
            test { client ->
                val result =
                    client
                        .post("$TEST_SERVER/upload/content") {
                            setBody(ByteArrayContent(ByteArray(1024)))
                        }.body<String>()

                assertEquals("EMPTY", result)
            }
        }

    @Test
    fun testUploadWithEmptyContentType() =
        clientTests {
            test { client ->
                val result =
                    client
                        .post("$TEST_SERVER/upload/content") {
                            setBody(ByteArrayContent(ByteArray(1024), ContentType("", "")))
                        }.body<String>()

                assertEquals("/", result)
            }
        }
}
