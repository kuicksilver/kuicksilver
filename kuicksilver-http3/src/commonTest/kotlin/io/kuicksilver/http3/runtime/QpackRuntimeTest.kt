// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.http3.runtime

import io.kuicksilver.http3.Http3Settings
import kotlinx.coroutines.test.runTest
import kotlin.test.Test
import kotlin.test.assertEquals

class QpackRuntimeTest {
    private val fields = listOf(":method" to "GET", "user-agent" to "kuicksilver-test/1.0 (dynamic table)")

    /**
     * The encoder stream's credit (RFC 9204 section 2.1.3) costs a hop onto the transport's loop: it is asked only when the
     * peer's table capacity allows an insert at all, so a static-only connection (the default) never asks.
     */
    @Test fun encoderCreditIsAskedOnlyWhenAnInsertIsPossible() =
        runTest {
            var asked = 0
            val q =
                QpackRuntime(Http3Settings.Default, {}, {}) {
                    asked++
                    Long.MAX_VALUE
                }
            repeat(3) { q.encode(0, fields) }
            assertEquals(0, asked, "static only: no credit asked")
            q.onPeerSettings(4096, 16)
            q.encode(4, fields)
            assertEquals(1, asked)
        }
}
