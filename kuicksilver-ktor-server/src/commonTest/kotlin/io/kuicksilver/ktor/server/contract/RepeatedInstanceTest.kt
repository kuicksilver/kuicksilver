// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.server.contract

import kotlin.test.Test

/**
 * The Kotlin/Native test runner keeps one instance per test case and reuses it under `--ktest_repeat`; JUnit does not.
 * This runs a suite test twice on one instance on every target, the way the Native runner does, so state a test leaves
 * on the instance (`enableSsl`, the resolved ports) cannot break its next run: before the reset in
 * [EngineTestBase.beforeTest] the second HTTP/3 run dialed the closed TLS port of the first until the handshake timeout.
 */
class RepeatedInstanceTest {
    private fun <T : EngineTestBase<*, *>> T.runTwice(
        load: T.() -> Unit,
        test: T.() -> Unit,
    ) {
        repeat(2) {
            load()
            beforeTest()
            try {
                test()
            } finally {
                afterTest()
            }
        }
    }

    @Test
    fun h3ResponseSentCalledOnceTwiceOnOneInstance() =
        KuicksilverH3HttpServerCommonTest().runTwice({ load() }) { testResponseSentCalledOnce() }

    @Test
    fun h1ResponseSentCalledOnceTwiceOnOneInstance() =
        KuicksilverH1HttpServerCommonTest().runTwice({ load() }) { testResponseSentCalledOnce() }
}
