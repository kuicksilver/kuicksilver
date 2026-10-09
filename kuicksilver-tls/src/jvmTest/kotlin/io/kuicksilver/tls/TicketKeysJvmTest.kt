// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.tls

import io.kuicksilver.native.KslLoader
import java.util.concurrent.CountDownLatch
import kotlin.concurrent.thread
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals

/** The process-wide default ticket keys are created once even when many servers start at the same moment. */
class TicketKeysJvmTest {
    @BeforeTest fun load() {
        KslLoader.ensureLoaded()
    }

    @Test fun concurrentFirstUseAgreesOnOneKey() {
        repeat(20) {
            DefaultTicketKeys.resetForTest()
            val start = CountDownLatch(1)
            val seen =
                java.util.concurrent.ConcurrentHashMap
                    .newKeySet<String>()
            val threads =
                List(16) {
                    thread {
                        start.await()
                        seen +=
                            DefaultTicketKeys.current(SessionTicketConfig.Default).first().joinToString(",")
                    }
                }
            start.countDown()
            threads.forEach { it.join() }
            assertEquals(1, seen.size, "servers started together encrypt with one current key")
        }
    }
}
