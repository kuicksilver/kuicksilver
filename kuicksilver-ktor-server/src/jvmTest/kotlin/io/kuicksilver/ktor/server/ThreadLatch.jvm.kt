// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.server

import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import kotlin.time.Duration

internal actual class ThreadLatch actual constructor() {
    private val latch = CountDownLatch(1)

    actual fun open() = latch.countDown()

    actual fun await(timeout: Duration): Boolean = latch.await(timeout.inWholeMilliseconds, TimeUnit.MILLISECONDS)
}
