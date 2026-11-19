// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.tls

import java.util.concurrent.locks.ReentrantLock

internal actual class BlockingLock actual constructor() {
    private val l = ReentrantLock()

    actual fun lock(): Unit = l.lock()

    actual fun unlock(): Unit = l.unlock()
}
