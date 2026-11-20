// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.client

internal actual fun dropStackTrace(t: Throwable) {
    t.stackTrace = emptyArray()
}

/** [e]'s own monitor: the one `Throwable.addSuppressed` and `getSuppressed` synchronize on. */
internal actual fun <T> withCarrierLock(
    e: Throwable,
    block: () -> T,
): T = synchronized(e) { block() }
