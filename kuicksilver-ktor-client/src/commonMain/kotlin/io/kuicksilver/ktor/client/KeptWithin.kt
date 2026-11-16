// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.client

import kotlinx.coroutines.withTimeoutOrNull
import kotlin.time.Duration

/**
 * [block]'s result, or null when [timeout] ran out first or the block gave null. Unlike `withTimeoutOrNull` a result the
 * block returned is never dropped: the timeout fires on another thread, and when it lands after the block returned but
 * before the timeout's scope completed, `withTimeoutOrNull` gives null for an answer that came (the lookups and script
 * runs of the platform code use this; `completedWithin` in kuicksilver-tls is the same for a block that never gives null).
 * The result is set as the block returns, before [afterForTest] (a test hook that holds the block there).
 */
internal suspend fun <T : Any> keptWithin(
    timeout: Duration,
    afterForTest: (suspend () -> Unit)? = null,
    block: suspend () -> T?,
): T? {
    var kept: T? = null
    withTimeoutOrNull(timeout) {
        kept = block()
        afterForTest?.invoke()
    }
    return kept
}
