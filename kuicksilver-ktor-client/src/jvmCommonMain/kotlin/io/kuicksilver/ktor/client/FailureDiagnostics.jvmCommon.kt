// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.client

internal actual fun dropStackTrace(t: Throwable) {
    t.stackTrace = emptyArray()
}
