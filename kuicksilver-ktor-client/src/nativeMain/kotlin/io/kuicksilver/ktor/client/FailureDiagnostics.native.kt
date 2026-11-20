// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.client

/** Kotlin/Native keeps the stack a Throwable captured when it was made: nothing to drop. */
internal actual fun dropStackTrace(t: Throwable) {}
