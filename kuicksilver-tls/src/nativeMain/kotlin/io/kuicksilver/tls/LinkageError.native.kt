// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.tls

// Kotlin/Native links ksl statically: a call cannot be missing at run time
internal actual fun isLinkageError(e: Throwable): Boolean = false
