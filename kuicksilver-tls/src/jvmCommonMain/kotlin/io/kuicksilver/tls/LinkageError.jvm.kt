// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.tls

internal actual fun isLinkageError(e: Throwable): Boolean = e is LinkageError
