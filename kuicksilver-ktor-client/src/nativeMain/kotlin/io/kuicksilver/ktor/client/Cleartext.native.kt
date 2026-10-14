// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.client

// iOS App Transport Security governs NSURLSession, not BSD sockets; docs/guide/tls.md says so
internal actual fun platformCleartextPermitted(host: String): Boolean = true
