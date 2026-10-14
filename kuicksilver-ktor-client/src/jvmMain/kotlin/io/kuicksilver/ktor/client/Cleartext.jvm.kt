// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.client

internal actual fun platformCleartextPermitted(host: String): Boolean = true // no platform policy on a desktop or server JVM
