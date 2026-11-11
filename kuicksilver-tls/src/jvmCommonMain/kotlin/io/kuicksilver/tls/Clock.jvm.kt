// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.tls

internal actual fun nowSeconds(): Long = System.currentTimeMillis() / 1000

internal actual fun sleepMillis(millis: Int): Unit = Thread.sleep(millis.toLong())
