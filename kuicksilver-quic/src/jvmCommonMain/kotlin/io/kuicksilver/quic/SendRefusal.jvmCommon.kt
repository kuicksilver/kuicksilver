// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic

private val emsgsizeText: String? by lazy { localizedEmsgsizeText() }

internal actual fun systemEmsgsizeText(): String? = emsgsizeText

/** The JDK reports a refusal as a `SocketException` with a text only ([namesEmsgsize] reads it). */
internal actual fun isPlatformEmsgsize(e: Throwable): Boolean = false
