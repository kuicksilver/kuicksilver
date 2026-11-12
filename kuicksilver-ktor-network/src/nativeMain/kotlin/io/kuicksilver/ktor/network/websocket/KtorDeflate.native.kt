// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.network.websocket

import io.ktor.websocket.WebSocketExtension

/** Ktor has no `WebSocketDeflateExtension` on Kotlin/Native. */
internal actual fun isKtorDeflateExtension(extension: WebSocketExtension<*>): Boolean = false
