// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.network.websocket

import io.ktor.websocket.WebSocketDeflateExtension
import io.ktor.websocket.WebSocketExtension

internal actual fun isKtorDeflateExtension(extension: WebSocketExtension<*>): Boolean = extension is WebSocketDeflateExtension
