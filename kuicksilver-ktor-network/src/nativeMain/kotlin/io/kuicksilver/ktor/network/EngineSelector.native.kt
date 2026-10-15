// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.network

import io.ktor.network.selector.SelectorManager

/** Kotlin/Native's selector closes a socket's descriptor itself when the socket closes (`EngineSelectorTest`). */
internal actual fun keepSelecting(selector: SelectorManager) {}
