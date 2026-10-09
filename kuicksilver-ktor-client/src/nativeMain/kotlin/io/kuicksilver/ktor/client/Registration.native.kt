// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.client

import io.ktor.client.engine.engines
import io.ktor.utils.io.InternalAPI

/** Registers the engine for `HttpClient()` on Kotlin/Native, as Ktor's own engines do (`@InternalAPI engines`, docs/ktor-internal-api.md). */
@Suppress("DEPRECATION")
@OptIn(ExperimentalStdlibApi::class, InternalAPI::class)
@EagerInitialization
private val initHook = engines.append(Kuicksilver)
