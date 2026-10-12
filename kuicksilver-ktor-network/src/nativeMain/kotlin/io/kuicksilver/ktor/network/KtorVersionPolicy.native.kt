// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.network

import kotlin.reflect.KClass

/** Kotlin/Native links the Ktor klibs the binary was built with: a mismatch fails the link, there is nothing to read here. */
internal actual fun ktorArtifactVersion(anchor: KClass<*>): String? = null

internal actual fun versionCheckDisabled(): Boolean = false
