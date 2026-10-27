// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(kotlinx.cinterop.ExperimentalForeignApi::class)

package io.kuicksilver.tls

import platform.posix.time

// time_t is Int on some native targets and Long on others, so the conversion is redundant only on some of them
@Suppress("REDUNDANT_CALL_OF_CONVERSION_METHOD")
internal actual fun nowSeconds(): Long = time(null).toLong()
