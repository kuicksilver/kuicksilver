// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic

/** Standard error: Windows has no system logger every application uses. */
internal actual fun platformLogger(minLevel: LogLevel): KuicksilverLogger = KuicksilverLogger.stderr(minLevel)
