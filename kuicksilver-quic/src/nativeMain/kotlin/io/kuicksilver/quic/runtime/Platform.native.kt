// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.runtime

import kotlin.experimental.ExperimentalNativeApi

internal actual val portableServerSupported: Boolean = false

@OptIn(ExperimentalNativeApi::class)
internal actual val millisecondPollWaits: Boolean = Platform.osFamily != OsFamily.WINDOWS
