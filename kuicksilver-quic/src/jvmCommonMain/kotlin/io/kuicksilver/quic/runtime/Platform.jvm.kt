// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.runtime

internal actual val portableServerSupported: Boolean = true

internal actual val millisecondPollWaits: Boolean =
    !System
        .getProperty("os.name")
        .orEmpty()
        .lowercase()
        .contains("windows")
