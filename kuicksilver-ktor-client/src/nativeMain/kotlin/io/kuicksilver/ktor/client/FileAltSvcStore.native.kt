// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.client

import kotlinx.io.files.Path

// kotlinx-io moves atomically on every native target; nothing else to fall back to.
internal actual fun renameReplacing(
    source: Path,
    destination: Path,
): Unit = throw UnsupportedOperationException("Atomic move not supported: $source -> $destination")
