// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.client

import kotlinx.io.IOException
import kotlinx.io.files.Path
import java.io.File

// java.io only: java.nio.file (and File.toPath) is missing below Android API 26. rename(2) replaces atomically on
// Linux/Android; the JVM never gets here (kotlinx-io moves through java.nio.file there).
internal actual fun renameReplacing(
    source: Path,
    destination: Path,
) {
    if (!File(source.toString()).renameTo(File(destination.toString()))) throw IOException("Cannot rename $source to $destination")
}
