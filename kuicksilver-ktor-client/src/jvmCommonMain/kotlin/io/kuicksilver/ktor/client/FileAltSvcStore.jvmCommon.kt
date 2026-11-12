// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.client

import io.ktor.util.date.getTimeMillis
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import kotlinx.io.IOException
import kotlinx.io.files.Path
import java.io.File

/**
 * A [FileAltSvcStore] kept in [file]: the same store as `FileAltSvcStore(path)`, for code that holds a `java.io.File`, as an
 * Android app does (`FileAltSvcStore(File(context.filesDir, "altsvc.tsv"))`). Works on every Android version the library
 * supports, API 24 and 25 included: nothing on this path uses `java.nio.file` or `File.toPath()`, which arrived in API 26.
 *
 * @param file the store file; it need not exist yet, and an unreadable file starts an empty store.
 * @param clock the current time in epoch milliseconds, used to drop expired records on load.
 */
@ExperimentalKuicksilverApi
public fun FileAltSvcStore(
    file: File,
    clock: () -> Long = { getTimeMillis() },
): FileAltSvcStore = FileAltSvcStore(Path(file.path), clock)

// java.io only: java.nio.file (and File.toPath) is missing below Android API 26. rename(2) replaces atomically on
// Linux/Android; the JVM never gets here (kotlinx-io moves through java.nio.file there).
internal actual fun renameReplacing(
    source: Path,
    destination: Path,
) {
    if (!File(source.toString()).renameTo(File(destination.toString()))) throw IOException("Cannot rename $source to $destination")
}
