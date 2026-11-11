// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(InternalKuicksilverApi::class)

package io.kuicksilver.quic.qlog

import android.content.Context
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.annotations.InternalKuicksilverApi
import io.kuicksilver.tls.checkPrivateDirectory
import java.io.File

/**
 * Android: a [DirectoryQlogSink] writing into the directory [name] inside the app's cache directory (`Context.cacheDir`),
 * which only the app can read, is left out of Auto Backup, and is the first place the system reclaims when storage runs
 * low. The directory is created now, owner-only (0700), and checked as [DirectoryQlogSink] checks it; read the traces with
 * `adb shell run-as <package> ls cache/<name>` (debuggable builds) or from the app. Works in release builds too: a trace holds
 * no keys. Below API 26 (no `java.nio.file`, so the directory cannot be checked) it throws [IllegalArgumentException], as
 * [DirectoryQlogSink] refuses there.
 *
 * @param name one path component; default `kuicksilver-qlog`.
 * @throws IllegalArgumentException when [name] is not one path component, the directory cannot be created, or it fails the
 *   checks (a symbolic link, not a directory, owned by another user, writable by others).
 */
@ExperimentalKuicksilverApi
public fun qlogDirectory(
    context: Context,
    name: String = "kuicksilver-qlog",
): DirectoryQlogSink = qlogDirectoryIn(context.cacheDir, name)

/** [qlogDirectory] under [parent] (tests): the directory [name] is created and checked now. */
internal fun qlogDirectoryIn(
    parent: File,
    name: String,
): DirectoryQlogSink {
    require(name.isNotEmpty() && name != "." && name != ".." && name.none { it == '/' || it == '\\' || it == '\u0000' }) {
        "qlog directory name must be one path component: \"$name\""
    }
    val dir = File(parent, name).path
    checkPrivateDirectory(dir)
    return DirectoryQlogSink(dir)
}
