// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(DelicateKuicksilverApi::class)

package io.kuicksilver.tls

import android.content.Context
import android.content.pm.ApplicationInfo
import io.kuicksilver.annotations.DelicateKuicksilverApi
import java.io.File

/** Android: a key log in the app's private files directory, only for debuggable builds (the library cannot see the flag without a Context).
 * Below API 26 (no `java.nio.file`, so the file cannot be checked) it throws [IllegalArgumentException], as [keylogFile] does. */
public fun keylogFile(
    context: Context,
    name: String = "kuicksilver-keylog.txt",
): KeylogSink? {
    if (context.applicationInfo.flags and ApplicationInfo.FLAG_DEBUGGABLE == 0) return null
    return keylogFile(File(context.filesDir, name).path)
}
