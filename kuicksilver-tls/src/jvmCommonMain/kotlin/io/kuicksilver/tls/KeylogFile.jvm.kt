// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(DelicateKuicksilverApi::class)

package io.kuicksilver.tls

import io.kuicksilver.annotations.DelicateKuicksilverApi
import java.io.File
import java.nio.file.Files
import java.nio.file.attribute.PosixFilePermissions

public actual fun keylogFile(path: String): KeylogSink {
    val f = File(path)
    if (!f.exists()) {
        try {
            Files.createFile(f.toPath(), PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")))
        } catch (
            _: UnsupportedOperationException,
        ) {
            f.createNewFile()
        }
    }
    return KeylogSink { line -> f.appendText(line + "\n") }
}

public actual fun keylogFromEnvironment(): KeylogSink? = System.getenv("SSLKEYLOGFILE")?.takeIf { it.isNotBlank() }?.let { keylogFile(it) }
