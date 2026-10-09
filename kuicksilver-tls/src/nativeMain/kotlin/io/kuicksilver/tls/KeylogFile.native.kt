// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(DelicateKuicksilverApi::class, ExperimentalForeignApi::class)

package io.kuicksilver.tls

import io.kuicksilver.annotations.DelicateKuicksilverApi
import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.cinterop.toKString
import platform.posix.O_APPEND
import platform.posix.O_CREAT
import platform.posix.O_WRONLY
import platform.posix.close
import platform.posix.fclose
import platform.posix.fdopen
import platform.posix.fputs
import platform.posix.getenv
import platform.posix.open

public actual fun keylogFile(path: String): KeylogSink =
    KeylogSink { line ->
        val fd = open(path, O_WRONLY or O_CREAT or O_APPEND, 0x180 /* 0600 */)
        if (fd >= 0) {
            val f = fdopen(fd, "a") // stdio has the same signature on every target (write() differs between POSIX and mingw)
            if (f != null) {
                fputs(line + "\n", f)
                fclose(f)
            } else {
                close(fd)
            }
        }
    }

public actual fun keylogFromEnvironment(): KeylogSink? =
    getenv("SSLKEYLOGFILE")
        ?.toKString()
        ?.takeIf {
            it.isNotBlank()
        }?.let { keylogFile(it) }
