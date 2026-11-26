// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(ExperimentalForeignApi::class)

package io.kuicksilver.sample.kq

import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.cinterop.addressOf
import kotlinx.cinterop.convert
import kotlinx.cinterop.usePinned
import kotlinx.coroutines.runBlocking
import platform.posix.ferror
import platform.posix.fflush
import platform.posix.fputs
import platform.posix.fwrite
import platform.posix.stderr
import platform.posix.stdout
import kotlin.system.exitProcess

/** The `kq` executable (macOS, Linux and Windows). */
fun main(args: Array<String>) {
    prepareStdout()
    val code =
        try {
            runBlocking { kq(args.toList(), NativeConsole) }
        } finally {
            restoreStdout()
        }
    exitProcess(code)
}

/** Sets stdout up for the body's bytes as they are: binary mode and UTF-8 console output on Windows; nothing elsewhere. */
internal expect fun prepareStdout()

/** Undoes what [prepareStdout] changed outside the process (the console's code page on Windows); idempotent. */
internal expect fun restoreStdout()

private object NativeConsole : Console {
    private var failed = false

    override fun out(
        bytes: ByteArray,
        offset: Int,
        length: Int,
    ) {
        if (length == 0) return
        val written = bytes.usePinned { fwrite(it.addressOf(offset), 1.convert(), length.convert(), stdout) }
        if (written.toLong() != length.toLong()) failed = true
    }

    override fun err(line: String) {
        fflush(stdout) // the body so far before the line, as on a terminal
        fputs(line + "\n", stderr)
        fflush(stderr)
    }

    override fun flush(): Boolean {
        if (fflush(stdout) != 0 || ferror(stdout) != 0) failed = true
        return !failed
    }
}
