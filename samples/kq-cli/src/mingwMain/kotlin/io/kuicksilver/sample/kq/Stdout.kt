// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(ExperimentalForeignApi::class)

package io.kuicksilver.sample.kq

import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.cinterop.staticCFunction
import platform.posix._O_BINARY
import platform.posix._fileno
import platform.posix._setmode
import platform.posix.stdout
import platform.windows.CP_UTF8
import platform.windows.FALSE
import platform.windows.GetConsoleOutputCP
import platform.windows.SetConsoleCtrlHandler
import platform.windows.SetConsoleOutputCP
import platform.windows.TRUE

/**
 * Binary mode for stdout, so a body's `\n` is not written as `\r\n` (the C runtime's text mode would); and UTF-8 as the
 * console's output code page while kq runs (restored at exit), so the stderr lines show non-ASCII text right on a console.
 * Neither failing stops kq.
 */
internal actual fun prepareStdout() {
    _setmode(_fileno(stdout), _O_BINARY)
    savedCodePage = GetConsoleOutputCP() // 0 without a console (output redirected): then nothing is set or restored
    if (savedCodePage != 0u) {
        SetConsoleOutputCP(CP_UTF8.toUInt())
        // Ctrl+C and Ctrl+Break end the process without the finally in main: give the console its code page back first,
        // then FALSE lets the default handler end the process as usual
        SetConsoleCtrlHandler(staticCFunction { _: UInt -> restoreStdout(); FALSE }, TRUE)
    }
}

/** The console's output code page before kq changed it; the console outlives kq, so it gets it back. */
private var savedCodePage: UInt = 0u

internal actual fun restoreStdout() {
    if (savedCodePage != 0u) SetConsoleOutputCP(savedCodePage) // setting the same page twice is harmless
}
