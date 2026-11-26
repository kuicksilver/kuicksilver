// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic

import platform.Foundation.NSLog

/** NSLog, which the unified logging system (Console.app, `log stream`) records; `os_log` needs a static format string. */
internal actual fun platformLogger(minLevel: LogLevel): KuicksilverLogger = NsLogLogger(minLevel)

private class NsLogLogger(
    private val minLevel: LogLevel,
) : KuicksilverLogger {
    override fun isEnabled(level: LogLevel): Boolean = level >= minLevel

    override fun log(
        level: LogLevel,
        message: String,
        cause: Throwable?,
    ) {
        if (level < minLevel) return
        // NSLog's first argument is a format: every '%' of the line is escaped, and no argument follows (a Kotlin String
        // passed through the C varargs is no NSString)
        NSLog("kuicksilver: ${level.name.uppercase()} $message${cause?.let { " ($it)" } ?: ""}".replace("%", "%%"))
    }

    override fun toString(): String = "KuicksilverLogger.platform($minLevel) (NSLog)"
}
