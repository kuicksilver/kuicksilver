// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.server

import io.ktor.util.logging.Logger
import io.kuicksilver.quic.KuicksilverLogger
import io.kuicksilver.quic.LogLevel

internal actual fun kuicksilverLoggerAsKtor(logger: KuicksilverLogger): Logger = KuicksilverKtorLogger(LoggerGuard(logger))

/** Every member of Ktor's native `Logger` on [guard]; trace goes as debug, and [level] is the lowest level [guard] enables. */
private class KuicksilverKtorLogger(
    private val guard: LoggerGuard,
) : Logger {
    override val level: io.ktor.util.logging.LogLevel
        get() =
            when {
                guard.enabled(LogLevel.Debug) -> io.ktor.util.logging.LogLevel.TRACE
                guard.enabled(LogLevel.Info) -> io.ktor.util.logging.LogLevel.INFO
                guard.enabled(LogLevel.Warn) -> io.ktor.util.logging.LogLevel.WARN
                else -> io.ktor.util.logging.LogLevel.ERROR
            }

    override fun error(message: String) = guard.log(LogLevel.Error) { message }

    override fun error(
        message: String,
        cause: Throwable,
    ) = guard.log(LogLevel.Error, cause) { message }

    override fun warn(message: String) = guard.log(LogLevel.Warn) { message }

    override fun warn(
        message: String,
        cause: Throwable,
    ) = guard.log(LogLevel.Warn, cause) { message }

    override fun info(message: String) = guard.log(LogLevel.Info) { message }

    override fun info(
        message: String,
        cause: Throwable,
    ) = guard.log(LogLevel.Info, cause) { message }

    override fun debug(message: String) = guard.log(LogLevel.Debug) { message }

    override fun debug(
        message: String,
        cause: Throwable,
    ) = guard.log(LogLevel.Debug, cause) { message }

    override fun trace(message: String) = guard.log(LogLevel.Debug) { message }

    override fun trace(
        message: String,
        cause: Throwable,
    ) = guard.log(LogLevel.Debug, cause) { message }

    override fun toString(): String = guard.toString()
}

// Kotlin/Native has no VirtualMachineError: running out of memory there ends the process rather than throwing
internal actual fun Throwable.isVirtualMachineError(): Boolean = false
