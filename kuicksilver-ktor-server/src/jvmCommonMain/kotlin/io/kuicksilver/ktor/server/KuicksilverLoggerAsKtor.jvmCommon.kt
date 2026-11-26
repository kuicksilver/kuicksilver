// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.server

import io.ktor.util.logging.Logger
import io.kuicksilver.quic.KuicksilverLogger
import io.kuicksilver.quic.LogLevel
import org.slf4j.Marker
import org.slf4j.event.Level
import org.slf4j.helpers.LegacyAbstractLogger
import org.slf4j.helpers.MessageFormatter

internal actual fun kuicksilverLoggerAsKtor(logger: KuicksilverLogger): Logger = KuicksilverSlf4jLogger(LoggerGuard(logger))

/**
 * The whole SLF4J `Logger` on [guard]: SLF4J's [LegacyAbstractLogger] routes every form (plain, formatted, with a marker,
 * the fluent API) through the level checks below and [handleNormalizedLoggingCall], so none of them reaches an SLF4J
 * binding. A marker is dropped (a [KuicksilverLogger] has none).
 */
private class KuicksilverSlf4jLogger(
    private val guard: LoggerGuard,
) : LegacyAbstractLogger() {
    init {
        name = "io.kuicksilver.ktor.server"
    }

    override fun isTraceEnabled(): Boolean = guard.enabled(LogLevel.Debug)

    override fun isDebugEnabled(): Boolean = guard.enabled(LogLevel.Debug)

    override fun isInfoEnabled(): Boolean = guard.enabled(LogLevel.Info)

    override fun isWarnEnabled(): Boolean = guard.enabled(LogLevel.Warn)

    override fun isErrorEnabled(): Boolean = guard.enabled(LogLevel.Error)

    override fun getFullyQualifiedCallerName(): String? = null

    override fun handleNormalizedLoggingCall(
        level: Level,
        marker: Marker?,
        messagePattern: String?,
        arguments: Array<out Any?>?,
        throwable: Throwable?,
    ) {
        val to =
            when (level) {
                Level.ERROR -> LogLevel.Error
                Level.WARN -> LogLevel.Warn
                Level.INFO -> LogLevel.Info
                else -> LogLevel.Debug
            }
        if (arguments.isNullOrEmpty()) {
            guard.log(to, throwable) { messagePattern.orEmpty() }
            return
        }
        // a trailing Throwable no placeholder takes is the cause (SLF4J's rule), as the binding would read it
        val formatted = runCatching { MessageFormatter.arrayFormat(messagePattern, arguments) }.getOrNull()
        guard.log(to, throwable ?: formatted?.throwable) { formatted?.message ?: messagePattern.orEmpty() }
    }

    override fun toString(): String = guard.toString()
}

internal actual fun Throwable.isVirtualMachineError(): Boolean = this is VirtualMachineError
