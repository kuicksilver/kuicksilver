// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic

import io.kuicksilver.annotations.ExperimentalKuicksilverApi

/** Severity of a [KuicksilverLogger] line, from the most verbose to the most severe. */
@ExperimentalKuicksilverApi
public enum class LogLevel {
    /** Per-connection lifecycle: opened, handshake complete, path changed, closed with its reason. */
    Debug,

    /** Endpoint lifecycle: bound, shutting down, closed. */
    Info,

    /** Something degraded but the endpoint goes on: a fallback to the portable socket, a failing listener or qlog sink. */
    Warn,

    /** The endpoint or one of its loops failed and is closing. */
    Error,
}

/**
 * Where the library's diagnostics go (docs/guide/quic.md, "Observability"), set per endpoint with
 * `QuicEndpointConfig.logger` and per Ktor engine with its `logger` setting. No SLF4J or other dependency: bridge it to the
 * logging framework of your application in a few lines.
 *
 * The library never logs secrets: no keys, traffic secrets, session tickets, Retry or address-validation tokens and no
 * reset tokens; connection IDs and addresses are logged. Lines are built only when [isEnabled] answers true for their
 * level, so a disabled level costs one call. [log] may be called from the endpoint loops (several threads with more than one
 * loop) and must be quick and thread-safe; an exception out of it is swallowed.
 */
@ExperimentalKuicksilverApi
public interface KuicksilverLogger {
    /** Whether lines of [level] are wanted; checked before a line is built. */
    public fun isEnabled(level: LogLevel): Boolean

    /** One line at [level], with the failure behind it when there is one. */
    public fun log(
        level: LogLevel,
        message: String,
        cause: Throwable? = null,
    )

    /** Holds the built-in loggers. */
    public companion object {
        /** The default: [LogLevel.Warn] and above, one line each on standard error (the behaviour before loggers existed). */
        public val Stderr: KuicksilverLogger = StderrLogger(LogLevel.Warn)

        /** Drops everything. */
        public val None: KuicksilverLogger =
            object : KuicksilverLogger {
                override fun isEnabled(level: LogLevel): Boolean = false

                override fun log(
                    level: LogLevel,
                    message: String,
                    cause: Throwable?,
                ) {}

                override fun toString(): String = "KuicksilverLogger.None"
            }

        /** [minLevel] and above to standard error, prefixed with `kuicksilver:` and the level. */
        public fun stderr(minLevel: LogLevel): KuicksilverLogger = StderrLogger(minLevel)
    }
}

@OptIn(ExperimentalKuicksilverApi::class)
private class StderrLogger(
    private val minLevel: LogLevel,
) : KuicksilverLogger {
    override fun isEnabled(level: LogLevel): Boolean = level >= minLevel

    override fun log(
        level: LogLevel,
        message: String,
        cause: Throwable?,
    ) {
        if (!isEnabled(level)) return
        printWarning("kuicksilver: ${level.name.uppercase()} $message${cause?.let { " ($it)" } ?: ""}")
    }

    override fun toString(): String = "KuicksilverLogger.stderr($minLevel)"
}

/** Logs [message] (built only when [level] is enabled); a logger that throws is ignored, never the caller's failure. */
@OptIn(ExperimentalKuicksilverApi::class)
internal inline fun KuicksilverLogger.emit(
    level: LogLevel,
    cause: Throwable? = null,
    message: () -> String,
) {
    try {
        if (isEnabled(level)) log(level, message(), cause)
    } catch (e: kotlinx.coroutines.CancellationException) {
        throw e
    } catch (_: Throwable) {
    }
}
