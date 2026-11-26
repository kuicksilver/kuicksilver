// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic

/** Severity of a [KuicksilverLogger] line, from the most verbose to the most severe. */
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
 * `quicEndpointConfig { observability { logger } }` and per Ktor engine with its `observability { logger }`. The default,
 * [Default], is the platform's logger; bridge it to any other logging framework of your application in a few lines.
 *
 * The library never logs secrets: no keys, traffic secrets, session tickets, Retry or address-validation tokens and no
 * reset tokens; connection IDs and addresses are logged. Lines are built only when [isEnabled] answers true for their
 * level, so a disabled level costs one call. [log] may be called from the endpoint loops (several threads with more than one
 * loop) and must be quick and thread-safe; an exception out of it (a CancellationException too) is swallowed and counted
 * in `EndpointStats.listenerFailures`.
 */
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
        /**
         * The default: [platform] at [LogLevel.Warn], so the library's warnings land where the application's own log lines
         * go. SLF4J on the JVM (the API Ktor logs through; the logger `io.kuicksilver`, and standard error when no SLF4J
         * provider is on the classpath), Logcat on Android (tag `Kuicksilver`), NSLog on Apple platforms, standard error on
         * Linux and Windows.
         */
        public val Default: KuicksilverLogger by lazy { platform(LogLevel.Warn) }

        /** [LogLevel.Warn] and above, one line each on standard error: the default before 0.3.0. */
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

        /** [minLevel] and above to the platform's logger, as [Default] does at [LogLevel.Warn]: `platform(LogLevel.Info)` while you debug. */
        public fun platform(minLevel: LogLevel): KuicksilverLogger = platformLogger(minLevel)
    }
}

/** The platform's logger behind [KuicksilverLogger.platform]. */
internal expect fun platformLogger(minLevel: LogLevel): KuicksilverLogger

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

/**
 * Logs [message] (built only when [level] is enabled); a logger that throws is ignored, never the caller's failure. That
 * includes a CancellationException: logging is not suspending, so one out of [KuicksilverLogger.log] is the logger's own
 * failure, and rethrowing it would end the coroutine of an endpoint loop without a trace.
 */
internal inline fun KuicksilverLogger.emit(
    level: LogLevel,
    cause: Throwable? = null,
    message: () -> String,
) {
    try {
        if (isEnabled(level)) log(level, message(), cause)
    } catch (_: Throwable) {
    }
}

/**
 * [delegate] behind a guard: nothing it throws, a CancellationException included, reaches the caller; [failures] counts
 * what it threw (an endpoint's `EndpointStats.listenerFailures`). Any thread may call it.
 */
@OptIn(kotlin.concurrent.atomics.ExperimentalAtomicApi::class)
internal class GuardedLogger(
    private val delegate: KuicksilverLogger,
) : KuicksilverLogger {
    private val failed = kotlin.concurrent.atomics.AtomicLong(0)

    /** Exceptions out of [delegate] so far. */
    val failures: Long get() = failed.load()

    override fun isEnabled(level: LogLevel): Boolean =
        try {
            delegate.isEnabled(level)
        } catch (_: Throwable) {
            failed.addAndFetch(1)
            false
        }

    override fun log(
        level: LogLevel,
        message: String,
        cause: Throwable?,
    ) {
        try {
            delegate.log(level, message, cause)
        } catch (_: Throwable) {
            failed.addAndFetch(1)
        }
    }

    override fun toString(): String = delegate.toString()
}
