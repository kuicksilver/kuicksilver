// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.server

import io.ktor.util.logging.KtorSimpleLogger
import io.ktor.util.logging.Logger
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.quic.KuicksilverLogger
import io.kuicksilver.quic.LogLevel
import kotlin.concurrent.atomics.AtomicReference
import kotlin.concurrent.atomics.ExperimentalAtomicApi
import kotlin.concurrent.atomics.update
import kotlin.test.assertTrue

/** One warning or error a [CapturedLog] took. */
internal data class CapturedLine(
    val level: String,
    val message: String,
    val cause: Throwable?,
)

/**
 * The application log (`environment.log`) of a test server that provokes warnings or errors on purpose: they are kept instead
 * of printed (a Kotlin/Native run prints each with its stack trace), and the test asserts them with [assertLogged], so an
 * expected line is a check and CI output keeps the unexpected ones. Anything below warnings goes to a plain logger as before.
 * [quic] is the same sink for a `KuicksilverApplicationEngine.Configuration.logger`.
 */
@OptIn(ExperimentalAtomicApi::class)
internal class CapturedLog(
    private val delegate: Logger = KtorSimpleLogger("io.kuicksilver.test"),
) : Logger by delegate {
    private val taken = AtomicReference(emptyList<CapturedLine>())

    val lines: List<CapturedLine> get() = taken.load()

    private fun take(
        level: String,
        message: String,
        cause: Throwable?,
    ) {
        taken.update { it + CapturedLine(level, message, cause) }
    }

    override fun warn(message: String) = take("WARN", message, null)

    override fun warn(
        message: String,
        cause: Throwable,
    ) = take("WARN", message, cause)

    override fun error(message: String) = take("ERROR", message, null)

    override fun error(
        message: String,
        cause: Throwable,
    ) = take("ERROR", message, cause)

    /** The Kuicksilver library logger over the same sink (warnings and errors only). */
    @OptIn(ExperimentalKuicksilverApi::class)
    val quic: KuicksilverLogger =
        object : KuicksilverLogger {
            override fun isEnabled(level: LogLevel): Boolean = level >= LogLevel.Warn

            override fun log(
                level: LogLevel,
                message: String,
                cause: Throwable?,
            ) = take(level.name.uppercase(), message, cause)
        }

    /** Asserts that a [level] line (`WARN` or `ERROR`) contains every fragment, in its message or in its cause's; returns it. */
    fun assertLogged(
        level: String,
        vararg fragments: String,
    ) {
        val hit =
            lines.firstOrNull { l ->
                l.level == level && fragments.all { f -> f in l.message || f in (l.cause?.toString() ?: "") }
            }
        assertTrue(hit != null, "no $level line with ${fragments.toList()} in $lines")
    }
}
