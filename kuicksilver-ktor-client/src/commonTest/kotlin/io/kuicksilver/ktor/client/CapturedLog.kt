// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.client

import io.ktor.util.logging.KtorSimpleLogger
import io.ktor.util.logging.Logger
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
 * The application log (`environment.log`) of a test server that provokes warnings or errors on purpose: the lines [captures]
 * accepts are kept instead of printed (a Kotlin/Native run prints each with its stack trace), and a test asserts them with
 * [assertLogged], so an expected line is a check and CI output keeps the unexpected ones. Everything else goes to a plain
 * logger as before.
 */
@OptIn(ExperimentalAtomicApi::class)
internal class CapturedLog(
    private val delegate: Logger = KtorSimpleLogger("io.kuicksilver.test"),
    private val captures: (message: String, cause: Throwable?) -> Boolean = { _, _ -> true },
) : Logger by delegate {
    private val taken = AtomicReference(emptyList<CapturedLine>())

    val lines: List<CapturedLine> get() = taken.load()

    private fun take(
        level: String,
        message: String,
        cause: Throwable?,
    ): Boolean {
        if (!captures(message, cause)) return false
        taken.update { it + CapturedLine(level, message, cause) }
        return true
    }

    override fun warn(message: String) {
        if (!take("WARN", message, null)) delegate.warn(message)
    }

    override fun warn(
        message: String,
        cause: Throwable,
    ) {
        if (!take("WARN", message, cause)) delegate.warn(message, cause)
    }

    override fun error(message: String) {
        if (!take("ERROR", message, null)) delegate.error(message)
    }

    override fun error(
        message: String,
        cause: Throwable,
    ) {
        if (!take("ERROR", message, cause)) delegate.error(message, cause)
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
