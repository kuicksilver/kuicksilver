// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic

import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import kotlin.concurrent.atomics.AtomicReference
import kotlin.concurrent.atomics.ExperimentalAtomicApi
import kotlin.concurrent.atomics.update
import kotlin.test.assertTrue

/** One line a [CapturingLogger] took. */
internal data class LoggedLine(
    val level: LogLevel,
    val message: String,
    val cause: Throwable?,
)

/**
 * A [KuicksilverLogger] for a test that provokes a warning or error on purpose: the lines are kept instead of printed, and the
 * test asserts them ([assertLogged]), so the expected line is a check and CI logs keep only the unexpected ones. Tests that
 * expect nothing leave the default logger, which prints.
 */
@OptIn(ExperimentalKuicksilverApi::class, ExperimentalAtomicApi::class)
internal class CapturingLogger(
    private val minLevel: LogLevel = LogLevel.Warn,
) : KuicksilverLogger {
    private val taken = AtomicReference(emptyList<LoggedLine>())

    val lines: List<LoggedLine> get() = taken.load()

    override fun isEnabled(level: LogLevel): Boolean = level >= minLevel

    override fun log(
        level: LogLevel,
        message: String,
        cause: Throwable?,
    ) {
        taken.update { it + LoggedLine(level, message, cause) }
    }

    /** Asserts that a line at [level] contains every fragment of [fragments], in its message or in its cause's. */
    fun assertLogged(
        level: LogLevel,
        vararg fragments: String,
    ) {
        val hit = lines.firstOrNull { l -> l.level == level && fragments.all { f -> f in l.message || f in (l.cause?.toString() ?: "") } }
        assertTrue(hit != null, "no $level line with ${fragments.toList()} in $lines")
    }
}
