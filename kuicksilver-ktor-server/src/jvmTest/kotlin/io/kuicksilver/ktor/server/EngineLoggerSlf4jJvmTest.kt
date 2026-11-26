// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.server

import io.kuicksilver.quic.KuicksilverLogger
import io.kuicksilver.quic.LogLevel
import org.slf4j.MarkerFactory
import java.util.concurrent.CopyOnWriteArrayList
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertSame
import kotlin.test.assertTrue

/**
 * On the JVM the engine's Ktor logger is a whole SLF4J `Logger`: with `observability { logger }` set, the forms a common
 * caller cannot see (formatted, with a marker, the `isXxxEnabled` checks, the fluent API) go to the application's logger
 * too, never to an SLF4J binding, and each is checked against its level first.
 */
class EngineLoggerSlf4jJvmTest {
    private class Recording(
        val enabled: Set<LogLevel>,
    ) : KuicksilverLogger {
        val lines = CopyOnWriteArrayList<Triple<LogLevel, String, Throwable?>>()

        override fun isEnabled(level: LogLevel): Boolean = level in enabled

        override fun log(
            level: LogLevel,
            message: String,
            cause: Throwable?,
        ) {
            check(level in enabled) { "$level delivered although disabled" }
            lines += Triple(level, message, cause)
        }
    }

    private fun slf4j(logger: KuicksilverLogger): org.slf4j.Logger =
        kuicksilverServer(null, configure = { observability { this.logger = logger } }) {}.engine.log

    @Test fun everySlf4jFormGoesToTheApplicationsLogger() {
        val own = Recording(LogLevel.entries.toSet())
        val log = slf4j(own)
        val boom = IllegalStateException("boom")
        val marker = MarkerFactory.getMarker("M")
        log.info("a {} b {}", 1, 2)
        log.warn("c {}", "x", boom) // a trailing Throwable no placeholder takes is the cause
        log.error(marker, "d {} {} {}", 1, 2, 3)
        log.debug(marker, "e")
        log.trace("t {}", 0)
        log.atInfo().addArgument(7).log("f {}")
        assertEquals(
            listOf(
                Triple(LogLevel.Info, "a 1 b 2", null),
                Triple(LogLevel.Warn, "c x", boom),
                Triple(LogLevel.Error, "d 1 2 3", null),
                Triple(LogLevel.Debug, "e", null),
                Triple(LogLevel.Debug, "t 0", null),
                Triple(LogLevel.Info, "f 7", null),
            ),
            own.lines.toList(),
        )
        assertTrue(log.isDebugEnabled && log.isTraceEnabled && log.isErrorEnabled(marker))
    }

    @Test fun negative_disabledLevelsAreNeitherBuiltNorDelivered() {
        val own = Recording(setOf(LogLevel.Warn, LogLevel.Error))
        val log = slf4j(own)
        var built = 0
        val expensive =
            object {
                override fun toString(): String {
                    built++
                    return "built"
                }
            }
        log.debug("{}", expensive)
        log.info("{}", expensive)
        log.trace(MarkerFactory.getMarker("M"), "{}", expensive)
        assertEquals(0, built, "a disabled line was formatted")
        assertFalse(log.isDebugEnabled || log.isTraceEnabled || log.isInfoEnabled)
        assertTrue(log.isWarnEnabled)
        log.warn("{}", expensive)
        assertEquals(listOf(Triple(LogLevel.Warn, "built", null)), own.lines.toList())
    }

    /** A logger that throws, or whose arguments throw when formatted, never reaches the engine with it. */
    @Test fun negative_throwingLoggerOrArgumentIsContained() {
        val throwing =
            object : KuicksilverLogger {
                override fun isEnabled(level: LogLevel): Boolean = throw IllegalStateException("isEnabled")

                override fun log(
                    level: LogLevel,
                    message: String,
                    cause: Throwable?,
                ): Unit = throw IllegalStateException("log")
            }
        val log = slf4j(throwing)
        log.error("x {}", 1)
        assertFalse(log.isErrorEnabled, "an isEnabled that throws reads as false")
        val own = Recording(LogLevel.entries.toSet())
        val bad =
            object {
                override fun toString(): String = throw IllegalStateException("toString")
            }
        slf4j(own).warn("y {}", bad) // SLF4J's formatter reports the failure in the text
        assertEquals(1, own.lines.size)
        assertSame(LogLevel.Warn, own.lines.single().first)
    }
}
