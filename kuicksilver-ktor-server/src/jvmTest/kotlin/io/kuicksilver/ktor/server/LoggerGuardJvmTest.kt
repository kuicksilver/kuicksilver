// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.server

import io.kuicksilver.quic.KuicksilverLogger
import io.kuicksilver.quic.LogLevel
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse

/** The engine's logger guard drops what a logger throws, a virtual machine error excepted. */
class LoggerGuardJvmTest {
    private class Throwing(
        val onEnabled: Throwable?,
        val onLog: Throwable?,
    ) : KuicksilverLogger {
        override fun isEnabled(level: LogLevel): Boolean = onEnabled?.let { throw it } ?: true

        override fun log(
            level: LogLevel,
            message: String,
            cause: Throwable?,
        ) {
            onLog?.let { throw it }
        }
    }

    @Test fun aLoggersExceptionIsDropped() {
        LoggerGuard(Throwing(null, IllegalStateException("logger down"))).log(LogLevel.Warn) { "line" }
        assertFalse(LoggerGuard(Throwing(RuntimeException("no level"), null)).enabled(LogLevel.Warn))
        // building the message may fail too
        LoggerGuard(Throwing(null, null)).log(LogLevel.Warn) { error("no message") }
    }

    @Test fun negative_aVirtualMachineErrorIsNotHidden() {
        assertFailsWith<StackOverflowError> { LoggerGuard(Throwing(null, StackOverflowError())).log(LogLevel.Warn) { "line" } }
        assertFailsWith<OutOfMemoryError> { LoggerGuard(Throwing(OutOfMemoryError(), null)).enabled(LogLevel.Warn) }
        assertFailsWith<OutOfMemoryError> { LoggerGuard(Throwing(null, null)).log(LogLevel.Warn) { throw OutOfMemoryError() } }
        var built = 0
        LoggerGuard(Throwing(null, null)).log(LogLevel.Warn) { "line ${++built}" }
        assertEquals(1, built)
    }
}
