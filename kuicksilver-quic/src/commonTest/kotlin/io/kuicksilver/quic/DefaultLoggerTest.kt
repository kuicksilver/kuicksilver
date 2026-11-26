// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0

package io.kuicksilver.quic

import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertSame
import kotlin.test.assertTrue

/** The default logger is the platform's (ADR-0026), at Warn; `platform(level)` lowers it, and every endpoint starts with it. */
class DefaultLoggerTest {
    @Test fun theDefaultLoggerTakesWarningsAndUp() {
        val d = KuicksilverLogger.Default
        assertFalse(d.isEnabled(LogLevel.Debug))
        assertFalse(d.isEnabled(LogLevel.Info))
        assertTrue(d.isEnabled(LogLevel.Warn))
        assertTrue(d.isEnabled(LogLevel.Error))
        assertSame(d, KuicksilverLogger.Default)
    }

    @Test fun platformTakesItsLevelAndAbove() {
        val l = KuicksilverLogger.platform(LogLevel.Info)
        assertFalse(l.isEnabled(LogLevel.Debug))
        assertTrue(l.isEnabled(LogLevel.Info))
        // a line below the level is dropped without a call into the platform; one at it does not throw
        l.log(LogLevel.Debug, "not written")
        l.log(LogLevel.Info, "kuicksilver logger test: 100% of a line with a % sign", IllegalStateException("cause"))
    }

    @Test fun anEndpointLogsToTheDefaultLogger() {
        assertSame(KuicksilverLogger.Default, QuicEndpointConfig.Default.logger)
        assertSame(KuicksilverLogger.Default, quicEndpointConfig {}.logger)
    }
}
