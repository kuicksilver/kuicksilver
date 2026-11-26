// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0

package io.kuicksilver.quic

import kotlin.test.Test
import kotlin.test.assertTrue

/** On the JVM the platform logger is SLF4J; without an SLF4J provider (as in these tests) it writes to standard error instead of nowhere. */
class PlatformLoggerJvmTest {
    @Test fun withoutAnSlf4jProviderTheWarningsGoToStandardError() {
        val provider = org.slf4j.LoggerFactory.getLogger("io.kuicksilver") !is org.slf4j.helpers.NOPLogger
        val name = KuicksilverLogger.platform(LogLevel.Warn).toString()
        assertTrue(if (provider) "SLF4J" in name else name == "KuicksilverLogger.stderr(Warn)", name)
    }
}
