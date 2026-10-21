// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.server

import kotlinx.io.IOException
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.seconds
import kotlin.time.TestTimeSource

/**
 * Accept failures are logged at most once per interval: with the descriptor table full they repeat every second for as
 * long as it lasts, and a warning per failure floods the log (and the disk it is on).
 */
class AcceptFailureReporterTest {
    @Test fun firstFailureIsLoggedThenAtMostOncePerInterval() {
        val time = TestTimeSource()
        val lines = ArrayList<String>()
        val reporter = AcceptFailureReporter(10.seconds, time) { lines += it }
        val e = IOException("Too many open files")
        reporter.report(e, 5.milliseconds)
        assertEquals(listOf("Accept failed: $e; retrying in 5ms"), lines)
        repeat(30) {
            time += 300.milliseconds
            reporter.report(e, 1.seconds)
        }
        assertEquals(1, lines.size, "logged within the interval: $lines")
        time += 1.seconds // 10 s after the first line
        reporter.report(e, 1.seconds)
        assertEquals("Accept failed: $e; retrying in 1s (30 more failures since the last report)", lines.last())
        assertEquals(2, lines.size)
    }
}
