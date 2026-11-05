// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)

package io.kuicksilver.quic

import io.kuicksilver.quic.api.ApiPair
import io.kuicksilver.quic.runtime.QuicResourceProbe
import io.kuicksilver.tls.KslQuicCrypto
import jdk.jfr.Recording
import jdk.jfr.consumer.RecordingFile
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import kotlinx.coroutines.yield
import java.nio.file.Files
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.seconds

/**
 * P.3: a connection that opens, handshakes and closes normally builds no exception objects but the close reasons the API
 * hands out (`closed`, the `Closed` event): one `ApplicationClosed` on each side. Every other `Throwable` built on that path
 * costs a stack walk on the JVM and a stack capture on Kotlin/Native per connection. Counted with JFR's
 * `jdk.JavaExceptionThrow`, which fires in every `Throwable` constructor.
 */
class NormalPathExceptionsJvmTest {
    /** Until no QUIC runtime is left in the process (this test's endpoints are the only ones open), with a deadline of the caller. */
    private suspend fun settled() {
        while ((QuicResourceProbe.snapshot()["quic.runtimes"] ?: 0L) > 0L) yield()
    }

    @Test fun aNormalConnectionBuildsOnlyItsCloseReasons(): Unit =
        runBlocking {
            val n = 20
            val file = Files.createTempFile("ksl-exceptions", ".jfr")
            val p = ApiPair.open(crypto = KslQuicCrypto)
            try {
                withTimeout(30.seconds) {
                    p.connect().let { (c, s) ->
                        c.close()
                        s.closed.await()
                    }
                    settled() // warm-up: classes load, lazies settle, the connection leaves both loops
                }
                val rec = Recording()
                rec.enable("jdk.JavaExceptionThrow").withStackTrace()
                rec.start()
                withTimeout(30.seconds) {
                    repeat(n) {
                        val (c, s) = p.connect()
                        c.close()
                        s.closed.await()
                        c.closed.await()
                    }
                    settled() // both sides drained and left their loops: their runtimes finished (ConnectionRuntime.finish)
                }
                rec.stop()
                rec.dump(file)
                rec.close()
            } finally {
                p.close()
            }
            // only this test's coroutines run in the window; the endpoints' loops and timers are part of what is measured
            // the library's and the coroutines' exceptions (the JDK's own, such as class loading, are not this path)
            val thrown =
                RecordingFile.readAllEvents(file).mapNotNull { e ->
                    e.getClass("thrownClass")?.name?.takeIf { it.startsWith("io.kuicksilver.") || it.startsWith("kotlin") }
                }
            Files.deleteIfExists(file)
            val byClass = thrown.groupingBy { it }.eachCount()
            val reasons = byClass["io.kuicksilver.quic.QuicException\$ConnectionLost\$ApplicationClosed"] ?: 0
            assertEquals(2 * n, reasons, "one ApplicationClosed per side and connection: $byClass")
            assertTrue(byClass.keys.all { it.endsWith("ApplicationClosed") }, "no other exception on the normal path: $byClass")
        }
}
