// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.tls

import io.ktor.utils.io.readAvailable
import io.ktor.utils.io.writeFully
import io.kuicksilver.native.KslLoader
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import kotlinx.io.IOException
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.seconds

/**
 * RFC 9846 section 5.5: "Implementations MUST either close the connection or do a key update ... prior to reaching these
 * limits". A session whose keys come within one record of their limit ends there, and ksl queues internal_error where an
 * alert can be sent (a TLS 1.3 server). The alert leaves on the transport before the failure ends the connection, so the peer
 * reads internal_error, not a bare end, and the connection counts as alerted ([TlsConnection.abortOutput]: the socket then
 * ends with a FIN instead of a reset). [lowerRecordLimit] sets a session's record limit through the native test hooks
 * (kuicksilver-native/src/testhooks), here 4 records.
 */
internal fun recordLimitEndsWithInternalError(lowerRecordLimit: (ssl: Long, records: Long) -> Unit): Unit =
    runBlocking {
        KslLoader.ensureLoaded()
        val (cd, sd) = connect(TcpFixtures.client(), TcpFixtures.server())
        val c = withTimeout(10.seconds) { cd.await() }
        val s = withTimeout(10.seconds) { sd.await() }
        try {
            s.withSslForTest { lowerRecordLimit(it, 4) }
            for (i in 1..3) {
                s.output.writeFully(byteArrayOf(i.toByte()), 0, 1)
                s.output.flush()
                assertEquals(i.toByte(), withTimeout(10.seconds) { c.input.readExactly(1) }[0], "record $i under the keys")
            }
            runCatching {
                s.output.writeFully(byteArrayOf(4), 0, 1)
                s.output.flush()
            }
            val seen =
                runCatching {
                    withTimeout(10.seconds) {
                        val buf = ByteArray(64)
                        while (c.input.readAvailable(buf, 0, buf.size) >= 0) continue
                        c.input.closedCause?.let { throw it }
                    }
                }
            var cause = seen.exceptionOrNull()
            while (cause != null && cause !is TlsException.AlertReceived) cause = cause.cause
            assertEquals(80, cause?.code, "the client saw $seen, not internal_error")
            assertTrue(s.abortOutput(IOException("the stream failed at the record limit")), "the session counts as alerted")
        } finally {
            c.close()
            s.close()
        }
    }
