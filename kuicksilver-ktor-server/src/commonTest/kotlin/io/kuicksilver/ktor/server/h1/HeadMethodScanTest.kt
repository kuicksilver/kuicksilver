// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.server.h1

import kotlinx.io.Buffer
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * Whether a request head is for HEAD is decided as the request line arrives ([HeadMethodScan]); the head check asks after
 * every read, so the scan must look at each byte once, whatever the segments. The method starts the line (RFC 9112
 * section 3: nothing before it) and SP alone ends it, so the answer is known after at most five bytes. The work is
 * counted, not timed.
 */
class HeadMethodScanTest {
    private fun scan(
        line: String,
        perRead: Int,
    ): HeadMethodScan {
        val scan = HeadMethodScan()
        val buffer = Buffer()
        val bytes = line.encodeToByteArray()
        var i = 0
        while (i < bytes.size) {
            val n = minOf(perRead, bytes.size - i)
            buffer.write(bytes, i, i + n)
            i += n
            scan.update(buffer)
        }
        return scan
    }

    @Test fun negative_eachByteIsInspectedOnce() {
        val prefix = " \t\u000b\u000c\r".repeat(1_638) // 8190 bytes of whitespace: no request line
        for (line in listOf(
            "$prefix HEAD / HTTP/1.1",
            "${prefix}GET / HTTP/1.1",
            prefix + " ".repeat(2),
            "HEAD / HTTP/1.1",
            "GET / HTTP/1.1",
        )) {
            val scan = scan(line, perRead = 1)
            assertTrue(scan.decided, "undecided after ${scan.inspected} bytes")
            assertTrue(scan.inspected <= 5, "${scan.inspected} bytes inspected for ${line.length} received one at a time")
        }
    }

    @Test fun headIsRecognizedWhateverTheSegments() {
        for (perRead in listOf(1, 3, 1_000)) {
            assertEquals(true, scan("HEAD / HTTP/1.1", perRead).head, "$perRead")
            assertEquals(false, scan("  HEAD / HTTP/1.1", perRead).head, "$perRead")
            assertEquals(false, scan("HEAD\t/ HTTP/1.1", perRead).head, "$perRead")
            assertEquals(false, scan("HEADER / HTTP/1.1", perRead).head, "$perRead")
            assertEquals(false, scan("GET / HTTP/1.1", perRead).head, "$perRead")
            assertEquals(false, scan("HEA", perRead).head, "$perRead")
            assertEquals(false, scan(" head / HTTP/1.1", perRead).head, "$perRead")
        }
    }
}
