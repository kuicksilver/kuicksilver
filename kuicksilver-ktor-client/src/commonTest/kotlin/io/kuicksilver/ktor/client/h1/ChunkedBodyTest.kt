// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
// Kept identical with kuicksilver-ktor-server's h1/ChunkedBodyTest.kt, as ChunkedBody.kt is.
package io.kuicksilver.ktor.client.h1

import io.ktor.utils.io.ByteChannel
import io.ktor.utils.io.ByteReadChannel
import io.ktor.utils.io.readBuffer
import kotlinx.coroutines.test.runTest
import kotlinx.io.IOException
import kotlinx.io.readByteArray
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

/** The chunk-size line grammar of RFC 9112 section 7.1, strictly: `1*HEXDIG [ chunk-ext ] CRLF`. */
class ChunkedBodyTest {
    private suspend fun decode(wire: String): String {
        val out = ByteChannel()
        decodeChunkedBody(ByteReadChannel(wire.encodeToByteArray()), out)
        return out.readBuffer().readByteArray().decodeToString()
    }

    private fun accepted(
        wire: String,
        body: String,
    ) = runTest { assertEquals(body, decode(wire), wire.visible()) }

    private fun rejected(wire: String) = runTest { assertFailsWith<IOException>(wire.visible()) { decode(wire) } }

    private fun String.visible() = replace("\r", "\\r").replace("\n", "\\n").replace("\t", "\\t")

    @Test fun plainChunks() {
        accepted("5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n", "hello world")
        accepted("A\r\n0123456789\r\n0\r\n\r\n", "0123456789")
        accepted("00005\r\nhello\r\n000\r\n\r\n", "hello")
    }

    /** chunk-ext = *( BWS ";" BWS chunk-ext-name [ BWS "=" BWS chunk-ext-val ] ), chunk-ext-val = token / quoted-string. */
    @Test fun chunkExtensionsAreSkipped() {
        accepted("5;a\r\nhello\r\n0\r\n\r\n", "hello")
        accepted("5;a=b;c=\"d;e\\\"f\\\\\"\r\nhello\r\n0;last\r\n\r\n", "hello")
        accepted("5 ; a = b\t;\tc\r\nhello\r\n0\r\n\r\n", "hello")
        accepted("5;a=\"\"\r\nhello\r\n0\r\n\r\n", "hello")
    }

    /**
     * Whitespace right before the CRLF that ends the line is not in the grammar (RFC 9112 section 7.1: BWS only before a
     * `;` and around the `=` of an extension) and fails the body; before, it was tolerated, so the parser accepted lines
     * a stricter recipient in front of it rejects or reads differently (request smuggling hardening).
     */
    @Test fun negative_whitespaceBeforeTheLineEndIsRejected() {
        rejected("5 \r\nhello\r\n0\r\n\r\n")
        rejected("5\t \r\nhello\r\n0\r\n\r\n")
        rejected("5\r\nhello\r\n0 \r\n\r\n")
        rejected("5;a=b \r\nhello\r\n0\r\n\r\n")
        rejected("5;a \r\nhello\r\n0\r\n\r\n")
        rejected("5;a=\"x\"\t\r\nhello\r\n0\r\n\r\n")
        rejected("5 \rhello\r\n0\r\n\r\n")
        rejected("5 \nhello\r\n0\r\n\r\n")
        accepted("5 ;a\r\nhello\r\n0\t; a\t=\t\"x\"\r\n\r\n", "hello")
    }

    /**
     * The failure names what is wrong, so the operator of a peer that writes `5 \r\n` (some servlet containers and
     * hand-written servers do; Go's net/http and nginx tolerate it on reading) can tell it from a broken body.
     */
    @Test fun whitespaceBeforeTheLineEndFailsWithAClearMessage() =
        runTest {
            for (wire in listOf("5 \r\nhello\r\n0\r\n\r\n", "5;a\t\r\nhello\r\n0\r\n\r\n", "5;a=b \r\nhello\r\n0\r\n\r\n")) {
                val e = assertFailsWith<IOException>(wire.visible()) { decode(wire) }
                assertEquals(
                    "Whitespace before the end of a chunk size line (RFC 9112 section 7.1 allows it only before the \";\" " +
                        "and around the \"=\" of a chunk extension)",
                    e.message,
                    wire.visible(),
                )
            }
        }

    /**
     * RFC 9112 section 2.2: a bare CR MUST be treated as invalid. Before, the parser skipped a CR anywhere in the line, so
     * `1\r0` was read as 0x10 where a recipient that ends the line at the CR reads 1, and `\r\r\n` was a last chunk.
     */
    @Test fun negative_bareCrInChunkSizeLineIsRejected() {
        rejected("1\r0\r\n0123456789abcdef\r\n0\r\n\r\n")
        rejected("\r\r\n0123456789abcdef\r\n0\r\n\r\n")
        rejected("5\r\rhello\r\n0\r\n\r\n")
        rejected("5;a\rb\r\nhello\r\n0\r\n\r\n")
        rejected("5;a=\"\r\"\r\nhello\r\n0\r\n\r\n")
        rejected("5\r\nhello\r\n0\r\r\n\r\n")
    }

    /**
     * A bare LF does not end a chunk-size line. RFC 9112 section 2.2 lets a recipient accept a bare LF in the start line
     * and field lines only; on a chunk line a lenient recipient behind a strict one (or the reverse) frames the body
     * differently, the "funky chunks" request smuggling class, so the line is rejected, as Ktor 3.6.0 already did.
     */
    @Test fun negative_bareLfInChunkSizeLineIsRejected() {
        rejected("5\nhello\r\n0\r\n\r\n")
        rejected("5;a\nhello\r\n0\r\n\r\n")
        rejected("5;a=\"\n\"\r\nhello\r\n0\r\n\r\n")
        rejected("5\r\nhello\r\n0\n\r\n")
    }

    /** chunk-size = 1*HEXDIG: no empty size, no sign, no prefix, no whitespace before the digits or inside an extension. */
    @Test fun negative_malformedChunkSizeIsRejected() {
        for (line in listOf(
            "",
            ";a",
            " 5",
            "+5",
            "-5",
            "0x5",
            "5 x",
            "5;a= ",
            "5; ",
            "g",
            "5;",
            "5;a=",
            "5;=b",
            "5;a b",
            "5;a=b c",
            "5;a=\"b\"c",
            "5;a@=b",
        )) {
            rejected("$line\r\nhello\r\n0\r\n\r\n")
        }
    }

    /** A quote outside a chunk extension is invalid. Before, it switched on a quoted mode that swallowed CR and LF. */
    @Test fun negative_quoteOutsideAnExtensionIsRejected() {
        rejected("5\"\r\n\"\r\nhello\r\n0\r\n\r\n")
        rejected("\"5\"\r\nhello\r\n0\r\n\r\n")
        rejected("5;a=b\"\r\nhello\r\n0\r\n\r\n")
    }

    /**
     * A size that does not fit a signed 64-bit length is rejected rather than wrapped. Before, 16 hex digits starting with
     * 8 or above became a negative size. The line is limited to 128 bytes, so neither leading zeros nor extensions run on.
     */
    @Test fun negative_overlongChunkSizeIsRejected() {
        rejected("8000000000000000\r\nhello\r\n0\r\n\r\n")
        rejected("FFFFFFFFFFFFFFFF\r\nhello\r\n0\r\n\r\n")
        rejected("10000000000000000\r\nhello\r\n0\r\n\r\n")
        rejected("0".repeat(200) + "5\r\nhello\r\n0\r\n\r\n")
        rejected("5;" + "a".repeat(200) + "\r\nhello\r\n0\r\n\r\n")
        // The largest size that fits is a valid line; the body then ends inside that chunk.
        rejected("7FFFFFFFFFFFFFFF\r\nhello\r\n0\r\n\r\n")
    }
}
