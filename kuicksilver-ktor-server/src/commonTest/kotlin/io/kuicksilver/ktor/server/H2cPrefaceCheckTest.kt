// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.server

import io.ktor.utils.io.ByteChannel
import io.ktor.utils.io.availableForRead
import io.ktor.utils.io.readByteArray
import io.ktor.utils.io.writeFully
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.async
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.yield
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/** The client connection preface check of [H2cMode.WithHttp11] (RFC 9113 section 3.4): bounded, consumes nothing. */
class H2cPrefaceCheckTest {
    private val preface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".encodeToByteArray()

    @Test fun thePrefaceAndWhatFollowsStayUnread() =
        runTest {
            val ch = ByteChannel()
            val sent = preface + byteArrayOf(0, 0, 0, 4, 0, 0, 0, 0, 0)
            ch.writeFully(sent)
            ch.flush()
            assertTrue(ch.startsWithH2Preface())
            assertEquals(sent.size, ch.availableForRead)
            assertContentEquals(sent, ch.readByteArray(sent.size))
        }

    @Test fun aPrefaceThatArrivesOctetByOctet() =
        runTest {
            val ch = ByteChannel()
            val check = async(start = CoroutineStart.UNDISPATCHED) { ch.startsWithH2Preface() }
            for (b in preface) {
                assertFalse(check.isCompleted)
                ch.writeFully(byteArrayOf(b))
                ch.flush()
                yield()
            }
            assertTrue(check.await())
            assertEquals(preface.size, ch.availableForRead)
        }

    /** An HTTP/1.1 request is told apart at its first octet: no wait for more. */
    @Test fun negative_theFirstOctetThatDiffersDecides() =
        runTest {
            val ch = ByteChannel()
            ch.writeFully("G".encodeToByteArray())
            ch.flush()
            assertFalse(ch.startsWithH2Preface())
            assertEquals(1, ch.availableForRead)
            val late = ByteChannel()
            late.writeFully("PRI * HTTP/1.1\r\n".encodeToByteArray())
            late.flush()
            assertFalse(late.startsWithH2Preface())
            assertEquals(16, late.availableForRead)
        }

    @Test fun negative_anInputThatEndsInsideThePreface() =
        runTest {
            val ch = ByteChannel()
            ch.writeFully(preface.copyOf(20))
            ch.flushAndClose()
            assertFalse(ch.startsWithH2Preface())
            val empty = ByteChannel()
            empty.flushAndClose()
            assertFalse(empty.startsWithH2Preface())
        }
}
