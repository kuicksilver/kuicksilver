// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(InternalAPI::class)

package io.kuicksilver.ktor.client

import io.ktor.utils.io.ByteReadChannel
import io.ktor.utils.io.InternalAPI
import io.kuicksilver.ktor.client.h1.HeadLimitedInput
import kotlinx.coroutines.test.runTest
import kotlinx.io.Buffer
import kotlinx.io.IOException
import kotlinx.io.RawSink
import kotlinx.io.readByteArray
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertSame
import kotlin.test.assertTrue

/**
 * The engine's buffering channels ([ConsumedBody] for request bodies, [HeadLimitedInput] for an HTTP/1.1 connection's
 * input) are cancelled from other threads while their reader reads (the socket timeout's `cancelInput`, a call that
 * ends): the cancel must leave the reader's buffer alone, as H2BodyChannel's (H2BodyCancelTest). Before, it emptied the
 * buffer under the read, which then failed with an EOFException (or, on two threads, `Buffer.clear` threw out of the
 * cancel).
 */
class BufferedCancelTest {
    private class InterruptedSink(
        private val during: () -> Unit,
    ) : RawSink {
        val got = Buffer()

        override fun write(
            source: Buffer,
            byteCount: Long,
        ) {
            during()
            got.write(source.readByteArray(byteCount.toInt()))
        }

        override fun flush() {}

        override fun close() {}
    }

    private suspend fun cancelDuringARead(channel: ByteReadChannel) {
        val bytes = ByteArray(3000) { (it % 251).toByte() }
        assertTrue(channel.awaitContent(bytes.size))
        val cause = IOException("the socket timeout expired")
        val src = channel.readBuffer
        val sink = InterruptedSink { channel.cancel(cause) }
        src.readTo(sink, bytes.size.toLong())
        assertContentEquals(bytes, sink.got.readByteArray())
        assertSame(cause, channel.closedCause)
        assertTrue(channel.isClosedForRead)
        assertSame(cause, assertFailsWith<IOException> { channel.readBuffer })
        assertSame(cause, assertFailsWith<IOException> { channel.awaitContent(1) })
        channel.cancel(IOException("again")) // idempotent: the first cause stays
        assertSame(cause, channel.closedCause)
    }

    private fun source() = ByteReadChannel(ByteArray(3000) { (it % 251).toByte() } + ByteArray(5000))

    @Test fun consumedBodyCancelDuringAReadLeavesTheReadersBytes() =
        runTest { cancelDuringARead(ConsumedBody(source(), Activity(), step = 4096)) }

    @Test fun headLimitedInputCancelDuringAReadLeavesTheReadersBytes() =
        runTest { cancelDuringARead(HeadLimitedInput(source(), maxHeadBytes = 8192)) }

    /** A cancel without a cause still fails the reads, with an IOException of the channel's own; the source is cancelled. */
    @Test fun cancelWithoutACauseFailsTheReads() =
        runTest {
            for (make in listOf<(ByteReadChannel) -> ByteReadChannel>({ ConsumedBody(it, Activity()) }, { HeadLimitedInput(it, 8192) })) {
                val src = source()
                val c = make(src)
                assertTrue(c.awaitContent(10))
                c.cancel(null)
                assertFailsWith<IOException> { c.awaitContent(1) }
                assertTrue(src.isClosedForRead, "the source is cancelled with it")
                assertEquals(true, c.closedCause is IOException)
            }
        }
}
