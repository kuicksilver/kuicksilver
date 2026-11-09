// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(io.kuicksilver.annotations.InternalKuicksilverApi::class)

package io.kuicksilver.tls

import io.ktor.utils.io.ByteChannel
import io.ktor.utils.io.ByteReadChannel
import io.ktor.utils.io.ByteWriteChannel
import io.ktor.utils.io.readAvailable
import io.ktor.utils.io.writeFully
import io.kuicksilver.native.KslLoader
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.async
import kotlinx.coroutines.cancel
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.seconds

/**
 * The TCP reader pump's batching: application data is handed on without waking the drainer, a pass that carried no
 * application data still wakes it (a KeyUpdate answer goes out while we are silent), and plaintext is never lost or
 * reordered whatever the batch size.
 */
class TlsReaderPumpTest {
    @BeforeTest fun load() {
        KslLoader.ensureLoaded()
        runBlocking { SessionCache.Default.clear() }
    }

    private val relays = CoroutineScope(SupervisorJob() + Dispatchers.Default)

    /**
     * A pair whose server-to-client direction the test delivers by hand, one TLS record at a time ([deliverRecord]).
     */
    private inner class RelayPair : ChannelPair() {
        private val fromServer = ByteChannel(autoFlush = true)
        private val toClient = ByteChannel(autoFlush = true)
        private val fromClient = ByteChannel(autoFlush = true)
        private val toServer = ByteChannel(autoFlush = true)

        /** Every record the server wrote, in order; the handshake's flow on its own until [manual]. */
        val records = Channel<ByteArray>(Channel.UNLIMITED)

        @kotlin.concurrent.Volatile var manual = false

        override val clientIn: ByteReadChannel get() = toClient
        override val clientOut: ByteWriteChannel get() = fromClient
        override val serverIn: ByteReadChannel get() = toServer
        override val serverOut: ByteWriteChannel get() = fromServer

        init {
            relays.launch {
                val buf = ByteArray(65_536)
                while (true) {
                    val n = fromClient.readAvailable(buf, 0, buf.size)
                    if (n < 0) break
                    toServer.writeFully(buf, 0, n)
                }
                toServer.flushAndClose()
            }
            relays.launch {
                while (true) {
                    val head = ByteArray(5)
                    if (!readFully(fromServer, head)) break
                    val body = ByteArray(((head[3].toInt() and 0xff) shl 8) or (head[4].toInt() and 0xff))
                    if (!readFully(fromServer, body)) break
                    val record = head + body
                    if (manual) records.send(record) else toClient.writeFully(record)
                }
            }
        }

        suspend fun deliverRecord() {
            toClient.writeFully(records.receive())
        }

        private suspend fun readFully(
            ch: ByteReadChannel,
            into: ByteArray,
        ): Boolean {
            var off = 0
            while (off < into.size) {
                val n = ch.readAvailable(into, off, into.size - off)
                if (n < 0) return false
                off += n
            }
            return true
        }
    }

    private fun both(pair: ChannelPair): Pair<TlsConnection, TlsConnection> =
        runBlocking {
            val (c, s) = connect(TcpFixtures.client(), TcpFixtures.server(), pair)
            withTimeout(20.seconds) { c.await() to s.await() }
        }

    /**
     * A download of 1 MiB wakes the client's drainer at most once or twice (the pass after the handshake, the end), not after
     * every transport read: each wake-up is a thread switch, which cost more client CPU than the decryption.
     */
    @Test fun applicationDataDoesNotWakeTheDrainer(): Unit =
        runBlocking {
            val (c, s) = both(ChannelPair())
            try {
                val data = ByteArray(1 shl 20) { (it * 13).toByte() }
                val send =
                    async {
                        s.output.writeFully(data, 0, data.size)
                        s.output.flush()
                    }
                val got = withTimeout(30.seconds) { c.input.readExactly(data.size) }
                send.await()
                assertContentEquals(data, got)
                assertTrue(c.drainWakeupsForTest <= 2, "the drainer woke ${c.drainWakeupsForTest} times for application data")
            } finally {
                c.close()
                s.close()
            }
        }

    /**
     * RFC 9846 section 4.7.3: "If the request_update field is set to "update_requested", then the receiver MUST send a
     * KeyUpdate of its own with request_update set to "update_not_requested" prior to sending its next Application Data
     * record." A record without application data (the server's KeyUpdate, delivered on its own) wakes the client's drainer,
     * whatever ksl produced for it; OpenSSL queues the answer for the client's next write, which sends it first: the
     * server then reads the client's data under the client's new keys.
     */
    @Test fun keyUpdateAloneWakesTheDrainer(): Unit =
        runBlocking {
            val pair = RelayPair()
            val (c, s) = both(pair)
            try {
                // let the post-handshake records (the server's tickets) through, then take the next ones by hand
                val ping = "ready".encodeToByteArray()
                s.output.writeFully(ping, 0, ping.size)
                s.output.flush()
                withTimeout(10.seconds) { c.input.readExactly(ping.size) }
                pair.manual = true
                val wakeups = c.drainWakeupsForTest
                s.keyUpdate(requestPeer = true)
                val data = "after the update".encodeToByteArray()
                s.output.writeFully(data, 0, data.size) // the KeyUpdate goes out first, then this record
                s.output.flush()
                pair.deliverRecord() // the KeyUpdate alone
                pair.deliverRecord()
                assertContentEquals(data, withTimeout(10.seconds) { c.input.readExactly(data.size) })
                assertTrue(c.drainWakeupsForTest > wakeups, "a record without application data wakes the drainer")
                val reply = "client data".encodeToByteArray()
                c.output.writeFully(reply, 0, reply.size)
                c.output.flush()
                assertContentEquals(reply, withTimeout(10.seconds) { s.input.readExactly(reply.size) })
            } finally {
                c.close()
                s.close()
                relays.cancel()
            }
        }

    /**
     * The server's KeyUpdate request arrives mixed with application data while the client is silent: the client's answer
     * may wait for its next write, and goes out before that write's data (the server could not read it otherwise).
     */
    @Test fun keyUpdateMixedWithDataIsAnsweredBeforeTheNextData(): Unit =
        runBlocking {
            val (c, s) = both(ChannelPair())
            try {
                repeat(3) { round ->
                    s.keyUpdate(requestPeer = true)
                    val data = ByteArray(40_000) { (it + round).toByte() }
                    s.output.writeFully(data, 0, data.size)
                    s.output.flush()
                    assertContentEquals(data, withTimeout(10.seconds) { c.input.readExactly(data.size) })
                    val reply = ByteArray(5_000) { (it * round).toByte() }
                    c.output.writeFully(reply, 0, reply.size)
                    c.output.flush()
                    assertContentEquals(reply, withTimeout(10.seconds) { s.input.readExactly(reply.size) })
                }
            } finally {
                c.close()
                s.close()
            }
        }

    /**
     * An application that reads nothing until 1 MiB has been sent gets all of it, in order: batches of up to 64 KiB wait
     * for room in the input as a single record did.
     */
    @Test fun slowReaderGetsEveryBatchInOrder(): Unit =
        runBlocking {
            val (c, s) = both(ChannelPair())
            try {
                val data = ByteArray(1 shl 20) { (it * 31 + (it shr 16)).toByte() }
                val send =
                    async {
                        s.output.writeFully(data, 0, data.size)
                        s.output.flush()
                    }
                // nothing is read until the input holds a full batch's worth
                assertTrue(withTimeout(30.seconds) { c.input.awaitContent(TlsConnection.READ_CHUNK) })
                val got = withTimeout(30.seconds) { c.input.readExactly(data.size) }
                send.await()
                assertContentEquals(data, got)
            } finally {
                c.close()
                s.close()
            }
        }

    /** Records split anywhere over the feeds are counted once complete; a header that cannot be one loses the framing. */
    @Test fun recordFramingCountsCompleteRecordsAcrossFeeds() {
        fun record(len: Int) = byteArrayOf(23, 3, 3, (len shr 8).toByte(), len.toByte()) + ByteArray(len)
        val stream = record(100) + record(0) + record(16_401) + record(3)
        for (step in listOf(1, 2, 5, 7, 4096, stream.size)) {
            val f = RecordFraming()
            var done = 0
            var off = 0
            while (off < stream.size) {
                val n = minOf(step, stream.size - off)
                done += f.complete(stream, off, n)
                off += n
            }
            kotlin.test.assertEquals(4, done, "step $step")
            kotlin.test.assertFalse(f.lost)
        }
        val bad = RecordFraming()
        kotlin.test.assertEquals(0, bad.complete(byteArrayOf(99, 3, 3, 0, 1, 0), 0, 6))
        assertTrue(bad.lost)
    }
}
