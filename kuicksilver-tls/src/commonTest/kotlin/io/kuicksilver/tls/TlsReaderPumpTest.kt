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
import kotlinx.io.readByteArray
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

        /**
         * The next records, at least [bytes] of them, in one write (one transport read on the client's side); returns the
         * sizes of the records delivered.
         */
        suspend fun deliverAtLeast(bytes: Int): List<Int> {
            var all = ByteArray(0)
            val sizes = ArrayList<Int>()
            while (all.size < bytes) all += records.receive().also { sizes += it.size }
            toClient.writeFully(all)
            return sizes
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

    /**
     * The client's first application data reaches the server in the same transport read as its Finished, the read ending
     * inside a record: the record framing follows the handshake's feeds too, so it is not lost, and the server's drainer
     * stays quiet for the data that follows.
     */
    @Test fun firstApplicationDataInTheReadOfTheFinishedKeepsTheFraming(): Unit =
        runBlocking {
            val pair = HeldClientPair()
            val (cd, sd) = connect(TcpFixtures.client(), TcpFixtures.server(), pair)
            val c = withTimeout(20.seconds) { cd.await() } // a TLS 1.3 client is done once its Finished is written
            val data = ByteArray(1 shl 20) { (it * 7).toByte() }
            val send =
                async {
                    c.output.writeFully(data, 0, data.size)
                    c.output.flush()
                }
            // the Finished and more than the handshake's 16 KiB read of application data, released at once
            withTimeout(20.seconds) { while (pair.held < 40_000) pair.grew.receive() }
            pair.release()
            val s = withTimeout(20.seconds) { sd.await() }
            try {
                val got = withTimeout(30.seconds) { s.input.readExactly(data.size) }
                send.await()
                assertContentEquals(data, got)
                kotlin.test.assertFalse(s.framingLostForTest, "the framing was lost after the handshake")
                assertTrue(s.drainWakeupsForTest <= 2, "the drainer woke ${s.drainWakeupsForTest} times for application data")
            } finally {
                c.close()
                s.close()
            }
        }

    /**
     * A pair whose client-to-server direction passes the ClientHello and then holds everything until [release], which
     * hands it over in one write.
     */
    private inner class HeldClientPair : ChannelPair() {
        private val fromClient = ByteChannel(autoFlush = true)
        private val toServer = ByteChannel(autoFlush = true)
        private val buffer = kotlinx.io.Buffer()
        private val released = kotlinx.coroutines.CompletableDeferred<Unit>()

        @kotlin.concurrent.Volatile var held = 0L
        val grew = Channel<Unit>(Channel.CONFLATED)

        override val clientOut: ByteWriteChannel get() = fromClient
        override val serverIn: ByteReadChannel get() = toServer

        init {
            relays.launch {
                val buf = ByteArray(65_536)
                var first = true
                while (true) {
                    val n = fromClient.readAvailable(buf, 0, buf.size)
                    if (n < 0) break
                    if (first || released.isCompleted) {
                        first = false
                        toServer.writeFully(buf, 0, n)
                    } else {
                        synchronizedAppend(buf, n)
                    }
                }
            }
        }

        private val lock = kotlinx.coroutines.sync.Mutex()

        private suspend fun synchronizedAppend(
            buf: ByteArray,
            n: Int,
        ) {
            lock.lock()
            try {
                if (released.isCompleted) {
                    toServer.writeFully(buf, 0, n)
                    return
                }
                buffer.write(buf, 0, n)
                held = buffer.size
            } finally {
                lock.unlock()
            }
            grew.trySend(Unit)
        }

        suspend fun release() {
            lock.lock()
            try {
                val all = buffer.readByteArray()
                toServer.writeFully(all)
                released.complete(Unit)
            } finally {
                lock.unlock()
            }
        }
    }

    /**
     * ksl refuses ciphertext in the middle of a pass: the plaintext the pass decrypted before reaches the application, and
     * the failure comes after it, as for any failure after data.
     */
    @Test fun negative_plaintextBeforeARefusedFeedIsDelivered(): Unit =
        runBlocking {
            val pair = RelayPair()
            val (c, s) = both(pair)
            try {
                val ping = "ready".encodeToByteArray()
                s.output.writeFully(ping, 0, ping.size)
                s.output.flush()
                withTimeout(10.seconds) { c.input.readExactly(ping.size) }
                pair.manual = true
                // more than one feed's worth arrives in one read: the first feed takes the records that fit (and part of the
                // next), the second feed is refused
                var feeds = 0
                c.refuseFeedForTest = { ++feeds >= 2 }
                val data = ByteArray(4 * TlsConnection.MAX_PLAINTEXT_RECORD) { (it * 3).toByte() }
                s.output.writeFully(data, 0, data.size)
                s.output.flush()
                val sizes = pair.deliverAtLeast(TlsConnection.FEED_CHUNK + 1)
                // the plaintext of the records wholly inside the first feed (TLS 1.3: header 5, content type 1, tag 16)
                var fed = 0
                var plain = 0
                for (size in sizes) {
                    if (fed + size > TlsConnection.FEED_CHUNK) break
                    fed += size
                    plain += size - 22
                }
                assertTrue(plain > 0)
                val first = withTimeout(10.seconds) { c.input.readExactly(plain) }
                assertContentEquals(data.copyOf(plain), first)
                val e = kotlin.test.assertFails { withTimeout(10.seconds) { c.input.readExactly(1) } }
                val tls = generateSequence(e) { it.cause }.filterIsInstance<TlsException>().firstOrNull()
                assertTrue(tls?.message?.contains("refused ciphertext") == true, "got $e")
            } finally {
                c.close()
                s.close()
                relays.cancel()
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
