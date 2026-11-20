// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(io.kuicksilver.annotations.InternalKuicksilverApi::class)

package io.kuicksilver.tls

import io.ktor.utils.io.writeFully
import io.kuicksilver.native.KslLoader
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.seconds
import kotlin.time.TimeSource

/**
 * [TlsConnection.cancelInput]: the application reads no more and the session reads on, dropping what it decrypts. On a
 * client the drop stops past [TlsConnection.INPUT_DROP_LIMIT] (a response nobody reads is cut, not downloaded); on a server
 * it lasts until the client's close_notify (a reset could erase the last response). The pairs are [BoundedChannelPair]s,
 * a few KiB per direction, so what a side does not read holds its peer's writes and no buffer size decides the outcome.
 */
class TlsCancelInputTest {
    private val caches = TestCaches()

    @BeforeTest fun load() {
        KslLoader.ensureLoaded()
    }

    @AfterTest fun closeCaches() = caches.close()

    /** Writes [total] bytes of plaintext in 16 KiB pieces; false when a write failed (the peer went away). */
    private suspend fun TlsConnection.writeBytes(total: Int): Boolean =
        runCatching {
            val piece = ByteArray(16 * 1024)
            repeat(total / piece.size) { output.writeFully(piece) }
            output.flush()
        }.isSuccess

    /**
     * A client that cancels its input while the server sends 64 MiB drops at most its bound (plus the one pass of the
     * reader pump that crossed it) and then stops reading: its shutdown is over long before the server could have sent it
     * all, and the server's writes are still held. Before the bound, the client read and dropped all 64 MiB until the
     * server's close_notify, for as long as its shutdown waited.
     */
    @Test fun negative_aClientStopsDroppingPastTheBound(): Unit =
        runBlocking {
            val (cd, sd) = connect(TcpFixtures.client(), TcpFixtures.server(), BoundedChannelPair(), caches.new())
            val client = withTimeout(20.seconds) { cd.await() }
            val server = withTimeout(20.seconds) { sd.await() }
            try {
                client.cancelInput(kotlinx.io.IOException("the test reads no more"))
                val sent = async(Dispatchers.Default) { server.writeBytes(64 shl 20) }
                val started = TimeSource.Monotonic.markNow()
                withTimeout(30.seconds) { client.shutdown(drainTimeout = 30.seconds) }
                val took = started.elapsedNow()
                val dropped = client.droppedInputForTest
                assertTrue(dropped > TlsConnection.INPUT_DROP_LIMIT, "the client dropped $dropped bytes, not past its bound")
                assertTrue(
                    dropped <= TlsConnection.INPUT_DROP_LIMIT + TlsConnection.READ_CHUNK,
                    "the client dropped $dropped bytes, past its bound and the pass that crossed it",
                )
                assertTrue(took < 10.seconds, "the client's shutdown took $took behind input it would not read")
                assertFalse(sent.isCompleted, "the server sent all of the 64 MiB the client dropped")
                sent.cancelAndJoin()
            } finally {
                server.close()
                client.close()
            }
        }

    /**
     * A server that cancels its input while the client still sends (a request body nobody will read, 2 MiB here, eight
     * times the client's bound) drops all of it until the client's close_notify: its shutdown ends on that close_notify,
     * not by cutting, and the client's writes all go through. A cut there could reset away the server's last response.
     */
    @Test fun aServerDropsUntilTheClientsCloseNotify(): Unit =
        runBlocking {
            val (cd, sd) = connect(TcpFixtures.client(), TcpFixtures.server(), BoundedChannelPair(), caches.new())
            val client = withTimeout(20.seconds) { cd.await() }
            val server = withTimeout(20.seconds) { sd.await() }
            try {
                server.cancelInput(kotlinx.io.IOException("the test reads no more"))
                val total = 2 shl 20
                val clientDone =
                    launch(Dispatchers.Default) {
                        assertTrue(client.writeBytes(total), "the client's writes went through")
                        client.shutdown(drainTimeout = 30.seconds)
                    }
                withTimeout(30.seconds) { server.shutdown(drainTimeout = 30.seconds) }
                withTimeout(30.seconds) { clientDone.join() }
                assertEquals(total.toLong(), server.droppedInputForTest, "the server dropped all the client sent")
            } finally {
                server.close()
                client.close()
            }
        }

    /**
     * The server's tickets (RFC 9846 section 4.6.1; six after a full TCP handshake) that came before the client's cut are
     * still stored: the cut ends the reading, not the records the session read before it.
     */
    @Test fun aTicketReadBeforeTheCutIsStored(): Unit =
        runBlocking {
            val cache = caches.new()
            val (cd, sd) = connect(TcpFixtures.client(), TcpFixtures.server(), BoundedChannelPair(), cache)
            val client = withTimeout(20.seconds) { cd.await() }
            val server = withTimeout(20.seconds) { sd.await() }
            try {
                client.cancelInput(kotlinx.io.IOException("the test reads no more"))
                val sent = async(Dispatchers.Default) { server.writeBytes(64 shl 20) }
                withTimeout(30.seconds) { client.shutdown(drainTimeout = 30.seconds) }
                assertTrue(client.droppedInputForTest > TlsConnection.INPUT_DROP_LIMIT, "the client was cut past its bound")
                assertTrue(cache.size() > 0, "no ticket of the server was stored before the cut")
                sent.cancelAndJoin()
            } finally {
                server.close()
                client.close()
            }
        }
}
