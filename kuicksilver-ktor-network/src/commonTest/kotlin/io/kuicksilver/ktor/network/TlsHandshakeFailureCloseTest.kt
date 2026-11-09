// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(kotlinx.coroutines.ExperimentalCoroutinesApi::class)

package io.kuicksilver.ktor.network

import io.ktor.network.sockets.InetSocketAddress
import io.ktor.network.sockets.Socket
import io.ktor.network.sockets.SocketAddress
import io.ktor.network.sockets.openWriteChannel
import io.ktor.utils.io.ByteChannel
import io.ktor.utils.io.ReaderJob
import io.ktor.utils.io.WriterJob
import io.ktor.utils.io.cancel
import io.ktor.utils.io.copyTo
import io.ktor.utils.io.readBuffer
import io.ktor.utils.io.reader
import io.ktor.utils.io.writeFully
import io.ktor.utils.io.writer
import io.kuicksilver.native.KslLoader
import io.kuicksilver.tls.TlsConnection
import io.kuicksilver.tls.TlsException
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CompletableJob
import kotlinx.coroutines.Job
import kotlinx.coroutines.async
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.test.currentTime
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.withTimeout
import kotlinx.coroutines.withTimeoutOrNull
import kotlinx.io.IOException
import kotlinx.io.readByteArray
import kotlin.coroutines.ContinuationInterceptor
import kotlin.coroutines.CoroutineContext
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.seconds

/**
 * A failed handshake closes its socket in stages, as RFC 9112 section 9.6 describes for an HTTP server's last response:
 * the alert and the FIN first, then what the peer still sends is read and dropped until it closes too (bounded in time
 * and bytes), and only then the socket closes. Closed at once, the input the peer sent after its flight (a TLS 1.3
 * client's request right after its Finished) meets a reset, which can erase the alert from the peer's receive buffer
 * before the peer read it (Windows discards what it has not delivered): the client saw a reset instead of the alert.
 */
class TlsHandshakeFailureCloseTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    /** A socket whose peer is the test: [toServer] is what the peer sends, [fromServer] what the socket sent, ended by its FIN. */
    private class PeerSocket(
        dispatcher: CoroutineContext,
    ) : Socket {
        override val socketContext: CompletableJob = Job()
        override val coroutineContext: CoroutineContext = socketContext + dispatcher
        override val localAddress: SocketAddress = InetSocketAddress("127.0.0.1", 1)
        override val remoteAddress: SocketAddress = InetSocketAddress("127.0.0.1", 2)
        val toServer = ByteChannel()
        val fromServer = ByteChannel()
        val closed = CompletableDeferred<Unit>()

        override fun attachForReading(channel: ByteChannel): WriterJob = writer(coroutineContext, channel) { toServer.copyTo(this.channel) }

        override fun attachForWriting(channel: ByteChannel): ReaderJob =
            reader(coroutineContext, channel) {
                this.channel.copyTo(fromServer)
                fromServer.flushAndClose()
            }

        override fun close() {
            closed.complete(Unit)
            toServer.cancel(null)
            socketContext.complete()
        }

        override fun dispose() = close()
    }

    /** The peer's flight: a ClientHello with an empty body, which the server answers with a fatal alert. */
    private suspend fun PeerSocket.sendMalformedClientHello() {
        toServer.writeFully(byteArrayOf(0x16, 0x03, 0x01, 0x00, 0x04, 0x01, 0x00, 0x00, 0x00))
        toServer.flush()
    }

    /** What the server sent up to its FIN, checked to be an alert record. */
    private suspend fun PeerSocket.readAlertAndFin(): ByteArray {
        val sent = fromServer.readBuffer().readByteArray()
        val hex = sent.joinToString(" ") { (it.toInt() and 0xff).toString(16) }
        assertTrue(sent.size >= 7 && sent[0] == ALERT_RECORD, "an alert record, then the FIN: $hex")
        return sent
    }

    @Test fun negative_aFailedHandshakeReadsWhatThePeerStillSendsUntilItsCloseBeforeClosing() =
        runTest {
            val peer = PeerSocket(coroutineContext[ContinuationInterceptor]!!)
            val handshake = async { runCatching { peer.tlsServer(serverConfig()) }.exceptionOrNull() }
            peer.sendMalformedClientHello()
            peer.readAlertAndFin()
            assertFalse(peer.closed.isCompleted, "closed while the peer may still be sending: what it sends would meet a reset")
            // what the peer sent after its flight, before it read the alert, is read and dropped
            peer.toServer.writeFully(ByteArray(16 * 1024))
            peer.toServer.flush()
            assertFalse(peer.closed.isCompleted, "closed before the peer's own close")
            val start = currentTime
            peer.toServer.flushAndClose()
            peer.closed.await()
            assertEquals(start, currentTime, "the socket closes as soon as the peer has closed")
            assertIs<TlsException>(handshake.await())
        }

    @Test fun aFailedHandshakeWaitsForThePeersCloseForTwoSecondsAtMost() =
        runTest {
            val peer = PeerSocket(coroutineContext[ContinuationInterceptor]!!)
            val handshake = async { runCatching { peer.tlsServer(serverConfig()) }.exceptionOrNull() }
            peer.sendMalformedClientHello()
            peer.readAlertAndFin()
            val start = currentTime
            peer.closed.await()
            assertEquals(TlsSocket.ALERT_LINGER.inWholeMilliseconds, currentTime - start)
            assertIs<TlsException>(handshake.await())
        }

    @Test fun aFailedHandshakeDropsAtMostItsByteCapOfWhatThePeerSends() =
        runTest {
            val peer = PeerSocket(coroutineContext[ContinuationInterceptor]!!)
            val handshake = async { runCatching { peer.tlsServer(serverConfig()) }.exceptionOrNull() }
            peer.sendMalformedClientHello()
            peer.readAlertAndFin()
            val start = currentTime
            peer.toServer.writeFully(ByteArray(TlsSocket.ALERT_LINGER_BYTES.toInt()))
            peer.toServer.flush()
            peer.closed.await()
            assertEquals(start, currentTime, "closed once the cap was read, without waiting for the peer")
            assertIs<TlsException>(handshake.await())
        }

    /** The handshake's own deadline passed: the peer is silent, and the socket closes at once, with no wait for it. */
    @Test fun aHandshakeThatTimedOutClosesWithoutWaitingForThePeer() =
        runTest {
            val peer = PeerSocket(coroutineContext[ContinuationInterceptor]!!)
            val handshake = async { runCatching { peer.tlsServer(serverConfig { handshakeTimeout = 1.seconds }) }.exceptionOrNull() }
            peer.closed.await()
            assertEquals(1.seconds.inWholeMilliseconds, currentTime, "closed at the handshake's deadline")
            assertIs<TlsException.Protocol>(handshake.await())
        }

    /** A caller's deadline that passes during the wait for the peer leaves the handshake's own failure the one thrown. */
    @Test fun aCallersDeadlineDuringTheWaitKeepsTheHandshakeFailure() =
        runTest {
            val peer = PeerSocket(coroutineContext[ContinuationInterceptor]!!)
            val handshake =
                async { runCatching { withTimeoutOrNull(500.milliseconds) { peer.tlsServer(serverConfig()) } } }
            peer.sendMalformedClientHello()
            peer.readAlertAndFin()
            peer.closed.await()
            assertEquals(500L, currentTime, "the caller's deadline ended the wait")
            val result = handshake.await()
            assertIs<TlsException>(result.exceptionOrNull(), "the handshake's failure was replaced: $result")
        }

    /** A client's failed handshake waits for the server's close for [TlsSocket.CLIENT_ALERT_LINGER] at most. */
    @Test fun aClientsFailedHandshakeWaitsForTheServerBriefly() =
        runTest {
            val peer = PeerSocket(coroutineContext[ContinuationInterceptor]!!)
            val handshake = async { runCatching { peer.tls(clientConfig()) }.exceptionOrNull() }
            // a ServerHello with an empty body, which the client answers with a fatal alert
            peer.toServer.writeFully(byteArrayOf(0x16, 0x03, 0x03, 0x00, 0x04, 0x02, 0x00, 0x00, 0x00))
            peer.toServer.flush()
            val sent = peer.fromServer.readBuffer().readByteArray() // the ClientHello, the alert, then the FIN
            assertTrue(sent.isNotEmpty() && sent[0] == HANDSHAKE_RECORD, "the ClientHello first")
            val start = currentTime
            peer.closed.await()
            assertEquals(TlsSocket.CLIENT_ALERT_LINGER.inWholeMilliseconds, currentTime - start)
            assertIs<TlsException>(handshake.await())
        }

    /**
     * After the handshake: an application stream that failed ends with the fatal alert internal_error and a FIN (RFC 9846
     * section 6.1), then the socket reads and drops what the peer still sends until it closes, as after a failed handshake.
     */
    @Test fun negative_aFailedStreamReadsWhatThePeerStillSendsUntilItsCloseBeforeClosing() =
        runBlocking {
            withTimeout(20.seconds) {
                val peer = PeerSocket(coroutineContext[ContinuationInterceptor]!!)
                val clientIn = ByteChannel()
                val fin = CompletableDeferred<Unit>()
                launch {
                    peer.fromServer.copyTo(clientIn)
                    fin.complete(Unit)
                    clientIn.flushAndClose()
                }
                val server = async { peer.tlsServer(serverConfig()) }
                val clientJob = Job()
                try {
                    TlsConnection.client(clientIn, peer.toServer, clientConfig(), clientJob)
                    val out = server.await().openWriteChannel()
                    out.writeFully("part of a response".encodeToByteArray())
                    out.flush()
                    out.cancel(IOException("the handler failed"))
                    fin.await() // the alert, then the FIN
                    assertFalse(peer.closed.isCompleted, "closed while the peer may still be sending: what it sends would meet a reset")
                    peer.toServer.writeFully(ByteArray(16 * 1024))
                    peer.toServer.flush()
                    assertFalse(peer.closed.isCompleted, "closed before the peer's own close")
                    peer.toServer.flushAndClose()
                    peer.closed.await()
                } finally {
                    clientJob.cancel()
                }
            }
        }

    private companion object {
        /** The record content type of an alert (RFC 9846 section 5.1). */
        const val ALERT_RECORD: Byte = 21

        /** The record content type of a handshake message. */
        const val HANDSHAKE_RECORD: Byte = 22
    }
}
