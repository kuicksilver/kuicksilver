// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)

package io.kuicksilver.ktor.client

import io.ktor.client.request.get
import io.ktor.client.statement.bodyAsText
import io.ktor.network.selector.SelectorManager
import io.ktor.network.sockets.InetSocketAddress
import io.ktor.network.sockets.openReadChannel
import io.ktor.network.sockets.openWriteChannel
import io.ktor.server.response.respondText
import io.ktor.server.routing.get
import io.ktor.server.routing.routing
import io.ktor.utils.io.ByteReadChannel
import io.ktor.utils.io.copyAndClose
import io.ktor.utils.io.readAvailable
import io.ktor.utils.io.readByteArray
import io.ktor.utils.io.writeByteArray
import io.ktor.utils.io.writeFully
import io.kuicksilver.ktor.network.bindTcp
import io.kuicksilver.ktor.network.connectTcp
import io.kuicksilver.native.KslLoader
import io.kuicksilver.tls.TlsException
import io.kuicksilver.tls.TlsVersion
import io.kuicksilver.tls.TlsVersions
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.IO
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.launch
import kotlinx.coroutines.withTimeout
import kotlinx.coroutines.withTimeoutOrNull
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.seconds

/**
 * Downgrade protection of the default client (TLS 1.3, or 1.2 with a server without 1.3) against a server that has both:
 * RFC 9846 section 4.2.3 (RFC 8446 section 4.1.3). An active attacker that hides the client's TLS 1.3 offer (here a relay
 * that renames the ClientHello's `supported_versions` extension, lengths unchanged) makes the server answer with TLS 1.2,
 * and that ServerHello carries the downgrade sentinel, on which the client ends the handshake ("MUST check ... If a match
 * is found, the client MUST abort the handshake with an "illegal_parameter" alert"; OpenSSL's "inappropriate fallback")
 * before anything else: never a TLS 1.2 connection with a server that has 1.3.
 */
class ClientTls12DowngradeTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    private fun hex(b: ByteArray) = b.joinToString("") { (it.toInt() and 0xff).toString(16).padStart(2, '0') }

    private suspend fun readRecord(input: ByteReadChannel): ByteArray {
        val head = input.readByteArray(5)
        val len = ((head[3].toInt() and 0xff) shl 8) or (head[4].toInt() and 0xff)
        return head + input.readByteArray(len)
    }

    /**
     * [record] (one ClientHello) with its `supported_versions` extension (43) renamed to the GREASE type 0x0a0a, which a
     * server ignores (RFC 8701): it sees a client that offers TLS 1.2 at most. Null when the extension is not there.
     */
    private fun stripTls13Offer(record: ByteArray): ByteArray? {
        val r = record.copyOf()
        var p = 5 + 4 + 2 + 32 // record header, handshake header, legacy_version, random

        fun u8() = r[p++].toInt() and 0xff

        fun u16() = (u8() shl 8) or u8()
        val sessionId = u8()
        p += sessionId
        val suites = u16()
        p += suites
        val compression = u8()
        p += compression
        val end = p + 2 + u16()
        while (p + 4 <= end) {
            val at = p
            val type = u16()
            val len = u16()
            if (type == 0x2b) {
                r[at] = 0x0a
                r[at + 1] = 0x0a
                return r
            }
            p += len
        }
        return null
    }

    /** What a relay saw: the server's first record (its ServerHello) of each connection, and every byte the client sent after its ClientHello. */
    private class Seen {
        val serverHellos = Channel<ByteArray>(Channel.UNLIMITED)
        val fromClient = Channel<ByteArray>(Channel.UNLIMITED)
        private var clientBytes = ByteArray(0)

        /** Waits (bounded) until the client's bytes after its ClientHello contain [record]. */
        suspend fun awaitFromClient(record: ByteArray): Boolean =
            withTimeoutOrNull(10.seconds) {
                while (!contains(clientBytes, record)) clientBytes += fromClient.receive()
                true
            } ?: false

        private fun contains(
            hay: ByteArray,
            needle: ByteArray,
        ): Boolean = (0..hay.size - needle.size).any { i -> needle.indices.all { hay[i + it] == needle[it] } }
    }

    /**
     * A relay to [originPort] that passes the first record of each connection through [rewrite], hands the server's first
     * record (its ServerHello) and the client's later bytes (an alert it sends) to [Seen].
     */
    private suspend fun relay(
        originPort: Int,
        rewrite: (ByteArray) -> ByteArray,
        block: suspend (Int, Seen) -> Unit,
    ) {
        val selector = SelectorManager(Dispatchers.IO)
        val listener = bindTcp(selector, "127.0.0.1", 0)
        val seen = Seen()
        try {
            coroutineScope {
                val job =
                    launch {
                        while (true) {
                            val s = listener.accept()
                            launch {
                                s.use {
                                    val input = s.openReadChannel()
                                    val output = s.openWriteChannel(autoFlush = true)
                                    connectTcp(selector, InetSocketAddress("127.0.0.1", originPort)).use { o ->
                                        val oIn = o.openReadChannel()
                                        val oOut = o.openWriteChannel(autoFlush = true)
                                        oOut.writeByteArray(rewrite(readRecord(input)))
                                        coroutineScope {
                                            launch {
                                                runCatching {
                                                    val buf = ByteArray(4096)
                                                    while (true) {
                                                        val n = input.readAvailable(buf, 0, buf.size)
                                                        if (n < 0) break
                                                        seen.fromClient.send(buf.copyOf(n))
                                                        oOut.writeFully(buf, 0, n)
                                                    }
                                                }
                                                runCatching { oOut.flushAndClose() }
                                            }
                                            runCatching {
                                                val first = readRecord(oIn)
                                                seen.serverHellos.send(first)
                                                output.writeByteArray(first)
                                                oIn.copyAndClose(output)
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                block((listener.localAddress as InetSocketAddress).port, seen)
                job.cancel()
            }
        } finally {
            listener.close()
            selector.close()
        }
    }

    @Test fun negative_aStrippedTls13OfferIsNotDowngradedTo12() =
        clientTest {
            val (server, port) =
                testServer(tls = { tls { versions = TlsVersions.Tls12And13 } }) { routing { get("/") { call.respondText("ok") } } }
            try {
                // control: through the relay unchanged, the default client and the server agree on TLS 1.3
                relay(port, { it }) { relayPort, seen ->
                    testClient().use { c ->
                        val r = c.get("https://127.0.0.1:$relayPort/")
                        assertEquals("ok", r.bodyAsText())
                        val d = assertIs<TcpConnectionSnapshot>(assertNotNull(r.kuicksilverDiagnostics).connection)
                        assertEquals(TlsVersion.Tls13, d.tlsVersion)
                    }
                    assertEquals("0303", hex(withTimeout(10.seconds) { seen.serverHellos.receive() }.copyOfRange(9, 11)))
                }
                // the attack: the server sees a TLS 1.2 client, answers TLS 1.2 with the sentinel; the client refuses it
                relay(port, { assertNotNull(stripTls13Offer(it), "supported_versions in the ClientHello") }) { relayPort, seen ->
                    testClient().use { c ->
                        val e = assertFailsWith<Throwable> { c.get("https://127.0.0.1:$relayPort/") }
                        val p = generateSequence(e) { it.cause }.filterIsInstance<TlsException.Protocol>().firstOrNull()
                        // ERR_LIB_SSL (20), SSL_R_INAPPROPRIATE_FALLBACK (373): the sentinel, not a failed Finished
                        assertEquals((20 shl 16) or 373, p?.openSslCode, "the downgrade sentinel ended it: $e")
                    }
                    // on the wire: the client's fatal illegal_parameter (47), in the clear as TLS 1.2 has it before ChangeCipherSpec
                    assertTrue(seen.awaitFromClient(ALERT_ILLEGAL_PARAMETER), "the client sent illegal_parameter")
                    val hello = withTimeout(10.seconds) { seen.serverHellos.receive() }
                    assertEquals(2, hello[5].toInt(), "a ServerHello")
                    assertEquals("0303", hex(hello.copyOfRange(9, 11)), "the server answered TLS 1.2")
                    // RFC 9846 section 4.2.3: the last 8 bytes of ServerHello.random, "DOWNGRD" and 01
                    assertEquals("444f574e47524401", hex(hello.copyOfRange(35, 43)))
                }
            } finally {
                server.stopSuspend(0, 0)
            }
        }

    /**
     * The same stripped offer from a client with `versions = Tls13` meets no TLS 1.2 at all: it offers TLS 1.3 suites alone,
     * so the server, which now sees a TLS 1.2 client, has no suite in common and ends it with handshake_failure (40) before
     * any ServerHello. Had a server answered TLS 1.2 anyway, the client would send protocol_version (70): OpenSSL checks the
     * version against the client's range before the sentinel (`ssl_choose_client_version`; docs/spec/rfc/9846.md).
     */
    @Test fun negative_tls13OnlyClientNeverSpeaksTls12() =
        clientTest {
            val (server, port) =
                testServer(tls = { tls { versions = TlsVersions.Tls12And13 } }) { routing { get("/") { call.respondText("ok") } } }
            try {
                relay(port, { assertNotNull(stripTls13Offer(it)) }) { relayPort, seen ->
                    testClient(engine = { tls { versions = TlsVersions.Tls13 } }).use { c ->
                        val e = assertFailsWith<Throwable> { c.get("https://127.0.0.1:$relayPort/") }
                        val alert = generateSequence(e) { it.cause }.filterIsInstance<TlsException.AlertReceived>().firstOrNull()
                        assertEquals(40, alert?.code, "the server's handshake_failure: $e")
                    }
                    // the server's first record is that alert, not a ServerHello
                    val first = withTimeout(10.seconds) { seen.serverHellos.receive() }
                    assertEquals("15030300020228", hex(first.copyOfRange(0, 7)))
                }
            } finally {
                server.stopSuspend(0, 0)
            }
        }

    private companion object {
        /** A fatal alert record before ChangeCipherSpec: illegal_parameter (47). */
        val ALERT_ILLEGAL_PARAMETER = byteArrayOf(0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x2f)
    }
}
