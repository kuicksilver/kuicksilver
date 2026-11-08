// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(io.kuicksilver.annotations.InternalKuicksilverApi::class)

package io.kuicksilver.tls

import io.ktor.utils.io.ByteChannel
import io.ktor.utils.io.ByteReadChannel
import io.ktor.utils.io.readAvailable
import io.ktor.utils.io.writeFully
import io.kuicksilver.native.KslLoader
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import java.io.ByteArrayInputStream
import java.net.InetAddress
import java.net.Socket
import java.security.KeyFactory
import java.security.KeyStore
import java.security.cert.CertificateFactory
import java.security.spec.PKCS8EncodedKeySpec
import javax.net.ssl.KeyManagerFactory
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLServerSocket
import javax.net.ssl.SSLSocket
import kotlin.concurrent.thread
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertContains
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.seconds

/**
 * RFC 9113 section 9.2.1: "A deployment of HTTP/2 over TLS 1.2 MUST disable renegotiation. An endpoint MUST treat a TLS
 * renegotiation as a connection error (Section 5.4.1) of type PROTOCOL_ERROR." The server is the JDK's own TLS 1.2 stack
 * (a server ksl cannot be made to ask for renegotiation), which sends a HelloRequest when its handshake is started again.
 * ksl refuses the renegotiation either way; on `h2` the input fails after the data that came before it, on any other protocol
 * the connection goes on.
 */
class RenegotiationJvmTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    /** A JDK TLS 1.2 server on loopback that sends "before", a HelloRequest and "after", then waits for [release]. */
    private class JdkServer(
        alpn: String,
    ) : AutoCloseable {
        private val socket: SSLServerSocket
        val release = CompletableDeferred<Unit>()
        val port: Int get() = socket.localPort
        private val worker: Thread

        init {
            val cf = CertificateFactory.getInstance("X.509")
            val chain = arrayOf(cf.generateCertificate(ByteArrayInputStream(TestCerts.server)))
            val key = KeyFactory.getInstance("EC").generatePrivate(PKCS8EncodedKeySpec(TestCerts.serverKey))
            val store = KeyStore.getInstance("PKCS12").apply { load(null, null) }
            store.setKeyEntry("server", key, CharArray(0), chain)
            val kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm()).apply { init(store, CharArray(0)) }
            val ssl = SSLContext.getInstance("TLSv1.2").apply { init(kmf.keyManagers, null, null) }
            socket = ssl.serverSocketFactory.createServerSocket(0, 1, InetAddress.getLoopbackAddress()) as SSLServerSocket
            worker =
                thread(isDaemon = true, name = "jdk-tls12-server") {
                    runCatching {
                        (socket.accept() as SSLSocket).use { s ->
                            s.sslParameters =
                                s.sslParameters.apply {
                                    protocols = arrayOf("TLSv1.2")
                                    applicationProtocols = arrayOf(alpn)
                                }
                            s.startHandshake()
                            val out = s.outputStream
                            out.write("before".encodeToByteArray())
                            out.flush()
                            s.startHandshake() // established: a HelloRequest, the JDK does not wait for the answer
                            out.write("after".encodeToByteArray())
                            out.flush()
                            runBlocking { release.await() }
                        }
                    }
                }
        }

        override fun close() {
            release.complete(Unit)
            socket.close()
            worker.join(5_000)
        }
    }

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

    /** A TLS 1.2 client over a loopback socket to [port], offering [alpn]. */
    private suspend fun client(
        port: Int,
        alpn: String,
    ): TlsConnection {
        val sock = Socket(InetAddress.getLoopbackAddress(), port)
        val fromNet = ByteChannel(autoFlush = true)
        val toNet = ByteChannel(autoFlush = true)
        scope.launch {
            val buf = ByteArray(16 * 1024)
            runCatching {
                while (true) {
                    val n = sock.getInputStream().read(buf)
                    if (n < 0) break
                    fromNet.writeFully(buf, 0, n)
                }
            }
            fromNet.flushAndClose()
        }
        scope.launch {
            val buf = ByteArray(16 * 1024)
            runCatching {
                while (true) {
                    val n = toNet.readAvailable(buf, 0, buf.size)
                    if (n < 0) break
                    sock.getOutputStream().write(buf, 0, n)
                    sock.getOutputStream().flush()
                }
            }
            sock.close()
        }
        return TlsConnection.client(
            fromNet,
            toNet,
            TcpFixtures.client {
                versions = TlsVersions.Tls12And13
                this.alpn = listOf(alpn)
            },
        )
    }

    private suspend fun ByteReadChannel.readText(n: Int): String {
        val b = ByteArray(n)
        var off = 0
        while (off < n) {
            val r = readAvailable(b, off, n - off)
            check(r >= 0) { "input ended after $off bytes" }
            off += r
        }
        return b.decodeToString()
    }

    @Test fun negative_renegotiationOnH2FailsTheInputAfterTheDataBeforeIt(): Unit =
        runBlocking {
            JdkServer("h2").use { server ->
                val c = withTimeout(10.seconds) { client(server.port, "h2") }
                try {
                    assertEquals(TlsVersion.Tls12, c.protocolVersion)
                    assertEquals("h2", c.negotiatedAlpn)
                    assertEquals("before", withTimeout(10.seconds) { c.input.readText(6) })
                    val failure =
                        runCatching { withTimeout(10.seconds) { c.input.readText(5) } }.exceptionOrNull()
                    var cause = failure
                    while (cause != null && cause !is TlsException) cause = cause.cause
                    assertIs<TlsException.Protocol>(cause, "the input failed with $failure, not the renegotiation")
                    assertContains(cause.message.orEmpty(), "renegotiation")
                    assertTrue(c.renegotiationAttempted, "the attempt is reported")
                } finally {
                    c.close()
                    scope.cancel()
                }
            }
        }

    @Test fun renegotiationElsewhereIsRefusedAndTheConnectionGoesOn(): Unit =
        runBlocking {
            JdkServer("http/1.1").use { server ->
                val c = withTimeout(10.seconds) { client(server.port, "http/1.1") }
                try {
                    assertEquals(TlsVersion.Tls12, c.protocolVersion)
                    assertEquals("before", withTimeout(10.seconds) { c.input.readText(6) })
                    assertEquals("after", withTimeout(10.seconds) { c.input.readText(5) }, "the data after the HelloRequest arrives")
                    assertTrue(c.renegotiationAttempted, "the attempt is reported")
                    assertFalse(c.input.isClosedForRead)
                } finally {
                    c.close()
                    scope.cancel()
                }
            }
        }
}
