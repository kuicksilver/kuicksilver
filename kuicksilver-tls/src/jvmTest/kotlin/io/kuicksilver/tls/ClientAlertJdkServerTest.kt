// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(io.kuicksilver.annotations.InternalKuicksilverApi::class)

package io.kuicksilver.tls

import io.ktor.utils.io.ByteChannel
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
import kotlin.test.assertNotNull
import kotlin.time.Duration.Companion.seconds

/**
 * RFC 9846 appendix A.1: "clients may send alerts that derive from post-ServerHello messages in the clear or with the early data
 * keys. If clients need to send such alerts, they SHOULD first rekey to the handshake keys if possible." The JDK's TLS 1.3 server
 * reads the client's records under the client handshake key from its ServerHello on and takes no alert in the clear there: when
 * the client refused the server's certificate with an alert in the clear (OpenSSL's middlebox compatibility mode), the server
 * failed with "Insufficient buffer remaining for AEAD cipher fragment (2)" and never learnt why. The alert is protected now, and
 * the server reports the client's refusal.
 */
class ClientAlertJdkServerTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

    @Test fun negative_aJdkServerReadsTheAlertOfAClientThatRefusesItsCertificate(): Unit =
        runBlocking {
            val cf = CertificateFactory.getInstance("X.509")
            val chain = arrayOf(cf.generateCertificate(ByteArrayInputStream(TestCerts.serverOtherCa)))
            val key = KeyFactory.getInstance("EC").generatePrivate(PKCS8EncodedKeySpec(TestCerts.serverOtherCaKey))
            val store = KeyStore.getInstance("PKCS12").apply { load(null, null) }
            store.setKeyEntry("server", key, CharArray(0), chain)
            val kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm()).apply { init(store, CharArray(0)) }
            val ssl = SSLContext.getInstance("TLSv1.3").apply { init(kmf.keyManagers, null, null) }
            val listener = ssl.serverSocketFactory.createServerSocket(0, 1, InetAddress.getLoopbackAddress()) as SSLServerSocket
            val serverFailure = CompletableDeferred<Throwable?>()
            val worker =
                thread(isDaemon = true, name = "jdk-tls13-server") {
                    serverFailure.complete(
                        runCatching {
                            (listener.accept() as SSLSocket).use { s ->
                                s.sslParameters = s.sslParameters.apply { protocols = arrayOf("TLSv1.3") }
                                s.startHandshake()
                            }
                        }.exceptionOrNull(),
                    )
                }
            val sock = Socket(InetAddress.getLoopbackAddress(), listener.localPort)
            try {
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
                    sock.shutdownOutput()
                }
                val clientFailure =
                    runCatching { withTimeout(10.seconds) { TlsConnection.client(fromNet, toNet, TcpFixtures.client()) } }
                        .exceptionOrNull()
                assertNotNull(clientFailure, "the client refuses a chain from another CA")
                val failure = assertNotNull(withTimeout(10.seconds) { serverFailure.await() }, "the server's handshake fails")
                val messages = generateSequence(failure) { it.cause }.joinToString(" / ") { it.message.orEmpty() }
                assertContains(messages, "Received fatal alert", message = "the server read the client's alert: $messages")
            } finally {
                sock.close()
                listener.close()
                worker.join(5_000)
                scope.cancel()
            }
        }
}
