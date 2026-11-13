// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.server

import io.ktor.server.engine.connector
import io.ktor.server.response.respondText
import io.ktor.server.routing.get
import io.ktor.server.routing.routing
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.withTimeout
import java.io.ByteArrayInputStream
import java.io.InputStream
import java.net.Socket
import java.security.KeyStore
import java.security.cert.CertificateFactory
import javax.net.ssl.SSLContext
import javax.net.ssl.TrustManagerFactory
import kotlin.test.Test
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.seconds
import kotlin.time.TimeSource

/**
 * A graceful stop with HTTP/1.1 keep-alive clients that keep their connection in a pool and do not read it until their
 * next request (OkHttp, the JDK's HttpClient): neither the TLS close_notify nor the FIN the server sends gets an answer.
 * Found by the engine interop bench (kuicksilver-engine-interop): `stop(3000, 6000)` took the whole 3 s with one such
 * client, idle or just answered, where an HTTP/2 client took 2 ms.
 *
 * RFC 9112 section 9.6 asks the closing server to keep reading "until it receives a corresponding close by the client, or
 * until the server is reasonably certain that its own TCP stack has received the client's acknowledgement of the
 * packet(s) containing the server's last response"; RFC 8446 section 6.1 lets it close its read side without the
 * peer's close_notify ("Both parties need not wait to receive a "close_notify" alert before closing their read side of
 * the connection"). The stop must not wait for a client that never answers, and the client must still read the whole
 * last response.
 */
class StopWithPooledClientsJvmTest {
    private fun clientSocket(
        port: Int,
        tls: Boolean,
    ): Socket {
        if (!tls) return Socket("127.0.0.1", port)
        val ca = CertificateFactory.getInstance("X.509").generateCertificate(ByteArrayInputStream(TestCerts.testCa))
        val store =
            KeyStore.getInstance("PKCS12").apply {
                load(null, null)
                setCertificateEntry("ca", ca)
            }
        val tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm()).apply { init(store) }
        val ctx = SSLContext.getInstance("TLS").apply { init(null, tmf.trustManagers, null) }
        return ctx.socketFactory.createSocket("127.0.0.1", port).also { (it as javax.net.ssl.SSLSocket).startHandshake() }
    }

    /** Reads one response with a Content-Length body and returns it whole (head and body). */
    private fun InputStream.readResponse(): String {
        val head = StringBuilder()
        while (!head.endsWith("\r\n\r\n")) {
            val b = read()
            check(b >= 0) { "the response ended inside its head: $head" }
            head.append(b.toChar())
        }
        val length = Regex("(?i)content-length: *(\\d+)").find(head)!!.groupValues[1].toInt()
        val body = readNBytes(length).decodeToString()
        return head.toString() + body
    }

    private fun stopWithAPooledClient(
        tls: Boolean,
        readsTheResponseFirst: Boolean,
    ) = serverTest {
        val answered = CompletableDeferred<Unit>()
        val module: io.ktor.server.application.Application.() -> Unit = {
            routing {
                get("/") {
                    call.respondText("ok")
                    answered.complete(Unit)
                }
            }
        }
        val server =
            kuicksilverServer(null, configure = {
                if (tls) {
                    tlsConnector(ServerFixtures.identity()) {
                        host = "127.0.0.1"
                        port = 0
                    }
                } else {
                    connector {
                        host = "127.0.0.1"
                        port = 0
                    }
                }
            }, module = module)
        server.startSuspend(false)
        val port =
            server.engine
                .resolvedConnectors()
                .first()
                .port
        clientSocket(port, tls).use { s ->
            s.getOutputStream().apply {
                write("GET / HTTP/1.1\r\nHost: server.test\r\n\r\n".encodeToByteArray())
                flush()
            }
            val first = if (readsTheResponseFirst) s.getInputStream().readResponse() else null
            answered.await()
            val start = TimeSource.Monotonic.markNow()
            // a grace period far above the bound: a stop that waits for the client fails here, not after 30 s
            withTimeout(5.seconds) { server.stopSuspend(30_000, 40_000) }
            val took = start.elapsedNow()
            assertTrue(took < 2.seconds, "tls=$tls read=$readsTheResponseFirst: the stop took $took")
            // the client still gets the whole last response: the server's close was no reset that destroys it
            val response = first ?: s.getInputStream().readResponse()
            assertTrue(response.startsWith("HTTP/1.1 200") && response.endsWith("ok"), response)
        }
    }

    /** An idle pooled connection: its response was read, the client waits for its next request. */
    @Test fun idlePooledConnectionDoesNotHoldTheStop() {
        stopWithAPooledClient(tls = false, readsTheResponseFirst = true)
        stopWithAPooledClient(tls = true, readsTheResponseFirst = true)
    }

    /** A connection whose response was just written and not yet read by the client. */
    @Test fun justAnsweredConnectionDoesNotHoldTheStop() {
        stopWithAPooledClient(tls = false, readsTheResponseFirst = false)
        stopWithAPooledClient(tls = true, readsTheResponseFirst = false)
    }
}
