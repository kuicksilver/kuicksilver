// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)

package io.kuicksilver.ktor.server.browser

import io.ktor.http.ContentType
import io.ktor.server.engine.embeddedServer
import io.ktor.server.request.receiveText
import io.ktor.server.response.respondText
import io.ktor.server.routing.get
import io.ktor.server.routing.post
import io.ktor.server.routing.routing
import io.ktor.utils.io.copyTo
import io.ktor.utils.io.writeFully
import io.kuicksilver.http3.WebTransportCloseInfo
import io.kuicksilver.http3.WebTransportSession
import io.kuicksilver.ktor.server.Kuicksilver
import io.kuicksilver.ktor.server.webTransport
import io.kuicksilver.native.KslLoader
import io.kuicksilver.quic.ConnectionInfo
import io.kuicksilver.quic.ConnectionListener
import io.kuicksilver.quic.QuicException
import io.kuicksilver.quic.qlog.AsyncQlogSink
import io.kuicksilver.quic.qlog.DirectoryQlogSink
import io.kuicksilver.tls.TlsIdentity
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.cancelChildren
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import kotlinx.coroutines.withTimeoutOrNull
import org.junit.jupiter.api.Assumptions.assumeTrue
import java.io.File
import java.net.URLEncoder
import java.nio.file.Files
import java.nio.file.StandardCopyOption
import java.security.MessageDigest
import java.security.cert.CertificateFactory
import java.util.Base64
import java.util.concurrent.ConcurrentLinkedQueue
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.seconds

/**
 * The server half of a by-hand WebTransport check in a browser that cannot be driven headless with a pinned certificate
 * (Firefox; `tools/interop/wt-firefox-manual.sh` runs both halves). It serves the page `wt/index.html` of
 * [ChromeWebTransportTest] with the same `/result`, `/wt/echo` and `/wt/server-close` routes, on `127.0.0.1` (HTTP/1.1
 * over TLS for the page, HTTP/3 for the sessions, one port), with a certificate given as PEM files: valid for at most
 * 14 days and not RSA, so the page's `?hash=` admits it through `serverCertificateHashes`.
 *
 * Opt-in: runs only with `-Pkuicksilver.manualWebTransport=true`. Properties (Gradle `-P`, forwarded to the test JVM):
 * `kuicksilver.manualWebTransport.cert` and `.key` (PEM chain and PKCS#8 key, required), `.port` (0, the default, picks a
 * free one), `.dir` (where `ready` is written with the port once the server listens, and `result.json` and `server.txt`
 * once the page has posted), `.timeoutSeconds` (how long to wait for the page, 600 by default). It prints the URL, waits
 * for the page's POST, prints the JSON, checks every step and stops.
 *
 * Diagnostics, with `.dir` only: a qlog trace per QUIC connection in `<dir>/qlog`, and `<dir>/server-events.txt`, a
 * timeline (wall clock in microseconds, comparable with Firefox's qlog) of each connection's open, handshake and close
 * (who closed, the code, its stats), each session's request headers and the client's SETTINGS as the connection saw them,
 * and how each session ended: its code, reason and cause chain. The cause tells the end apart: none with code 0 is the
 * client's FIN without a WT_CLOSE_SESSION, a stream error is a RESET_STREAM (or our STOP_SENDING), a lost connection is a
 * CONNECTION_CLOSE (or a timeout) before any capsule was read.
 */
class ManualWebTransportServer {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    @Test fun browserByHand() {
        assumeTrue(
            System.getProperty(PREFIX) == "true",
            "the manual WebTransport server runs with -P$PREFIX=true (tools/interop/wt-firefox-manual.sh)",
        )
        val certFile = File(requireNotNull(prop("cert")) { "-P$PREFIX.cert=<PEM certificate> is required" })
        val keyFile = File(requireNotNull(prop("key")) { "-P$PREFIX.key=<PEM PKCS#8 key> is required" })
        val port = prop("port")?.toInt() ?: 0
        val dir = prop("dir")?.let(::File)
        val wait = (prop("timeoutSeconds")?.toLong() ?: 600L).seconds
        val certPem = certFile.readText()
        val hash = certificateHash(certPem)
        val identity = TlsIdentity.fromPem(certPem, keyFile.readText().toCharArray())
        val page = javaClass.getResource("/wt/index.html")!!.readText()
        val result = CompletableDeferred<String>()
        val clientClose = CompletableDeferred<WebTransportCloseInfo>()
        val connect = CompletableDeferred<String>()
        val events = Timeline()
        val qlogSink = dir?.let { AsyncQlogSink(DirectoryQlogSink(File(it, "qlog").path)) }
        lateinit var peerSettings: suspend () -> String

        /** The session's headers and the client's SETTINGS on arrival, and its end once it ends, in [events]. */
        @OptIn(kotlinx.coroutines.ExperimentalCoroutinesApi::class)
        suspend fun observe(
            route: String,
            session: WebTransportSession,
        ) {
            events.add("$route: session ${session.sessionId} accepted, protocol=${session.protocol}")
            for ((name, value) in session.headers.fields) events.add("$route:   request header $name: $value")
            events.add("$route:   ${peerSettings()}")
            session.closed.invokeOnCompletion {
                val info = session.closed.getCompleted()
                events.add(
                    "$route: session ${session.sessionId} ended: code=${info.code} reason=\"${info.reason}\" cause=${chain(info.cause)}",
                )
            }
        }
        val server =
            embeddedServer(Kuicksilver, configure = {
                tlsConnector(identity) {
                    host = "127.0.0.1"
                    this.port = port
                }
                webTransport = true
                qlog = qlogSink
                connectionListener = events
            }) {
                routing {
                    get("/wt/index.html") { call.respondText(page, ContentType.Text.Html) }
                    post("/result") {
                        result.complete(call.receiveText())
                        call.respondText("ok")
                    }
                    webTransport("/wt/echo") { session ->
                        observe("/wt/echo", session)
                        connect.complete(
                            "sec-webtransport-http3-draft02=${session.headers["sec-webtransport-http3-draft02"]} " +
                                "user-agent=${session.headers["user-agent"]}",
                        )
                        coroutineScope {
                            launch {
                                runCatching {
                                    while (true) {
                                        val st = session.acceptBidi()
                                        launch {
                                            st.input.copyTo(st.output)
                                            st.output.flushAndClose()
                                        }
                                    }
                                }
                            }
                            launch { runCatching { while (true) session.sendDatagram(session.receiveDatagram()) } }
                            launch {
                                val uni = session.openUni()
                                uni.output.writeFully("uni-hello".encodeToByteArray())
                                uni.output.flushAndClose()
                            }
                            clientClose.complete(session.closed.await())
                            coroutineContext.cancelChildren()
                        }
                    }
                    webTransport("/wt/server-close") { session ->
                        observe("/wt/server-close", session)
                        session.close(9, "server-bye")
                    }
                }
            }
        peerSettings = {
            server.engine.h3ListenersForProbe
                .flatMap { it.live() }
                .joinToString("; ", prefix = "client SETTINGS per live connection: ") { c ->
                    val ps = c.peerSettings.value
                    if (ps == null) "none yet" else "$ps unknown=${ps.unknown.entries.joinToString { (k, v) -> "0x${k.toString(16)}=$v" }}"
                }
        }
        runBlocking {
            server.startSuspend(wait = false)
            try {
                val bound =
                    server.engine
                        .resolvedConnectors()
                        .first()
                        .port
                val url = "https://localhost:$bound/wt/index.html?hash=${URLEncoder.encode(hash, Charsets.UTF_8)}"
                println("Manual WebTransport server ready on 127.0.0.1:$bound (TCP and UDP); open $url")
                dir?.let { writeAtomically(File(it, "ready"), "$bound\n$url\n") }
                val json = withTimeout(wait) { result.await() }
                val seenClose = withTimeoutOrNull(10.seconds) { clientClose.await() }
                val seenConnect = withTimeoutOrNull(1.seconds) { connect.await() }
                val closeText = seenClose?.let { "${it.code} \"${it.reason}\" (cause ${chain(it.cause)})" }
                val serverSide = "connect: $seenConnect\nclientClose seen by the server: $closeText\n"
                println("Browser WebTransport result: $json")
                print(serverSide)
                dir?.let {
                    writeAtomically(File(it, "server.txt"), serverSide)
                    writeAtomically(File(it, "result.json"), json + "\n")
                }
                for (step in STEPS) assertTrue("\"$step\":\"ok\"" in json, "step $step in $json")
                assertTrue("\"closeInfo\":{\"code\":9,\"reason\":\"server-bye\"}" in json, json)
                val closed = assertNotNull(seenClose, "the server did not see the page close its session")
                assertEquals(7L to "bye", closed.code to closed.reason)
            } finally {
                server.stopSuspend(100, 1000)
                qlogSink?.close()
                val timeline = events.text()
                print("Server events:\n$timeline")
                dir?.let { writeAtomically(File(it, "server-events.txt"), timeline) }
            }
        }
    }

    /** The QUIC connections' lifecycle and the sessions' events, stamped with the wall clock in microseconds. */
    private class Timeline : ConnectionListener {
        private val lines = ConcurrentLinkedQueue<String>()
        private val epochMicros = System.currentTimeMillis() * 1000
        private val startNanos = System.nanoTime()

        fun add(event: String) {
            val us = epochMicros + (System.nanoTime() - startNanos) / 1000
            lines += "${us / 1_000_000}.${(us % 1_000_000).toString().padStart(6, '0')} $event"
        }

        fun text(): String = lines.joinToString("") { it + "\n" }

        override fun onOpened(connection: ConnectionInfo) = add("quic ${connection.id}: opened from ${connection.remoteAddress}")

        override fun onHandshakeCompleted(connection: ConnectionInfo) = add("quic ${connection.id}: handshake completed")

        override fun onClosed(
            connection: ConnectionInfo,
            reason: QuicException.ConnectionLost,
        ) {
            val s = connection.connection.stats
            add(
                "quic ${connection.id}: closed: ${chain(reason)}; packets received ${s.packetsReceived}, sent ${s.packetsSent}, " +
                    "lost ${s.lostPackets}",
            )
        }
    }

    private fun prop(name: String): String? = System.getProperty("$PREFIX.$name")?.takeIf { it.isNotBlank() }

    /** Base64 of the SHA-256 of the leaf certificate's DER, the value `serverCertificateHashes` takes. */
    private fun certificateHash(pem: String): String {
        val cert = CertificateFactory.getInstance("X.509").generateCertificate(pem.byteInputStream())
        return Base64.getEncoder().encodeToString(MessageDigest.getInstance("SHA-256").digest(cert.encoded))
    }

    /** Written next to [target] and moved over it, so the script polling for the file never reads half of it. */
    private fun writeAtomically(
        target: File,
        text: String,
    ) {
        val tmp = File(target.parentFile, target.name + ".tmp")
        tmp.writeText(text)
        Files.move(tmp.toPath(), target.toPath(), StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING)
    }

    private companion object {
        /** [e] and its causes, each as its class and message. */
        fun chain(e: Throwable?): String =
            generateSequence(e) { it.cause }.take(6).joinToString(" <- ") { "${it::class.simpleName}(${it.message})" }.ifEmpty { "none" }

        const val PREFIX = "kuicksilver.manualWebTransport"
        val STEPS = listOf("connect", "bidiEcho1MB", "uniFromServer", "datagrams", "clientClose", "serverClose")
    }
}
