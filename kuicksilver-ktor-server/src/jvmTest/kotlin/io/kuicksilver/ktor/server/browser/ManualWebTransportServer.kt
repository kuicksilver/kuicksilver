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
import io.kuicksilver.ktor.server.Kuicksilver
import io.kuicksilver.ktor.server.webTransport
import io.kuicksilver.native.KslLoader
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
        val server =
            embeddedServer(Kuicksilver, configure = {
                tlsConnector(identity) {
                    host = "127.0.0.1"
                    this.port = port
                }
                webTransport = true
            }) {
                routing {
                    get("/wt/index.html") { call.respondText(page, ContentType.Text.Html) }
                    post("/result") {
                        result.complete(call.receiveText())
                        call.respondText("ok")
                    }
                    webTransport("/wt/echo") { session ->
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
                    webTransport("/wt/server-close") { session -> session.close(9, "server-bye") }
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
                val closeText = seenClose?.let { "${it.code} \"${it.reason}\"" }
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
            }
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
        const val PREFIX = "kuicksilver.manualWebTransport"
        val STEPS = listOf("connect", "bidiEcho1MB", "uniFromServer", "datagrams", "clientClose", "serverClose")
    }
}
