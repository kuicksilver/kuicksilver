// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)

package io.kuicksilver.ktor.server.browser

import io.ktor.http.ContentType
import io.ktor.server.request.receiveText
import io.ktor.server.response.respondText
import io.ktor.server.routing.get
import io.ktor.server.routing.post
import io.ktor.server.routing.routing
import io.ktor.utils.io.copyTo
import io.ktor.utils.io.writeFully
import io.kuicksilver.http3.WebTransportCloseInfo
import io.kuicksilver.ktor.server.TestCerts
import io.kuicksilver.ktor.server.serverTest
import io.kuicksilver.ktor.server.tlsServer
import io.kuicksilver.ktor.server.webTransport
import io.kuicksilver.native.KslLoader
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.cancelChildren
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.launch
import kotlinx.coroutines.withTimeout
import org.junit.jupiter.api.Assumptions.assumeTrue
import java.io.File
import java.nio.file.Files
import java.security.MessageDigest
import java.security.cert.CertificateFactory
import java.util.Base64
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.seconds

/**
 * A real browser against the Ktor server's WebTransport routes (draft-ietf-webtrans-http3; Chrome speaks draft-02):
 * the page `wt/index.html` runs a 1 MiB bidirectional echo, reads a unidirectional stream the server opens, sends 100
 * datagrams (one echoed back is enough: datagrams may be lost), closes a session with code 7 and "bye", and has the
 * server close another with code 9 and "server-bye"; it posts its results to `/result`.
 *
 * Opt-in: runs only with `-Pkuicksilver.browserTests=true` and an installed Chrome or Chromium; nothing is installed.
 * Chrome runs headless with its own throw-away profile, QUIC forced for the test origin, and the test certificate
 * admitted by its SPKI hash (for such an origin Chrome's WebTransport accepts a root it does not know).
 */
class ChromeWebTransportTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    @Test fun chromeDraft02() = runChrome(emptyList())

    /** Chrome with draft-07 enabled falls back to draft-02: we do not announce draft-07's SETTINGS (0xc671706a). */
    @Test fun chromeWithDraft07EnabledFallsBackToDraft02() = runChrome(listOf("--enable-features=EnableWebTransportDraft07"))

    private fun runChrome(extraFlags: List<String>) {
        assumeTrue(System.getProperty("kuicksilver.browserTests") == "true", "browser tests run with -Pkuicksilver.browserTests=true")
        val chrome = findChrome()
        assumeTrue(chrome != null, "no Chrome or Chromium installed")
        val page = javaClass.getResource("/wt/index.html")!!.readText()
        serverTest {
            val result = CompletableDeferred<String>()
            val clientClose = CompletableDeferred<WebTransportCloseInfo>()
            val draft02 = CompletableDeferred<Boolean>()
            val (server, port) =
                tlsServer({ webTransport = true }) {
                    routing {
                        get("/wt/index.html") { call.respondText(page, ContentType.Text.Html) }
                        post("/result") {
                            result.complete(call.receiveText())
                            call.respondText("ok")
                        }
                        webTransport("/wt/echo") { session ->
                            draft02.complete(session.headers["sec-webtransport-http3-draft02"] == "1")
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
            var profile: File? = null
            var process: Process? = null
            // Ctrl-C or a stopped Gradle daemon must not leave the browser running
            val reaper = Thread { process?.destroyForcibly() }
            Runtime.getRuntime().addShutdownHook(reaper)
            try {
                profile = Files.createTempDirectory("kuicksilver-chrome").toFile()
                val output = File(profile, "chrome.log")
                process =
                    ProcessBuilder(
                        listOf(
                            chrome!!,
                            "--headless=new",
                            "--user-data-dir=${profile.absolutePath}",
                            "--no-first-run",
                            "--no-default-browser-check",
                            "--enable-quic",
                            "--origin-to-force-quic-on=127.0.0.1:$port",
                            "--ignore-certificate-errors-spki-list=${spkiHash()}",
                        ) + extraFlags + "https://127.0.0.1:$port/wt/index.html",
                    ).redirectErrorStream(true)
                        .redirectOutput(output)
                        .start()
                try {
                    // the only real-time wait: an external browser process
                    val json = withTimeout(45.seconds) { result.await() }
                    println("Chrome WebTransport result: $json")
                    for (step in listOf("connect", "bidiEcho1MB", "uniFromServer", "datagrams", "clientClose", "serverClose")) {
                        assertTrue("\"$step\":\"ok\"" in json, "step $step in $json")
                    }
                    assertTrue("\"closeInfo\":{\"code\":9,\"reason\":\"server-bye\"}" in json, json)
                    val seen = withTimeout(10.seconds) { clientClose.await() }
                    assertEquals(7L to "bye", seen.code to seen.reason)
                    assertTrue(withTimeout(10.seconds) { draft02.await() }, "Chrome did not use draft-02")
                } catch (e: Throwable) {
                    throw AssertionError("Chrome WebTransport run failed; Chrome's output:\n${output.readText().takeLast(4000)}", e)
                }
            } finally {
                process?.let { p ->
                    p.destroy()
                    if (!p.waitFor(10, java.util.concurrent.TimeUnit.SECONDS)) p.destroyForcibly()
                }
                runCatching { Runtime.getRuntime().removeShutdownHook(reaper) }
                profile?.deleteRecursively()
                server.stop(100, 1000)
            }
        }
    }

    /** Base64 of the SHA-256 of the test certificate's SubjectPublicKeyInfo, as Chrome's SPKI list takes it. */
    private fun spkiHash(): String {
        val cert = CertificateFactory.getInstance("X.509").generateCertificate(TestCerts.server.inputStream())
        return Base64.getEncoder().encodeToString(MessageDigest.getInstance("SHA-256").digest(cert.publicKey.encoded))
    }

    private fun findChrome(): String? {
        val mac =
            listOf(
                "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
                "/Applications/Chromium.app/Contents/MacOS/Chromium",
            )
        val path = System.getenv("PATH").orEmpty().split(File.pathSeparator)
        val names = listOf("google-chrome", "google-chrome-stable", "chromium", "chromium-browser")
        return (mac + path.flatMap { dir -> names.map { File(dir, it).path } }).firstOrNull { File(it).canExecute() }
    }
}
