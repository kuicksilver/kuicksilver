// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)

package io.kuicksilver.ktor.server.browser

import io.ktor.http.ContentType
import io.ktor.server.application.install
import io.ktor.server.request.httpVersion
import io.ktor.server.request.receiveText
import io.ktor.server.response.respondText
import io.ktor.server.routing.get
import io.ktor.server.routing.post
import io.ktor.server.routing.routing
import io.ktor.server.websocket.WebSockets
import io.ktor.server.websocket.webSocket
import io.ktor.websocket.Frame
import io.ktor.websocket.readText
import io.kuicksilver.ktor.server.TestCerts
import io.kuicksilver.ktor.server.h2TlsServer
import io.kuicksilver.ktor.server.serverTest
import io.kuicksilver.native.KslLoader
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.withTimeout
import org.junit.jupiter.api.Assumptions.assumeTrue
import java.io.File
import java.nio.file.Files
import java.security.MessageDigest
import java.security.cert.CertificateFactory
import java.util.Base64
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.seconds

/**
 * A real browser opening a WebSocket over HTTP/2 (RFC 8441) to the Ktor server: Chrome loads a page over HTTP/2 (HTTP/3
 * off), then the page opens `wss://` to the same origin, which Chrome sends as an Extended CONNECT on that HTTP/2
 * connection once the server's SETTINGS allowed it; the route echoes with the call's HTTP version, and the page posts what
 * it got to `/result`.
 *
 * Opt-in, as ChromeWebTransportTest: runs only with `-Pkuicksilver.browserTests=true` and an installed Chrome or Chromium.
 */
class ChromeWebSocketH2Test {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    private val page =
        """
        <!DOCTYPE html><html><body><script>
        (async () => {
          const r = {};
          try {
            const ws = new WebSocket(`wss://${'$'}{location.host}/ws`);
            await new Promise((ok, no) => { ws.onopen = ok; ws.onerror = () => no(new Error('error')); });
            ws.send('chrome');
            r.echo = await new Promise((ok) => { ws.onmessage = (e) => ok(e.data); });
            const closed = new Promise((ok) => { ws.onclose = (e) => ok(e.code); });
            ws.close(1000, 'bye');
            r.close = await closed;
          } catch (e) { r.error = String(e); }
          await fetch('/result', { method: 'POST', body: JSON.stringify(r) });
        })();
        </script></body></html>
        """.trimIndent()

    @Test fun chromeWebSocketOverH2() {
        assumeTrue(System.getProperty("kuicksilver.browserTests") == "true", "browser tests run with -Pkuicksilver.browserTests=true")
        val chrome = findChrome()
        assumeTrue(chrome != null, "no Chrome or Chromium installed")
        serverTest {
            val result = CompletableDeferred<String>()
            val (server, port) =
                h2TlsServer {
                    install(WebSockets)
                    routing {
                        get("/") { call.respondText(page, ContentType.Text.Html) }
                        post("/result") {
                            result.complete(call.receiveText())
                            call.respondText("ok")
                        }
                        webSocket("/ws") {
                            for (frame in incoming) {
                                if (frame is Frame.Text) send(Frame.Text("${call.request.httpVersion}:" + frame.readText()))
                            }
                        }
                    }
                }
            var profile: File? = null
            var process: Process? = null
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
                            "--disable-quic",
                            "--ignore-certificate-errors-spki-list=${spkiHash()}",
                            "https://127.0.0.1:$port/",
                        ),
                    ).redirectErrorStream(true)
                        .redirectOutput(output)
                        .start()
                try {
                    // the only real-time wait: an external browser process
                    val json = withTimeout(45.seconds) { result.await() }
                    println("Chrome WebSocket over HTTP/2 result: $json")
                    assertTrue("\"echo\":\"HTTP/2:chrome\"" in json, json)
                    assertTrue("\"close\":1000" in json, json)
                } catch (e: Throwable) {
                    throw AssertionError("Chrome WebSocket run failed; Chrome's output:\n${output.readText().takeLast(4000)}", e)
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
