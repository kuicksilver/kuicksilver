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
import io.kuicksilver.ktor.server.tlsServer
import io.kuicksilver.ktor.server.webTransport
import io.kuicksilver.native.KslLoader
import io.kuicksilver.quic.QuicLbConfig
import io.kuicksilver.tls.KslCrypto
import io.kuicksilver.tls.KslQuicCrypto
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.cancelChildren
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.junit.jupiter.api.Assumptions.assumeTrue
import java.io.File
import java.nio.file.Files
import java.security.MessageDigest
import java.security.cert.CertificateFactory
import java.util.Base64
import java.util.concurrent.ConcurrentLinkedQueue
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.seconds

/**
 * A real browser against the Ktor server's WebTransport routes (draft-ietf-webtrans-http3; Chrome speaks draft-02):
 * the page `wt/index.html` runs a 1 MiB bidirectional echo, reads a unidirectional stream the server opens, sends 100
 * datagrams (one echoed back is enough: datagrams may be lost), closes a session with code 7 and "bye", and has the
 * server close another with code 9 and "server-bye"; then its error code stage ([WtCodesProbe]): draft-02 stream error
 * codes both ways (the page's `writer.abort` / `reader.cancel` with 0, 42, 255, 256, 1000 and 2^32-1, the server's
 * reset / STOP_SENDING with 0..255) and 32-bit session close codes both ways. It posts the code table to `/codes` and its
 * results to `/result`. The table, with the raw HTTP/3 code and the mapped WebTransport code of every RESET_STREAM and
 * STOP_SENDING, is printed and kept in `build/browser-wt-codes/`; Chrome's observed outcomes are asserted, and a stream
 * code above 255 from Chrome is reported loudly and fails the test (the strict draft-02 policy assumes there is none).
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

    /**
     * A QUIC-LB configuration change while the session is open: as soon as the echo session is accepted the server moves to
     * another configuration (`updateLoadBalancer`) and sends NEW_CONNECTION_ID frames with Retire Prior To, so Chrome retires
     * the connection ID it sends to. The server closes a connection whose RETIRE_CONNECTION_ID names the ID of the packet
     * carrying it (RFC 9000 section 19.16); the page's later steps (the 1 MiB echo, datagrams, the closes) must still pass.
     */
    @Test fun chromeSessionOutlivesAQuicLbChange() = runChrome(emptyList(), lbChange = true)

    private fun runChrome(
        extraFlags: List<String>,
        lbChange: Boolean = false,
    ) {
        assumeTrue(System.getProperty("kuicksilver.browserTests") == "true", "browser tests run with -Pkuicksilver.browserTests=true")
        val chrome = findChrome()
        assumeTrue(chrome != null, "no Chrome or Chromium installed")
        val page = javaClass.getResource("/wt/index.html")!!.readText()
        // the page's error code stage adds about a minute to the steps: a longer bound than serverTest's
        runBlocking {
            withTimeout(240.seconds) {
                val result = CompletableDeferred<String>()
                val codesPosted = CompletableDeferred<String>()
                val timeline = ConcurrentLinkedQueue<String>()
                val probe = WtCodesProbe { line -> timeline += line }
                val clientClose = CompletableDeferred<WebTransportCloseInfo>()
                val draft02 = CompletableDeferred<Boolean>()
                val lbChanged = CompletableDeferred<Unit>()
                val lbKeys = if (lbChange) List(2) { KslQuicCrypto.newLoadBalancerKey(KslCrypto.randomBytes(16)) } else emptyList()
                var changeLoadBalancer: (suspend () -> Unit)? = null
                val (server, port) =
                    tlsServer({
                        http3 { webTransport { enabled = true } }
                        observability { qlog = probe }
                        if (lbChange) http3 { endpoint { loadBalancer = QuicLbConfig(1, LB_SERVER_ID, 4, lbKeys[0]) } }
                    }) {
                        routing {
                            get("/wt/index.html") { call.respondText(page, ContentType.Text.Html) }
                            post("/result") {
                                result.complete(call.receiveText())
                                call.respondText("ok")
                            }
                            post("/codes") {
                                codesPosted.complete(call.receiveText())
                                call.respondText("ok")
                            }
                            probe.routes(this)
                            webTransport("/wt/echo") { session ->
                                draft02.complete(session.headers["sec-webtransport-http3-draft02"] == "1")
                                // recorded when it happens, not from the handler, which the connection's end may cancel first
                                session.closed.invokeOnCompletion {
                                    @OptIn(kotlinx.coroutines.ExperimentalCoroutinesApi::class)
                                    clientClose.complete(session.closed.getCompleted())
                                }
                                changeLoadBalancer?.let { change ->
                                    change()
                                    lbChanged.complete(Unit)
                                }
                                coroutineScope {
                                    launch {
                                        runCatching {
                                            while (true) {
                                                val st = session.acceptBidi()
                                                launch {
                                                    // a stream the session's end cuts must not fail the handler
                                                    runCatching {
                                                        st.input.copyTo(st.output)
                                                        st.output.flushAndClose()
                                                    }
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
                                    session.closed.await()
                                    coroutineContext.cancelChildren()
                                }
                            }
                            webTransport("/wt/server-close") { session -> session.close(9, "server-bye") }
                        }
                    }
                if (lbChange) changeLoadBalancer = { server.engine.updateLoadBalancer(QuicLbConfig(2, LB_SERVER_ID, 4, lbKeys[1])) }
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
                        val json = withTimeout(180.seconds) { result.await() }
                        println("Chrome WebTransport result: $json")
                        val codes = checkCodes(probe, withTimeout(10.seconds) { codesPosted.await() }, timeline, extraFlags, lbChange)
                        for (step in STEPS) {
                            assertTrue("\"$step\":\"ok\"" in json, "step $step in $json")
                        }
                        assertTrue("\"closeInfo\":{\"code\":9,\"reason\":\"server-bye\"}" in json, json)
                        val seen = withTimeout(10.seconds) { clientClose.await() }
                        assertEquals(7L to "bye", seen.code to seen.reason)
                        assertTrue(withTimeout(10.seconds) { draft02.await() }, "Chrome did not use draft-02")
                        if (lbChange) assertTrue(lbChanged.isCompleted, "the QUIC-LB configuration changed during the session")
                        codes()
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
                    lbKeys.forEach { it.close() }
                }
            }
        }
    }

    /**
     * The error code stage's table (WtCodesProbe), printed and kept in `build/browser-wt-codes/`; returns the assertions
     * on it, run after the page's other checks. A stream code above 255 from Chrome is reported loudly first: draft-02
     * section 4.3 allows only 0..255, and the library's strict policy (no receive shim) was taken on the premise that
     * browsers keep to it.
     */
    private fun checkCodes(
        probe: WtCodesProbe,
        pageLines: String,
        timeline: Collection<String>,
        extraFlags: List<String>,
        lbChange: Boolean,
    ): () -> Unit {
        val table = probe.table("Chrome ${extraFlags.joinToString(" ")}".trim(), pageLines)
        val name =
            if (lbChange) {
                "lb-change"
            } else {
                extraFlags
                    .joinToString("-") {
                        it.trimStart('-')
                    }.ifEmpty { "draft02" }
                    .replace(Regex("[^A-Za-z0-9-]"), "_")
            }
        val dir = File("build/browser-wt-codes").apply { mkdirs() }
        File(dir, "chrome-$name-table.txt").writeText(table)
        File(dir, "chrome-$name-server-events.txt").writeText(timeline.joinToString("") { it + "\n" })
        println(table)
        val above = probe.above255()
        if (above.isNotEmpty()) {
            System.err.println("!!!!!!!! CHROME SENT DRAFT-02 STREAM ERROR CODES ABOVE 255 (strict policy, no shim): $above")
        }
        return {
            assertTrue(above.isEmpty(), "Chrome sent draft-02 stream codes above 255; revisit the strict policy: $above\n$table")
            assertCodes(probe, pageLines, table)
        }
    }

    /**
     * Chrome's outcomes, as observed with Chrome 158 headless on 2026-11-26 (docs/spec/interop.md, "Browsers"):
     * - `new WebTransportError({streamErrorCode})` (Chrome takes one WebTransportErrorInit; the W3C form with a message
     *   first throws TypeError) keeps 0..255 and clamps every larger value to 255 (`[Clamp] octet`), so `writer.abort` and
     *   `reader.cancel` send RESET_STREAM / STOP_SENDING carrying WebTransport code min(v, 255): never above 255;
     * - the page reads the server's RESET_STREAM and STOP_SENDING codes 0..255 as the same `streamErrorCode` (source
     *   "stream"); the server refuses 256 and 1000 locally (strict draft-02 policy), so the page sees a plain end;
     * - session close codes are 32-bit both ways; `close({closeCode: 2^32})` does not throw: Chrome wraps it to 0
     *   (WebIDL `unsigned long` without `[EnforceRange]`) and sends 0.
     */
    private fun assertCodes(
        probe: WtCodesProbe,
        pageLines: String,
        table: String,
    ) {
        val rows = pageLines.lines().filter { it.isNotBlank() }.associate { l -> l.split('\t').let { it[0] to it } }

        fun row(label: String): List<String> = rows[label] ?: throw AssertionError("no row \"$label\" in\n$table")
        for (v in listOf(0L, 42L, 255L, 256L, 1000L, 4294967295L)) {
            val sent = minOf(v, 255L)
            for ((kind, frame, what) in listOf(
                Triple("abort-bidi", "reset_stream", "RESET_STREAM"),
                Triple("abort-uni", "reset_stream", "RESET_STREAM"),
                Triple("cancel-bidi", "stop_sending", "STOP_SENDING"),
                Triple("cancel-uni", "stop_sending", "STOP_SENDING"),
            )) {
                val label = "$kind $v"
                val local = row(label)[1]
                assertTrue(local.startsWith(if (v <= 255) "KEEPS $v " else "CLAMPS to 255 "), "$label: $local")
                val case = probe.case(label) ?: throw AssertionError("$label: the server saw no stream\n$table")
                assertEquals("$what, API code $sent", case.server, "$label\n$table")
                val rx = probe.framesOf(case).filter { it.received }
                assertEquals(listOf(frame to WtCodesProbe.h3Code(sent)), rx.map { it.type to it.raw }, "$label: frames received\n$table")
            }
        }
        for (v in listOf(0L, 1L, 42L, 127L, 128L, 254L, 255L, 256L, 1000L)) {
            for ((kind, frame) in listOf(
                "srv-reset-bidi" to "RESET_STREAM",
                "srv-reset-uni" to "RESET_STREAM",
                "srv-stop-bidi" to "STOP_SENDING",
                "srv-stop-uni" to "STOP_SENDING",
            )) {
                val label = "$kind $v"
                val seen = row(label)[2]
                if (v <= 255) {
                    assertEquals("SAME CODE", row(label)[1], "$label: $seen")
                    assertTrue("streamErrorCode=$v source=stream \"Received $frame.\"" in seen, "$label: $seen")
                } else {
                    assertTrue(probe.case(label)!!.server.contains("refused locally (IllegalArgumentException"), "$label\n$table")
                    assertTrue(seen == "FIN (no error)" || seen.startsWith("no error within"), "$label: $seen")
                }
            }
        }
        assertEquals("closed resolved: closeCode=4294967295 reason=\"page-bye-32\"", row("page-close page-bye-32")[2], table)
        assertEquals("session closed with code 4294967295 reason \"page-bye-32\"", probe.serverSawClose("page-bye-32"), table)
        assertEquals("close({closeCode: 4294967296}) did not throw", row("page-close page-2^32")[1], table)
        assertEquals("session closed with code 0 reason \"page-2^32\"", probe.serverSawClose("page-2^32"), table)
        assertEquals("closeCode=4294967294 reason=\"server-bye-32\"", row("server-close-32")[2], table)
    }

    private companion object {
        /** The server ID of the QUIC-LB configurations of [chromeSessionOutlivesAQuicLbChange]. */
        val LB_SERVER_ID = byteArrayOf(0x31, 0x44, 0x1a)
        val STEPS = listOf("connect", "bidiEcho1MB", "uniFromServer", "datagrams", "clientClose", "serverClose", "codes")
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
