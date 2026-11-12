// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)

package io.kuicksilver.ktor.server

import io.ktor.client.HttpClient
import io.ktor.client.plugins.websocket.webSocket
import io.ktor.client.request.get
import io.ktor.client.request.header
import io.ktor.client.statement.bodyAsText
import io.ktor.http.HttpProtocolVersion
import io.ktor.server.application.install
import io.ktor.server.request.httpVersion
import io.ktor.server.routing.routing
import io.ktor.server.websocket.WebSockets
import io.ktor.server.websocket.webSocket
import io.ktor.websocket.Frame
import io.ktor.websocket.readText
import io.kuicksilver.ktor.client.Http3DiscoveryMode
import io.kuicksilver.native.KslLoader
import io.kuicksilver.tls.Certificate
import io.kuicksilver.tls.TrustConfig
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeout
import org.junit.jupiter.api.Assumptions.assumeTrue
import java.io.File
import java.nio.file.Files
import java.util.Base64
import java.util.concurrent.TimeUnit
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.seconds
import io.ktor.client.plugins.websocket.WebSockets as ClientWebSockets
import io.kuicksilver.ktor.client.Kuicksilver as KuicksilverClient

/**
 * WebSockets over HTTP/2 (RFC 8441) against an independent implementation: Node.js's `http2` module, which is nghttp2
 * underneath, as the client of our server and as the server of our client (the scripts are the `.mjs` files of `h2ws` among the test
 * resources). Skipped when no `node` is found (`KSL_NODE`, the PATH, or the usual Homebrew and system locations); runs
 * on its own otherwise. The only real-time waits are on the external process.
 */
class NodeH2WebSocketInteropTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    @Test fun nodeClientAgainstOurServer() {
        val node = findNode()
        assumeTrue(node != null, "no node found (KSL_NODE, PATH)")
        serverTest {
            val (server, port) =
                h2TlsServer {
                    install(WebSockets)
                    routing {
                        webSocket("/ws") {
                            for (frame in incoming) {
                                if (frame is Frame.Text) send(Frame.Text("${call.request.httpVersion}:" + frame.readText()))
                            }
                        }
                    }
                }
            val dir = scripts()
            try {
                val ca = File(dir, "ca.pem").apply { writeText(pem("CERTIFICATE", TestCerts.testCa)) }
                val (rc, out) = run(listOf(node!!, File(dir, "client.mjs").path, port.toString(), ca.path))
                println("node client against our server:\n$out")
                assertEquals(0, rc, out)
                val lines = out.lines()
                assertTrue("SETTINGS enableConnectProtocol=true" in lines, out)
                assertTrue("STATUS 200" in lines, out)
                assertTrue("TEXT HTTP/2:node" in lines, out)
                assertTrue("CLOSE 1000" in lines, out)
                assertTrue("SERVER_END_STREAM" in lines, out)
                assertTrue("OK" in lines, out)
            } finally {
                dir.deleteRecursively()
                server.stop(100, 500)
            }
        }
    }

    @Test fun ourClientAgainstNodeServer() {
        val node = findNode()
        assumeTrue(node != null, "no node found (KSL_NODE, PATH)")
        val dir = scripts()
        val cert = File(dir, "cert.pem").apply { writeText(pem("CERTIFICATE", TestCerts.server)) }
        val key = File(dir, "key.pem").apply { writeText(pem("PRIVATE KEY", TestCerts.serverKey)) }
        val process =
            ProcessBuilder(node!!, File(dir, "server.mjs").path, cert.path, key.path)
                .redirectErrorStream(true)
                .start()
        val output = StringBuffer()
        try {
            val reader = process.inputStream.bufferedReader()
            val first = reader.readLine() ?: error("node exited: ${process.waitFor()}")
            assertTrue(first.startsWith("LISTENING "), first)
            val port = first.removePrefix("LISTENING ").trim().toInt()
            val pump = Thread { reader.lineSequence().forEach { output.append(it).append('\n') } }.apply { start() }
            serverTest {
                HttpClient(KuicksilverClient) {
                    install(ClientWebSockets)
                    engine {
                        trust = TrustConfig.AnchoredCa(listOf(Certificate(TestCerts.testCa)))
                        http3 { discovery = Http3DiscoveryMode.H1Only }
                    }
                }.use { c ->
                    val get = withTimeout(10.seconds) { c.get("https://127.0.0.1:$port/") }
                    assertEquals(HttpProtocolVersion.HTTP_2_0, get.version)
                    assertEquals("ok", get.bodyAsText())
                    withTimeout(10.seconds) {
                        c.webSocket("wss://127.0.0.1:$port/ws?q=1", request = { header("Sec-WebSocket-Protocol", "chat") }) {
                            assertEquals(HttpProtocolVersion.HTTP_2_0, call.response.version)
                            assertEquals("chat", call.response.headers["sec-websocket-protocol"])
                            send(Frame.Text("kuicksilver"))
                            assertEquals("node:kuicksilver", (incoming.receive() as Frame.Text).readText())
                        }
                    }
                }
            }
            process.destroy()
            process.waitFor(10, TimeUnit.SECONDS)
            pump.join(10_000)
            val out = output.toString()
            println("our client against the node server:\n$out")
            val connect = out.lines().single { it.startsWith("CONNECT ") }
            for (expected in listOf(
                "\":method\":\"CONNECT\"",
                "\":protocol\":\"websocket\"",
                "\":scheme\":\"https\"",
                "\":path\":\"/ws?q=1\"",
                "\"sec-websocket-version\":\"13\"",
            )) {
                assertTrue(expected in connect, connect)
            }
            for (absent in listOf("sec-websocket-key", "\"connection\"", "\"upgrade\"", "\"host\"")) assertTrue(absent !in connect, connect)
            assertTrue("CLIENT_END_STREAM" in out.lines(), out)
            assertTrue("STREAM_CLOSED rst=0" in out.lines(), out)
            assertTrue("UNMASKED_FRAME" !in out.lines(), out)
        } finally {
            process.destroyForcibly()
            dir.deleteRecursively()
        }
    }

    /** Runs [cmd] to its end (at most 30 s) and returns its exit code and output. */
    private suspend fun run(cmd: List<String>): Pair<Int, String> =
        withContext(Dispatchers.IO) {
            val p = ProcessBuilder(cmd).redirectErrorStream(true).start()
            try {
                val out = p.inputStream.bufferedReader().readText()
                if (!p.waitFor(30, TimeUnit.SECONDS)) error("node did not exit:\n$out")
                p.exitValue() to out
            } finally {
                p.destroyForcibly()
            }
        }

    /** The scripts in a fresh temporary directory (they import each other by relative path). */
    private fun scripts(): File {
        val dir = Files.createTempDirectory("kuicksilver-h2ws").toFile()
        for (name in listOf("client.mjs", "server.mjs", "ws-frames.mjs")) {
            File(dir, name).writeText(javaClass.getResource("/h2ws/$name")!!.readText())
        }
        return dir
    }

    private fun pem(
        type: String,
        der: ByteArray,
    ): String = "-----BEGIN $type-----\n" + Base64.getMimeEncoder(64, "\n".toByteArray()).encodeToString(der) + "\n-----END $type-----\n"

    private fun findNode(): String? {
        System.getenv("KSL_NODE")?.takeIf { File(it).canExecute() }?.let { return it }
        val path =
            System
                .getenv("PATH")
                .orEmpty()
                .split(File.pathSeparator)
                .map { File(it, "node").path }
        val usual = listOf("/opt/homebrew/bin/node", "/opt/homebrew/opt/node@24/bin/node", "/usr/local/bin/node", "/usr/bin/node")
        return (path + usual).firstOrNull { File(it).canExecute() }
    }
}
