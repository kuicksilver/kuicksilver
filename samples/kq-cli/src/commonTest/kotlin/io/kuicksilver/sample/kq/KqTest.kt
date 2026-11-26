// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.sample.kq

import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import kotlinx.io.buffered
import kotlinx.io.files.Path
import kotlinx.io.files.SystemFileSystem
import kotlinx.io.readString
import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.seconds

/** kq against an in-process Kuicksilver server over real sockets on loopback (TCP and UDP), as a user runs it. */
class KqTest {
    private class Captured(
        val stdoutWorks: Boolean = true,
    ) : Console {
        val body = StringBuilder()
        val err = mutableListOf<String>()

        override fun out(
            bytes: ByteArray,
            offset: Int,
            length: Int,
        ) {
            body.append(bytes.decodeToString(offset, offset + length))
        }

        override fun err(line: String) {
            err += line
        }

        override fun flush() = stdoutWorks

        fun errText() = err.joinToString("\n")
    }

    private lateinit var server: KqServer
    private var port = 0
    private lateinit var ca: Path

    @BeforeTest fun start() =
        runBlocking {
            val (s, p) = startServer()
            server = s
            port = p
            ca = tempFile("ca.pem", SampleCerts.caPem)
        }

    @AfterTest fun stop() {
        server.stop(0, 1000)
        deleteTree(ca)
    }

    private fun kq(
        vararg args: String,
        console: Captured = Captured(),
    ): Pair<Int, Captured> {
        val argv = listOf(args[0], "--cacert", ca.toString()) + args.drop(1)
        val code = runBlocking { withTimeout(60.seconds) { kq(argv, console) } }
        return code to console
    }

    @Test fun altSvcLearnedThenUsedInANewRun() {
        val store = tempPath("alt-svc.txt")
        try {
            val (code, c) = kq("get", "-v", "--alt-svc", store.toString(), "--repeat", "2", "https://127.0.0.1:$port/")
            assertEquals(0, code, c.errText())
            // the first request over TCP (h2 in ALPN), which announces HTTP/3 on the same port
            assertTrue(c.body.toString().startsWith("hello over HTTP/2\n"), c.body.toString())
            val err = c.errText()
            assertTrue("* GET https://127.0.0.1:$port/ (1 of 2)" in err, err)
            assertTrue("HTTP/2 over TCP, TLS, ALPN h2, new connection to 127.0.0.1:$port" in err, err)
            assertTrue("not HTTP/3: NoAlternative" in err, err)
            // the second has the alternative and races it against the open HTTP/2 connection; which one wins is timing
            assertTrue("chosen because: Race (HTTP/3 alternative 127.0.0.1:$port from AltSvc)" in err, err)
            // Alt-Svc comes with the TCP responses only: once for the first, again for the second only when TCP won
            val second = c.err.indexOf("* GET https://127.0.0.1:$port/ (2 of 2)")
            val altSvc = "* Alt-Svc received: h3=\":$port\"; ma=86400"
            assertEquals(1, c.err.subList(0, second).count { it == altSvc }, err)
            val tcpWon = c.body.toString() == "hello over HTTP/2\nhello over HTTP/2\n"
            assertEquals(if (tcpWon) 1 else 0, c.err.subList(second, c.err.size).count { it == altSvc }, err)
            // a new run reads the alternative from the file: a cold start can go to HTTP/3 at once
            val (code2, c2) = kq("get", "-v", "--alt-svc", store.toString(), "https://127.0.0.1:$port/")
            assertEquals(0, code2, c2.errText())
            assertTrue("(HTTP/3 alternative 127.0.0.1:$port from AltSvc)" in c2.errText(), c2.errText())
        } finally {
            deleteTree(store)
        }
    }

    @Test fun altSvcClearDropsTheStoredAlternative() {
        val store = tempPath("alt-svc.txt")
        try {
            assertEquals(0, kq("get", "--alt-svc", store.toString(), "https://127.0.0.1:$port/").first)
            val (code, c) = kq("get", "-v", "--alt-svc", store.toString(), "https://127.0.0.1:$port/clear")
            assertEquals(0, code, c.errText())
            assertTrue("* Alt-Svc received: clear (the origin's alternatives are dropped)" in c.err, c.errText())
            // the file no longer has the origin's alternative: the next run starts without one
            val (code2, c2) = kq("get", "-v", "--http2", "--alt-svc", store.toString(), "https://127.0.0.1:$port/clear")
            assertEquals(0, code2, c2.errText())
            val (code3, c3) = kq("get", "-v", "--alt-svc", store.toString(), "https://127.0.0.1:$port/")
            assertEquals(0, code3, c3.errText())
            assertTrue("not HTTP/3: NoAlternative" in c3.errText(), c3.errText())
        } finally {
            deleteTree(store)
        }
    }

    @Test fun http3PreferredRacesTcp() {
        val (code, c) = kq("get", "-v", "--http3", "https://127.0.0.1:$port/")
        assertEquals(0, code, c.errText())
        val err = c.errText()
        assertTrue("chosen because: " in err && "from Preferred)" in err, err)
        if (c.body.toString() == "hello over HTTP/3\n") {
            assertTrue("HTTP/3 over QUIC v1, ALPN h3, new connection to 127.0.0.1:$port" in err, err)
            assertTrue("QUIC handshake " in err && "ms; RTT " in err, err)
        } else {
            assertTrue("HTTP/3 and TCP raced" in err, err) // TCP won the race: reported, not hidden
        }
    }

    @Test fun http3OnlyWithQlog() {
        val dir = tempPath("qlog")
        try {
            val (code, c) = kq("get", "-v", "--http3-only", "--qlog", dir.toString(), "https://127.0.0.1:$port/")
            assertEquals(0, code, c.errText())
            assertEquals("hello over HTTP/3\n", c.body.toString())
            val err = c.errText()
            assertTrue("chosen because: Configuration (HTTP/3 alternative 127.0.0.1:$port from H3Only)" in err, err)
            assertTrue("HTTP/3 over QUIC v1, ALPN h3, new connection to 127.0.0.1:$port" in err, err)
            assertTrue(c.err.any { it.startsWith("* QUIC handshake ") && "0-RTT off (--0rtt)" in it }, err)
            assertTrue(c.err.none { it.startsWith("* qlog:") }, err) // nothing dropped
            assertCompleteTraces(dir, 1)
        } finally {
            deleteTree(dir)
        }
    }

    @Test fun zeroRttWithQlogOnEveryConnection() {
        val dir = tempPath("qlog")
        try {
            val (code, c) = kq("get", "-v", "--http3-only", "--0rtt", "--repeat", "3", "--qlog", dir.toString(), "https://127.0.0.1:$port/")
            assertEquals(0, code, c.errText())
            val err = c.errText()
            // the first connection has no ticket yet; a later one resumes with one (a ticket that is not there yet when a
            // repeat starts makes that repeat a full handshake, so not every later one need be accepted)
            val first = c.err.indexOf("* GET https://127.0.0.1:$port/ (1 of 3)")
            val second = c.err.indexOf("* GET https://127.0.0.1:$port/ (2 of 3)")
            assertTrue(c.err.subList(first, second).any { "0-RTT not used (no session ticket for this server yet)" in it }, err)
            assertTrue(c.err.subList(second, c.err.size).any { "0-RTT accepted" in it }, err)
            // one trace per connection (each repeat opens one), every one closed and written out before kq returned
            assertCompleteTraces(dir, 3)
        } finally {
            deleteTree(dir)
        }
    }

    private fun assertCompleteTraces(
        dir: Path,
        n: Int,
    ) {
        val traces = SystemFileSystem.list(dir)
        assertEquals(n, traces.size, "$traces")
        for (trace in traces) {
            assertTrue("_client_" in trace.name && trace.name.endsWith(".sqlog"), trace.name)
            val text = SystemFileSystem.source(trace).buffered().use { it.readString() }
            assertTrue("\"qlog_format\":\"JSON-SEQ\"" in text && "transport:packet_received" in text, text.take(400))
            assertTrue("connectivity:connection_closed" in text, text.takeLast(400)) // the trace's last event is there
        }
    }

    @Test fun http11AndIncludeAndOutput() {
        val file = tempPath("body.bin")
        try {
            val (code, c) = kq("get", "-i", "-v", "--http1.1", "-o", file.toString(), "https://127.0.0.1:$port/bytes/5000")
            assertEquals(0, code, c.errText())
            val body = SystemFileSystem.source(file).buffered().use { it.readString() }
            assertTrue(body.startsWith("HTTP/1.1 200 OK\r\n"), body.take(200))
            assertTrue("\r\n\r\n" + "x".repeat(5000) == body.substring(body.indexOf("\r\n\r\n")), body.takeLast(50))
            assertEquals("", c.body.toString())
            assertTrue("HTTP/1.1 over TCP, TLS, ALPN http/1.1" in c.errText(), c.errText())
            assertTrue("* 200, head after " in c.errText() && "5000 body bytes" in c.errText(), c.errText())
        } finally {
            deleteTree(file)
        }
    }

    @Test fun headHasNoBody() {
        val (code, c) = kq("head", "--http2", "-i", "https://127.0.0.1:$port/")
        assertEquals(0, code, c.errText())
        assertTrue(c.body.toString().startsWith("HTTP/2 200"), c.body.toString())
        assertTrue(c.body.toString().endsWith("\r\n\r\n"), c.body.toString())
    }

    @Test fun userinfoIsNeverPrinted() {
        val (code, c) = kq("get", "-v", "--http2", "https://someone:s3cret@127.0.0.1:$port/")
        assertEquals(0, code, c.errText())
        assertTrue("* GET https://127.0.0.1:$port/" in c.err, c.errText())
        assertFalse("s3cret" in c.errText() || "someone" in c.errText(), c.errText())
        val closed = port
        server.stop(0, 1000)
        val (code2, c2) = kq("get", "--http2", "--connect-timeout", "2", "https://someone:s3cret@127.0.0.1:$closed/")
        assertEquals(1, code2, c2.errText())
        assertFalse("s3cret" in c2.errText() || "someone" in c2.errText(), c2.errText())
    }

    @Test fun userinfoIsNeverPrintedOnAFailure() {
        val closed = port
        server.stop(0, 1000)
        for (verbose in listOf(false, true)) {
            val args = listOf("get") + (if (verbose) listOf("-v") else emptyList()) +
                listOf("--http3-only", "--connect-timeout", "1", "https://someone:s3cret@127.0.0.1:$closed/")
            val (code, c) = kq(*args.toTypedArray())
            assertEquals(1, code, c.errText())
            assertTrue("kq: GET https://127.0.0.1:$closed/ failed: " in c.errText(), c.errText())
            assertTrue("connect failure: " in c.errText(), c.errText()) // the lines that carry Ktor's message with the URL
            assertFalse("s3cret" in c.errText() || "someone" in c.errText(), c.errText())
        }
    }

    @Test fun negative_http3OnlyToAPortWithoutQuicFails() {
        val closed = port
        server.stop(0, 1000)
        val (code, c) = kq("get", "--http3-only", "--connect-timeout", "2", "https://127.0.0.1:$closed/")
        assertEquals(1, code, c.errText())
        assertTrue("kq: GET https://127.0.0.1:$closed/ failed: " in c.errText(), c.errText())
        assertTrue("kq: failed over Quic" in c.errText(), c.errText())
        assertTrue("connect failure: QuicHandshake to " in c.errText(), c.errText())
    }

    @Test fun negative_untrustedServerFails() {
        val c = Captured()
        val code = runBlocking { withTimeout(60.seconds) { kq(listOf("get", "--http2", "https://127.0.0.1:$port/"), c) } }
        assertEquals(1, code, c.errText()) // the system trust store does not know the sample's CA
        assertTrue("connect failure: TlsHandshake" in c.errText(), c.errText())
    }

    @Test fun negative_outputFileThatCannotBeOpenedExitsOne() {
        val (code, c) = kq("get", "-o", tempPath("no-such-dir").toString() + "/body", "https://127.0.0.1:$port/")
        assertEquals(1, code, c.errText())
        assertTrue(c.err.single().startsWith("kq: -o "), c.errText())
    }

    @Test fun negative_stdoutWriteFailureExitsOne() {
        val (code, c) = kq("get", "--http2", "https://127.0.0.1:$port/", console = Captured(stdoutWorks = false))
        assertEquals(1, code, c.errText())
        assertEquals("kq: writing to stdout failed", c.err.single())
    }

    @Test fun negative_usageErrorExitsTwo() {
        val c = Captured()
        assertEquals(2, runBlocking { kq(listOf("get", "--bogus", "https://127.0.0.1:$port/"), c) })
        assertEquals(listOf("kq: unknown option '--bogus'", "try 'kq --help'"), c.err)
        val missing = Captured()
        assertEquals(2, runBlocking { kq(listOf("get", "--cacert", tempPath("none.pem").toString(), "https://127.0.0.1:$port/"), missing) })
        assertTrue(missing.err.single().startsWith("kq: --cacert "), missing.errText())
    }
}
