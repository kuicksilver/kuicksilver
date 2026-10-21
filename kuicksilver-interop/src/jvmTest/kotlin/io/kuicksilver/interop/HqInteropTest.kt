// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.interop

import io.kuicksilver.native.KslLoader
import io.kuicksilver.quic.ConnectionAdmission
import io.kuicksilver.tls.CipherSuites
import io.kuicksilver.tls.EarlyDataState
import io.kuicksilver.tls.TlsIdentity
import io.kuicksilver.quic.QuicEndpoint
import io.kuicksilver.quic.QuicEndpointConfig
import io.kuicksilver.quic.QuicServerConfig
import io.kuicksilver.quic.quicConfig
import io.kuicksilver.tls.TlsRole
import io.kuicksilver.tls.tlsConfig
import io.ktor.network.sockets.InetSocketAddress
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import java.io.File
import java.nio.file.Files
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlin.test.assertNotNull
import kotlin.test.assertSame
import kotlin.time.Duration.Companion.seconds

class HqInteropTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()
    private fun identity() = TlsIdentity.fromDer(listOf(TestCerts.server), TestCerts.serverKey.copyOf())
    private fun www(vararg files: Pair<String, ByteArray>): File { val d = Files.createTempDirectory("www").toFile(); for ((n, b) in files) File(d, n).writeBytes(b); return d }

    @Test fun serverServesFileOverHqInterop() = runBlocking {
        val data = ByteArray(3 shl 20) { (it * 11).toByte() }; val root = www("big.bin" to data); val downloads = Files.createTempDirectory("dl").toFile()
        HqInteropServer.start(identity(), port = 0, www = root.path, versions = Interop.v1).use { srv ->
            val code = Interop.run(mapOf("ROLE" to "client", "TESTCASE" to "transfer", "REQUESTS" to "https://127.0.0.1:${srv.port}/big.bin", "DOWNLOADS" to downloads.path))
            assertEquals(0, code); assertContentEquals(data, File(downloads, "big.bin").readBytes())
        }
    }
    @Test fun clientDownloadsAllRequestsOnOneConnection() = runBlocking {
        val files = (1..5).map { "f$it" to ByteArray(10_000 * it) { (it + 3).toByte() } }; val root = www(*files.toTypedArray()); val downloads = Files.createTempDirectory("dl").toFile()
        HqInteropServer.start(identity(), port = 0, www = root.path, versions = Interop.v1).use { srv ->
            val code = Interop.run(mapOf("ROLE" to "client", "TESTCASE" to "transfer", "REQUESTS" to files.joinToString(" ") { "https://127.0.0.1:${srv.port}/${it.first}" }, "DOWNLOADS" to downloads.path))
            assertEquals(0, code); for ((n, b) in files) assertContentEquals(b, File(downloads, n).readBytes()); assertEquals(1, srv.connectionsAccepted, "one connection for all requests")
        }
    }
    @Test @OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)
    fun bbrModeTransfersAFile() = runBlocking {
        // KSL_CC=bbr: the endpoint mode the interop agent runs the runner's goodput and crosstraffic measurements with
        val data = ByteArray(2 shl 20) { (it * 13).toByte() }; val root = www("bbr.bin" to data); val downloads = Files.createTempDirectory("dl").toFile()
        HqInteropServer.start(identity(), port = 0, www = root.path, versions = Interop.v1, congestionController = { io.kuicksilver.quic.Bbr() }).use { srv ->
            val code = Interop.run(mapOf("ROLE" to "client", "TESTCASE" to "transfer", "KSL_CC" to "bbr", "REQUESTS" to "https://127.0.0.1:${srv.port}/bbr.bin", "DOWNLOADS" to downloads.path))
            assertEquals(0, code); assertContentEquals(data, File(downloads, "bbr.bin").readBytes())
        }
        assertTrue(Testcases.client("transfer", Testcases.congestionController("bbr")!!)!!.quic.congestionController() is io.kuicksilver.quic.Bbr)
        assertTrue(Testcases.client("transfer", Testcases.congestionController(null)!!)!!.quic.congestionController() is io.kuicksilver.quic.Cubic)
        assertEquals(127, Interop.run(mapOf("ROLE" to "client", "TESTCASE" to "transfer", "KSL_CC" to "vegas", "REQUESTS" to "")))
    }
    @Test @OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)
    fun clientExits1WhenTheConnectionIsLost() = runBlocking {
        // a lost connection (here the server's CONNECTION_CLOSE; in the runner the idle timeout of ngtcp2->kuicksilver-native:rebind-addr)
        // ends the client with exit 1 on the JVM and on Native alike, not with an uncaught exception (Kotlin/Native: exit 133)
        val tls = tlsConfig(TlsRole.Server) { alpn = listOf("hq-interop"); this.identity = identity() }
        val config = QuicEndpointConfig.Builder().apply { server = QuicServerConfig.Builder(tls).apply { quic = quicConfig { versions = Interop.v1 } }.build() }.build()
        val ep = QuicEndpoint.bind(InetSocketAddress("127.0.0.1", 0), config)
        try {
            val closer = launch(Dispatchers.Default) { ep.accept().close(0x101, "go away") }
            val downloads = Files.createTempDirectory("dl").toFile()
            val code = Interop.run(mapOf("ROLE" to "client", "TESTCASE" to "transfer", "REQUESTS" to "https://127.0.0.1:${ep.localAddress.port}/f", "DOWNLOADS" to downloads.path))
            assertEquals(1, code); closer.join()
        } finally { ep.close() }
    }
    @Test fun unknownTestcaseExits127() { assertEquals(127, Interop.run(mapOf("ROLE" to "client", "TESTCASE" to "connectionmigration", "REQUESTS" to ""))); assertEquals(127, Interop.run(mapOf("ROLE" to "server", "TESTCASE" to "foo"))) }
    @Test fun keylogWrittenWhenEnvSet() = runBlocking {
        val root = www("k" to ByteArray(100)); val downloads = Files.createTempDirectory("dl").toFile(); val keylog = File(downloads, "keys.log")
        HqInteropServer.start(identity(), port = 0, www = root.path, versions = Interop.v1).use { srv ->
            assertEquals(0, Interop.run(mapOf("ROLE" to "client", "TESTCASE" to "handshake", "REQUESTS" to "https://127.0.0.1:${srv.port}/k", "DOWNLOADS" to downloads.path, "SSLKEYLOGFILE" to keylog.path)))
            assertTrue(keylog.readText().contains("CLIENT_TRAFFIC_SECRET_0"), keylog.readText().take(200))
        }
    }

    @Test fun keyupdateTestcaseInitiatesUpdate() = runBlocking {
        val data = ByteArray(3 shl 20) { (it * 13).toByte() }; val root = www("big.bin" to data); val downloads = Files.createTempDirectory("dl").toFile()
        HqInteropServer.start(identity(), port = 0, www = root.path, versions = Interop.v1).use { srv ->
            val code = Interop.run(mapOf("ROLE" to "client", "TESTCASE" to "keyupdate", "REQUESTS" to "https://127.0.0.1:${srv.port}/big.bin", "DOWNLOADS" to downloads.path))
            assertEquals(0, code); assertContentEquals(data, File(downloads, "big.bin").readBytes())
            assertTrue(srv.keyUpdatesSeen >= 1, "the server followed the client's key update: ${srv.keyUpdatesSeen}")
        }
    }

    // ---- the full test case list of the runner ----
    @Test fun everySupportedTestcaseConfigures() {
        for (t in Testcases.supported) { assertNotNull(Testcases.client(t), "client plan for $t"); assertNotNull(Testcases.server(t), "server plan for $t") }
        assertTrue(setOf("handshake", "transfer", "chacha20", "multiconnect", "keyupdate", "retry", "v2", "ecn").all { it in Testcases.supported })
        assertEquals(127, Interop.run(mapOf("ROLE" to "client", "TESTCASE" to "versionnegotiation", "REQUESTS" to "")))
    }
    @Test fun serverPlanWaitsLongerThanTheDefaultForAmplificationLimitedClients() {
        // amplificationlimit: after six dropped datagrams a client's PTO backoff reaches the server after 8-14 s (ngtcp2), beyond the library's 10 s default
        for (t in Testcases.supported) assertEquals(30.seconds, Testcases.server(t)!!.handshakeTimeout, "server plan for $t")
        // handshakecorruption: a two-datagram ClientHello (ML-KEM key share) under 30 % corruption can need more than four PTO rounds (1+2+4+8 s)
        for (t in Testcases.supported) assertEquals(30.seconds, Testcases.client(t)!!.quic.handshakeTimeout, "client plan for $t")
    }

    @Test fun retryCaseServerSendsRetry() { assertSame(ConnectionAdmission.AlwaysRetry, Testcases.server("retry")!!.admission); assertTrue(Testcases.server("transfer")!!.admission !== ConnectionAdmission.AlwaysRetry) }
    @Test fun chacha20CaseRestrictsSuites() {
        assertEquals(listOf(CipherSuites.CHACHA20_POLY1305), Testcases.client("chacha20")!!.cipherSuites.suites); assertEquals(listOf(CipherSuites.CHACHA20_POLY1305), Testcases.server("chacha20")!!.cipherSuites.suites)
        assertEquals(CipherSuites.Default.suites, Testcases.client("transfer")!!.cipherSuites.suites)
    }
    @Test fun multiconnectUsesOneConnectionPerRequest() = runBlocking {
        val files = (1..3).map { "m$it" to ByteArray(1000) { it.toByte() } }; val root = www(*files.toTypedArray()); val downloads = Files.createTempDirectory("dl").toFile()
        HqInteropServer.start(identity(), port = 0, www = root.path, versions = Interop.v1).use { srv ->
            val code = Interop.run(mapOf("ROLE" to "client", "TESTCASE" to "multiconnect", "REQUESTS" to files.joinToString(" ") { "https://127.0.0.1:${srv.port}/${it.first}" }, "DOWNLOADS" to downloads.path))
            assertEquals(0, code); for ((n, b) in files) assertContentEquals(b, File(downloads, n).readBytes()); assertEquals(3, srv.connectionsAccepted, "one connection per request")
        }
    }
    /** Files.stream's boundaries: an empty file (no write, just the FIN) and a file of exactly one [io.kuicksilver.interop.Files.CHUNK] (and one byte more). */
    @Test fun serverStreamsEmptyAndExactlyOneChunkFiles() = runBlocking {
        val files = listOf("empty" to ByteArray(0), "chunk" to ByteArray(io.kuicksilver.interop.Files.CHUNK) { (it * 31).toByte() }, "chunk1" to ByteArray(io.kuicksilver.interop.Files.CHUNK + 1) { (it * 7).toByte() })
        val root = www(*files.toTypedArray()); val downloads = Files.createTempDirectory("dl").toFile()
        HqInteropServer.start(identity(), port = 0, www = root.path, versions = Interop.v1).use { srv ->
            val code = Interop.run(mapOf("ROLE" to "client", "TESTCASE" to "multiconnect", "REQUESTS" to files.joinToString(" ") { "https://127.0.0.1:${srv.port}/${it.first}" }, "DOWNLOADS" to downloads.path))
            assertEquals(0, code); for ((n, b) in files) assertContentEquals(b, File(downloads, n).readBytes(), n)
        }
    }
    /**
     * The server forgets a connection once it ended: it kept every accepted connection in a list it copied on each accept, so a
     * handshake benchmark (12 000 connections, tools/bench/handshakes.sh) paid a growing copy per accept and a growing heap to mark.
     */
    @Test fun serverForgetsEndedConnections() = runBlocking {
        val root = www("f" to ByteArray(32) { it.toByte() }); val downloads = Files.createTempDirectory("dl").toFile()
        HqInteropServer.start(identity(), port = 0, www = root.path, versions = Interop.v1).use { srv ->
            val code = Interop.run(mapOf("ROLE" to "client", "TESTCASE" to "multiconnect", "REQUESTS" to List(5) { "https://127.0.0.1:${srv.port}/f" }.joinToString(" "), "DOWNLOADS" to downloads.path))
            assertEquals(0, code); assertEquals(5, srv.connectionsAccepted)
            val deadline = System.nanoTime() + 5_000_000_000L
            while (srv.connectionsTracked > 0 && System.nanoTime() < deadline) kotlinx.coroutines.delay(20)
            assertEquals(0, srv.connectionsTracked, "connections the client closed are no longer tracked")
        }
    }
    /**
     * Linux only: on macOS the JVM's dual-stack `[::]` socket next to the `0.0.0.0` socket of the same port answers a `[::1]` client from
     * `127.0.0.1`, and a client now discards datagrams from an address that is not the server's (RFC 9000 section 9).
     * The runner's `ipv6` case runs in Linux containers, where the two sockets are separate (IPV6_V6ONLY) and the answer comes from `::1`.
     */
    @Test fun ipv6CaseBindsDualStack() = runBlocking {
        if (!System.getProperty("os.name").lowercase().contains("linux")) { println("ipv6CaseBindsDualStack: Linux only (dual-stack loopback answers from the wrong family on macOS)"); return@runBlocking }
        val data = ByteArray(20_000) { (it * 7).toByte() }; val root = www("six.bin" to data); val downloads = Files.createTempDirectory("dl").toFile()
        HqInteropServer.start(identity(), port = 0, www = root.path, versions = Interop.v1).use { srv ->
            val p6 = srv.port6; if (p6 == null) { println("no IPv6 on this host; v4 only"); return@use }
            assertEquals(0, Interop.run(mapOf("ROLE" to "client", "TESTCASE" to "transfer", "REQUESTS" to "https://[::1]:$p6/six.bin", "DOWNLOADS" to downloads.path, "KSL_INTEROP_EXPECTED_NAME" to "server.test")))
            assertContentEquals(data, File(downloads, "six.bin").readBytes())
            assertEquals(0, Interop.run(mapOf("ROLE" to "client", "TESTCASE" to "transfer", "REQUESTS" to "https://127.0.0.1:${srv.port}/six.bin", "DOWNLOADS" to downloads.path)))
        }
    }
    @Test fun unsupportedCasesExit127() { for (t in listOf("connectionmigration", "versionnegotiation", "foo")) { assertEquals(127, Interop.run(mapOf("ROLE" to "client", "TESTCASE" to t, "REQUESTS" to "")), t); assertEquals(127, Interop.run(mapOf("ROLE" to "server", "TESTCASE" to t)), t) } }

    // ---- the runner's `http3` case (an H3 transaction per file, one connection, ALPN h3)
    @Test fun http3CaseDownloadsOverH3() = runBlocking {
        val files = listOf("a.bin" to ByteArray(5_000) { (it * 3).toByte() }, "b.bin" to ByteArray(500_000) { (it * 5).toByte() }); val root = www(*files.toTypedArray()); val downloads = Files.createTempDirectory("dl").toFile()
        H3InteropServer.start(identity(), port = 0, www = root.path, versions = Interop.v1).use { srv ->
            val code = Interop.run(mapOf("ROLE" to "client", "TESTCASE" to "http3", "REQUESTS" to files.joinToString(" ") { "https://127.0.0.1:${srv.port}/${it.first}" }, "DOWNLOADS" to downloads.path))
            assertEquals(0, code); for ((n, b) in files) assertContentEquals(b, File(downloads, n).readBytes()); assertEquals(1, srv.connectionsAccepted, "one connection for all requests")
            assertEquals(1, Interop.run(mapOf("ROLE" to "client", "TESTCASE" to "http3", "REQUESTS" to "https://127.0.0.1:${srv.port}/missing.bin", "DOWNLOADS" to downloads.path)), "a missing file fails the case")
            assertEquals(404, srv.lastStatusFor("missing.bin"), "a missing file is a 404, not a reset")
        }
    }
    @Test fun http3IsASupportedTestcase() { assertTrue("http3" in Testcases.supported); assertTrue(Testcases.client("http3")!!.http3); assertTrue(Testcases.server("http3")!!.http3); assertTrue(!Testcases.client("transfer")!!.http3) }

    // ---- 0.2.0: the runner's `resumption` and `zerortt` cases (ADR-0015; 0-RTT is opt-in, so only these two plans turn it on)
    @Test fun onlyResumptionAndZeroRttPlansEnableEarlyData() {
        for (t in listOf("resumption", "zerortt")) { assertTrue(t in Testcases.supported, t); assertTrue(Testcases.server(t)!!.earlyData, t); assertEquals(EarlyDataState.Allowed, Testcases.client(t)!!.earlyData, t) }
        for (t in Testcases.supported - setOf("resumption", "zerortt")) { assertTrue(!Testcases.server(t)!!.earlyData, t); assertEquals(EarlyDataState.Disabled, Testcases.client(t)!!.earlyData, t) }
        assertTrue(Testcases.client("zerortt")!!.zeroRtt); assertTrue(!Testcases.client("resumption")!!.zeroRtt)
    }
    @Test fun resumptionCaseResumesTheFirstConnectionsTicket() = runBlocking {
        val files = listOf("r1.bin" to ByteArray(5_000) { (it * 3).toByte() }, "r2.bin" to ByteArray(10_000) { (it * 5).toByte() }); val root = www(*files.toTypedArray()); val downloads = Files.createTempDirectory("dl").toFile()
        val plan = Testcases.server("resumption")!!
        HqInteropServer.start(identity(), port = 0, www = root.path, versions = plan.versions, earlyData = plan.earlyData).use { srv ->
            val code = Interop.run(mapOf("ROLE" to "client", "TESTCASE" to "resumption", "REQUESTS" to files.joinToString(" ") { "https://127.0.0.1:${srv.port}/${it.first}" }, "DOWNLOADS" to downloads.path))
            assertEquals(0, code); for ((n, b) in files) assertContentEquals(b, File(downloads, n).readBytes())
            assertEquals(2, srv.connectionsAccepted, "the first file on one connection, the rest on a second")
            assertEquals(1, srv.earlyAcceptedConnections, "the second connection resumed the first one's ticket (a server accepts early data only on a PSK resumption)")
            assertEquals(0, srv.earlyStreams, "resumption sends no request in 0-RTT")
        }
    }
    @Test fun zerorttCaseSendsTheRemainingRequestsIn0Rtt() = runBlocking {
        val files = (1..6).map { "z$it-" + "x".repeat(200) to ByteArray(32) { b -> (b + it).toByte() } }; val root = www(*files.toTypedArray()); val downloads = Files.createTempDirectory("dl").toFile(); val keylog = File(downloads, "keys.log")
        val plan = Testcases.server("zerortt")!!
        HqInteropServer.start(identity(), port = 0, www = root.path, versions = plan.versions, earlyData = plan.earlyData).use { srv ->
            // on loopback the server answers the ClientHello within a millisecond, so whether the requests left before the client
            // had the 1-RTT keys was scheduling (1 failure in 6 runs, 2026-10-21); the relay holds the server's answer on the 0-RTT
            // connection until the requests arrived, as the runner's 30 ms round trip does, and the client is made to write only
            // once that answer exists, the order that used to send them in 1-RTT
            HandshakeHoldRelay(srv.port).use { relay ->
                srv.onEarlyStream = { n -> if (n == files.size - 1) relay.release() }
                HqInteropClient.beforeZeroRttRequests = { relay.answerSettled.await() }
                try {
                    val code = Interop.run(mapOf("ROLE" to "client", "TESTCASE" to "zerortt", "REQUESTS" to files.joinToString(" ") { "https://127.0.0.1:${relay.port}/${it.first}" }, "DOWNLOADS" to downloads.path, "SSLKEYLOGFILE" to keylog.path))
                    assertEquals(0, code); for ((n, b) in files) assertContentEquals(b, File(downloads, n).readBytes())
                    assertEquals(2, srv.connectionsAccepted); assertEquals(1, srv.earlyAcceptedConnections)
                    assertEquals(files.size - 1, srv.earlyStreams, "every request after the first arrived in 0-RTT")
                    assertTrue(keylog.readText().contains("CLIENT_EARLY_TRAFFIC_SECRET"), "the runner decrypts 0-RTT with the client's key log")
                } finally { HqInteropClient.beforeZeroRttRequests = {}; srv.onEarlyStream = null }
            }
        }
    }
}
