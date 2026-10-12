// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(DelicateKuicksilverApi::class, io.kuicksilver.annotations.InternalKuicksilverApi::class)

package io.kuicksilver.tls

import io.ktor.utils.io.ByteReadChannel
import io.ktor.utils.io.ByteWriteChannel
import io.ktor.utils.io.readAvailable
import io.ktor.utils.io.writeFully
import io.kuicksilver.annotations.DelicateKuicksilverApi
import io.kuicksilver.native.Ksl
import io.kuicksilver.native.KslConst
import io.kuicksilver.native.KslLoader
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeout
import java.io.File
import java.lang.management.ManagementFactory
import java.nio.file.Files
import java.nio.file.attribute.PosixFilePermission
import java.nio.file.attribute.PosixFilePermissions
import javax.management.MBeanServer
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFails
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.seconds

/** Key material never lands on the JVM heap (ADR-0003): a heap dump after a handshake does not contain the connection's secrets. */
class SecretsJvmTest {
    @BeforeTest fun load() {
        KslLoader.ensureLoaded()
        runBlocking { SessionCache.Default.clear() }
    }

    @Test fun negative_keylogFileMode0600() {
        val f =
            File.createTempFile("ksl-keylog", ".txt").also {
                it.delete()
                it.deleteOnExit()
            }
        keylogFile(f.path).log("CLIENT_RANDOM 00 11")
        val perms = Files.getPosixFilePermissions(f.toPath())
        assertTrue(PosixFilePermission.GROUP_READ !in perms && PosixFilePermission.OTHERS_READ !in perms, perms.toString())
        assertEquals("CLIENT_RANDOM 00 11\n", f.readText())
    }

    /** An existing world-readable file is tightened to 0600 before the first line lands in it. */
    @Test fun negative_keylogFileExistingModeTightened() {
        val f = File.createTempFile("ksl-keylog", ".txt").also { it.deleteOnExit() }
        Files.setPosixFilePermissions(f.toPath(), PosixFilePermissions.fromString("rw-r--r--"))
        keylogFile(f.path).log("X")
        val perms = Files.getPosixFilePermissions(f.toPath())
        assertTrue(PosixFilePermission.GROUP_READ !in perms && PosixFilePermission.OTHERS_READ !in perms, perms.toString())
        assertEquals("X\n", f.readText())
    }

    /** A symlink at the keylog path is refused outright: not one line goes into the file it points to. */
    @Test fun negative_keylogFileRefusesSymlink() {
        val target = File.createTempFile("ksl-keylog-target", ".txt").also { it.deleteOnExit() }
        val link =
            File.createTempFile("ksl-keylog-link", ".txt").also {
                it.delete()
                it.deleteOnExit()
            }
        Files.createSymbolicLink(link.toPath(), target.toPath())
        assertFails { keylogFile(link.path).log("X") }
        assertEquals(0L, target.length(), "nothing was written through the symlink")
    }

    @Test fun negative_keylogDisabledInRelease() {
        // the Gradle test task sets SSLKEYLOGFILE; neither OpenSSL (no-sslkeylog) nor the library may touch it
        val env = System.getenv("SSLKEYLOGFILE")
        assertTrue(!env.isNullOrBlank(), "test task must set SSLKEYLOGFILE")
        val p = Pump(KslQuicCrypto.newSession(Fixtures.client()), KslQuicCrypto.newSession(Fixtures.server()))
        p.c.setTransportParameters(Fixtures.tp)
        p.s.setTransportParameters(Fixtures.tp)
        try {
            p.run()
            assertTrue(p.cs.done)
        } finally {
            p.close()
        }
        assertFalse(File(env).exists(), "SSLKEYLOGFILE=$env must not be created")
    }

    @Test fun negative_heapDumpNoSecrets() {
        val log = File.createTempFile("ksl-keylog", ".txt").also { it.deleteOnExit() }
        val sink = keylogFile(log.path) // writes straight to disk; nothing retained on the heap
        val p = Pump(KslQuicCrypto.newSession(Fixtures.client { keylog = sink }), KslQuicCrypto.newSession(Fixtures.server()))
        p.c.setTransportParameters(Fixtures.tp)
        p.s.setTransportParameters(Fixtures.tp)
        val dump: File
        try {
            p.run()
            assertTrue(p.cs.done && p.ss.done)
            dump =
                File.createTempFile("ksl-heap", ".hprof").also {
                    it.delete()
                    it.deleteOnExit()
                }
            System.gc()
            val server: MBeanServer = ManagementFactory.getPlatformMBeanServer()
            val bean =
                ManagementFactory.newPlatformMXBeanProxy(
                    server,
                    "com.sun.management:type=HotSpotDiagnostic",
                    com.sun.management.HotSpotDiagnosticMXBean::class.java,
                )
            bean.dumpHeap(dump.path, true)
        } finally {
            p.close()
        }
        val secrets =
            log.readLines().filter { it.isNotBlank() }.map { line ->
                line
                    .split(' ')[2]
                    .chunked(2)
                    .map { it.toInt(16).toByte() }
                    .toByteArray()
            }
        assertTrue(secrets.size >= 4, "keylog has the handshake secrets")
        val heap = dump.readBytes()
        for (s in secrets) assertFalse(contains(heap, s), "a TLS secret of this connection was found in the heap dump")
        assertTrue(contains(heap, "kuicksilver".encodeToByteArray()), "sanity: the dump is searchable")
    }

    /**
     * An identity's private key lives in OpenSSL only (ksl ABI 5): while a [TlsIdentity.InMemory] and a context built from it
     * are alive, a heap dump holds no copy of the EC private scalar. The key is one no other test touches, so the only heap
     * copy is the array handed to `fromDer` (zeroed there); the needle is kept masked until the dump is written.
     */
    @Test fun negative_heapDumpNoIdentityPrivateKey() {
        val der = TestCerts.clientNoEkuKey // the lazily cached array itself: fromDer zeroes it
        val at = (0 until der.size - 34).first { der[it] == 0x04.toByte() && der[it + 1] == 0x20.toByte() && der[it - 3] == 0x02.toByte() } + 2
        val masked = ByteArray(32) { (der[at + it].toInt() xor 0x5a).toByte() }
        val id = TlsIdentity.fromDer(listOf(TestCerts.clientNoEku), der)
        assertTrue(der.all { it == 0.toByte() }, "fromDer zeroes the caller's array")
        val ctx = KslContext.create(tlsConfig(TlsRole.Server) { alpn = listOf("x"); identity = id }, quic = false)
        val dump =
            File.createTempFile("ksl-heap", ".hprof").also {
                it.delete()
                it.deleteOnExit()
            }
        try {
            System.gc()
            val bean =
                ManagementFactory.newPlatformMXBeanProxy(
                    ManagementFactory.getPlatformMBeanServer(),
                    "com.sun.management:type=HotSpotDiagnostic",
                    com.sun.management.HotSpotDiagnosticMXBean::class.java,
                )
            bean.dumpHeap(dump.path, true)
            assertEquals(1, id.chain.size) // the identity is reachable while the heap is dumped
        } finally {
            ctx.close()
            id.close()
        }
        val heap = dump.readBytes()
        val scalar = ByteArray(32) { (masked[it].toInt() xor 0x5a).toByte() }
        assertFalse(contains(heap, scalar), "the identity's private key was found in the heap dump")
        assertTrue(contains(heap, "kuicksilver".encodeToByteArray()), "sanity: the dump is searchable")
    }

    /**
     * A TCP client keeps its resumption ticket for later connections. The session (master secret, resumption PSK) must stay
     * native: the heap holds a handle, never `i2d_SSL_SESSION` bytes. TLS 1.2 makes the check exact: the session's master key is the
     * `CLIENT_RANDOM` secret of the keylog. The server is a raw TLS 1.2-only `ksl` session (TlsConfig cannot cap a peer at 1.2).
     */
    @Test fun negative_heapDumpNoSecretsTcpSessionCache(): Unit =
        runBlocking {
            val log = File.createTempFile("ksl-keylog", ".txt").also { it.deleteOnExit() }
            val pair = ChannelPair()
            val server = async(Dispatchers.Default) { tls12Server(pair.serverIn, pair.serverOut) }
            val client =
                withTimeout(20.seconds) {
                    TlsConnection.client(
                        pair.clientIn,
                        pair.clientOut,
                        TcpFixtures.client {
                            versions =
                                TlsVersions.Tls12And13
                            ; keylog = keylogFile(log.path)
                        },
                    )
                }
            try {
                assertEquals(TlsVersion.Tls12, client.protocolVersion)
                withTimeout(5.seconds) { while (SessionCache.Default.size() == 0) delay(10) } // the ticket is cached from the reader pump
            } finally {
                client.close()
                server.cancel()
            }
            val dump =
                File.createTempFile("ksl-heap", ".hprof").also {
                    it.delete()
                    it.deleteOnExit()
                }
            withContext(Dispatchers.IO) {
                System.gc()
                ManagementFactory
                    .newPlatformMXBeanProxy(
                        ManagementFactory.getPlatformMBeanServer(),
                        "com.sun.management:type=HotSpotDiagnostic",
                        com.sun.management.HotSpotDiagnosticMXBean::class.java,
                    ).dumpHeap(dump.path, true)
            }
            val master =
                log
                    .readLines()
                    .single {
                        it.startsWith(
                            "CLIENT_RANDOM ",
                        )
                    }.split(' ')[2]
                    .chunked(2)
                    .map { it.toInt(16).toByte() }
                    .toByteArray()
            assertEquals(48, master.size)
            assertEquals(1, SessionCache.Default.size(), "the session is still cached when the heap is dumped")
            val heap = dump.readBytes()
            assertFalse(contains(heap, master), "the cached TLS session's master secret was found in the heap dump")
            assertTrue(contains(heap, "kuicksilver".encodeToByteArray()), "sanity: the dump is searchable")
        }

    /** A TLS 1.2-only server over raw `ksl` that issues a ticket in its handshake flight and stops once the handshake is done. */
    private suspend fun tls12Server(
        input: ByteReadChannel,
        output: ByteWriteChannel,
    ) {
        val ctx = Ksl.ctxNew(KslConst.SERVER)
        val ssl: Long
        try {
            Ksl.ctxSetAlpn(ctx, byteArrayOf(2, 'x'.code.toByte(), '1'.code.toByte()))
            Ksl.ctxSetIdentity(ctx, listOf(TestCerts.server), TestCerts.serverKey.copyOf())
            Ksl.ctxSetOption(ctx, KslConst.OPT_MIN_VERSION, KslConst.TLS1_2)
            Ksl.ctxSetOption(ctx, KslConst.OPT_MAX_VERSION, KslConst.TLS1_2)
            Ksl.ctxSetTicketKeys(ctx, listOf(Ksl.rand(80)))
            Ksl.ctxSetOption(ctx, KslConst.OPT_NUM_TICKETS, 1)
            Ksl.ctxFreeze(ctx)
            ssl = Ksl.sslNew(ctx, KslConst.MODE_TCP)
        } catch (t: Throwable) {
            Ksl.ctxFree(ctx)
            throw t
        }
        val buf = ByteArray(16 * 1024)
        try {
            while (true) {
                val rc = Ksl.drive(ssl)
                while (true) {
                    val n = Ksl.tcpDrain(ssl, buf, 0, buf.size)
                    if (n <= 0) break
                    output.writeFully(buf, 0, n)
                }
                output.flush()
                if (rc == KslConst.OK) return
                val n = input.readAvailable(buf, 0, buf.size)
                if (n < 0) return
                var off = 0
                while (off < n) {
                    val used = Ksl.tcpFeed(ssl, buf, off, n - off)
                    if (used <= 0) return
                    off += used
                }
            }
        } finally {
            Ksl.sslFree(ssl)
            Ksl.ctxFree(ctx)
        }
    }

    private fun contains(
        hay: ByteArray,
        needle: ByteArray,
    ): Boolean {
        if (needle.isEmpty() || hay.size < needle.size) return false
        val first = needle[0]
        var i = 0
        while (i <= hay.size - needle.size) {
            if (hay[i] == first) {
                var j = 1
                while (j < needle.size && hay[i + j] == needle[j]) j++
                if (j == needle.size) return true
            }
            i++
        }
        return false
    }
}
