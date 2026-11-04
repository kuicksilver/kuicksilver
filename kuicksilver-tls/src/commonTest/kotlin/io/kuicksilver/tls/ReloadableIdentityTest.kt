// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(ExperimentalKuicksilverApi::class, io.kuicksilver.annotations.InternalKuicksilverApi::class)

package io.kuicksilver.tls

import io.ktor.utils.io.writeFully
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.native.Ksl
import io.kuicksilver.native.KslConst
import io.kuicksilver.native.KslLoader
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeout
import kotlinx.coroutines.withTimeoutOrNull
import kotlinx.coroutines.yield
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotNull
import kotlin.test.assertSame
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.seconds

/**
 * [TlsIdentity.Reloadable]: certificate rotation for new handshakes (RFC 9846 sections 4.5.1, 4.5.2), connections that keep
 * the identity they started with, resumption across a reload (section 4.7.1), and native keys freed only when nothing uses them.
 */
class ReloadableIdentityTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    private val leafA = Certificate(TestCerts.server)
    private val leafB = Certificate(TestCerts.serverViaIntermediate)

    private fun identityA() = TlsIdentity.fromDer(listOf(TestCerts.server), TestCerts.serverKey.copyOf())

    private fun identityB() =
        TlsIdentity.fromDer(listOf(TestCerts.serverViaIntermediate, TestCerts.intermediate), TestCerts.serverViaIntermediateKey.copyOf())

    // not TcpFixtures.server: that one makes (and never closes) an identity of its own, which the native key counts would see
    private fun server(id: TlsIdentity) =
        tlsConfig(TlsRole.Server) {
            alpn = listOf("x1")
            identity = id
        }

    /** A full handshake (a cache of its own, so nothing resumes) or, with [cache], one that may resume. */
    private suspend fun open(
        id: TlsIdentity,
        cache: SessionCache = SessionCache(),
    ): Pair<TlsConnection, TlsConnection> {
        val (cd, sd) = connect(TcpFixtures.client(), server(id), clientCache = cache)
        return withTimeout(20.seconds) { cd.await() to sd.await() }
    }

    /** Both directions carry [size] bytes; a connection whose keys or records broke fails here. */
    private suspend fun exchange(
        c: TlsConnection,
        s: TlsConnection,
        size: Int = 1024,
    ) {
        val up = ByteArray(size) { (it * 7).toByte() }
        val down = ByteArray(size) { (it * 13).toByte() }
        withTimeout(20.seconds) {
            c.output.writeFully(up, 0, size)
            c.output.flush()
            assertContentEquals(up, s.input.readExactly(size))
            s.output.writeFully(down, 0, size)
            s.output.flush()
            assertContentEquals(down, c.input.readExactly(size))
        }
    }

    private suspend fun closeAll(vararg cs: TlsConnection) = cs.forEach { it.close() }

    @Test fun newHandshakeSeesReloadedLeaf(): Unit =
        runBlocking {
            val r = TlsIdentity.reloadable(identityA())
            val (c1, s1) = open(r)
            assertEquals(leafA, c1.peerCertificates[0])
            r.reload(identityB())
            val (c2, s2) = open(r)
            assertEquals(leafB, c2.peerCertificates[0], "a handshake after the reload presents the new leaf")
            assertEquals(listOf(leafB, Certificate(TestCerts.intermediate)), c2.peerCertificates, "with the new chain")
            assertEquals(leafA, c1.peerCertificates[0])
            exchange(c1, s1)
            exchange(c2, s2)
            closeAll(c1, s1, c2, s2)
            r.close()
        }

    @Test fun liveConnectionKeepsOldIdentityAfterReload(): Unit =
        runBlocking {
            val a = identityA()
            val r = TlsIdentity.reloadable(a)
            val (c, s) = open(r)
            r.reload(identityB())
            assertTrue(a.isClosed, "reload closes the identity it replaces")
            // the connection's context still holds its reference to the old key: traffic and a key update go on
            c.keyUpdate(requestPeer = true)
            s.keyUpdate()
            exchange(c, s, 16 * 1024)
            closeAll(c, s)
            r.close()
        }

    @Test fun negative_mismatchedPairFailsBeforeReloadClosedIdentityRefused(): Unit =
        runBlocking {
            val a = identityA()
            val r = TlsIdentity.reloadable(a)
            assertFailsWith<TlsException.Config>("a key that does not belong to the leaf never becomes an identity") {
                TlsIdentity.fromDer(listOf(TestCerts.server), TestCerts.serverOtherKeyKey.copyOf())
            }
            val closed = identityB().also { it.close() }
            assertFailsWith<TlsException.Config> { r.reload(closed) }
            assertSame(a, r.current, "the old identity stays")
            assertTrue(!a.isClosed)
            val (c, s) = open(r)
            assertEquals(leafA, c.peerCertificates[0])
            closeAll(c, s)
            r.close()
        }

    @Test fun negative_reloadRejectsExpiredLeaf(): Unit =
        runBlocking {
            val a = identityA()
            val r = TlsIdentity.reloadable(a)
            val expired = TlsIdentity.fromDer(listOf(TestCerts.expired), TestCerts.expiredKey.copyOf())
            val e = assertFailsWith<TlsException.Config> { r.reload(expired) }
            assertTrue("expired" in e.message.orEmpty(), e.message)
            assertSame(a, r.current)
            assertTrue(!expired.isClosed, "a refused identity stays the caller's")
            expired.close()
            assertFailsWith<TlsException.Config>("an expired identity is not a starting point either") {
                TlsIdentity.reloadable(TlsIdentity.fromDer(listOf(TestCerts.expired), TestCerts.expiredKey.copyOf()))
            }
            r.close()
        }

    /** The expiry check uses the reloadable identity's clock: a leaf that expired by then is refused, on a virtual clock. */
    @Test fun negative_reloadRejectsLeafExpiredOnTheClock() {
        var now = nowSeconds()
        val r = TlsIdentity.Reloadable(identityA()) { now }
        val b = identityB()
        now = b.chain[0].notAfterEpochSeconds // still valid at notAfter (RFC 5280 section 4.1.2.5)
        r.reload(b)
        val b2 = identityB()
        now = b2.chain[0].notAfterEpochSeconds + 1
        assertFailsWith<TlsException.Config> { r.reload(b2) }
        assertSame(b, r.current)
        b2.close()
        r.close()
    }

    /** The checks read the clock once and name no time: a repeated failure reads the same (a watcher warns once). */
    @Test fun negative_expiredMessageIsStable() {
        var now = nowSeconds()
        val r = TlsIdentity.Reloadable(identityA()) { now }
        val b = identityB()
        now = b.chain[0].notAfterEpochSeconds + 1
        val m1 = assertFailsWith<TlsException.Config> { r.reload(b) }.message
        now += 1000
        val m2 = assertFailsWith<TlsException.Config> { r.reload(b) }.message
        assertEquals(m1, m2)
        b.close()
        r.close()
    }

    /** A certificate staged for later (notBefore ahead of the clock beyond 5 minutes of skew) is never served early. */
    @Test fun negative_reloadRejectsLeafNotYetValid() {
        val r = TlsIdentity.reloadable(identityA())
        val future = TlsIdentity.fromDer(listOf(TestCerts.notYetValid), TestCerts.notYetValidKey.copyOf())
        val e = assertFailsWith<TlsException.Config> { r.reload(future) }
        assertTrue("not valid yet" in e.message.orEmpty(), e.message)
        assertTrue(!future.isClosed)
        future.close()
        r.close()
        var now = nowSeconds()
        val clocked = TlsIdentity.Reloadable(identityA()) { now }
        val b = identityB()
        now = b.chain[0].notBeforeEpochSeconds - 301
        assertFailsWith<TlsException.Config>("notBefore 301 s ahead") { clocked.reload(b) }
        now = b.chain[0].notBeforeEpochSeconds - 299
        clocked.reload(b) // within the 5-minute skew allowance
        assertSame(b, clocked.current)
        clocked.close()
    }

    /** An identity closed by someone else while [TlsIdentity.Reloadable.reload] swaps it in is refused; the old one stays current and open. */
    @Test fun negative_identityClosedDuringReloadNeverBecomesCurrent() {
        val a = identityA()
        val r = TlsIdentity.reloadable(a)
        val b = identityB()
        r.afterExchangeForTest = { b.close() }
        assertFailsWith<TlsException.Config> { r.reload(b) }
        r.afterExchangeForTest = null
        assertSame(a, r.current)
        assertTrue(!a.isClosed)
        r.close()
    }

    /** The retry of `withCurrentKey`: a snapshot replaced and closed between its load and its use is retried with the new one. */
    @Test fun snapshotReplacedBeforeUseIsRetried() {
        val r = TlsIdentity.reloadable(identityA())
        val b = identityB()
        var loads = 0
        r.beforeAcquireForTest = { cur -> if (loads++ == 0) r.reload(b) } // closes `cur` (A) before it is used
        val used = r.withCurrentKey { cur, _ -> cur }
        r.beforeAcquireForTest = null
        assertSame(b, used, "the retry took the identity that replaced the closed snapshot")
        assertEquals(2, loads)
        r.close()
    }

    /**
     * A client's ticket remembers the client identity it was authenticated with: one that reached the cache key of another
     * identity (a reload between computing the key and building the context) is not resumed under it.
     */
    @Test fun negative_clientTicketOfAnotherClientIdentityNotResumed(): Unit =
        runBlocking {
            val x = TlsIdentity.reloadable(TlsIdentity.fromDer(listOf(TestCerts.client), TestCerts.clientKey.copyOf()))
            val server =
                tlsConfig(TlsRole.Server) {
                    alpn = listOf("x1")
                    identity = TlsIdentity.fromDer(listOf(TestCerts.server), TestCerts.serverKey.copyOf())
                    clientAuth = ClientAuth.Required
                    trust = TrustConfig.AnchoredCa(listOf(Fixtures.testCa))
                }
            val client = TcpFixtures.client { identity = x }
            val cache = SessionCache()
            val keyX = SessionCache.key(client.serverName, "server.test", client.trust, x)
            val (c1, s1) = connect(client, server, clientCache = cache).let { (c, s) -> withTimeout(20.seconds) { c.await() to s.await() } }
            exchange(c1, s1)
            closeAll(c1, s1)
            val entry = assertNotNull(cache.take(keyX), "ticket cached under the client identity X")
            x.reload(TlsIdentity.fromDer(listOf(TestCerts.clientNoEku), TestCerts.clientNoEkuKey.copyOf()))
            // as if the key was computed after the reload
            cache.put(SessionCache.key(client.serverName, "server.test", client.trust, x), entry)
            val (c2, s2) = connect(client, server, clientCache = cache).let { (c, s) -> withTimeout(20.seconds) { c.await() to s.await() } }
            assertTrue(!c2.sessionReused, "a session authenticated as X is not resumed with the identity Y")
            assertEquals(Certificate(TestCerts.clientNoEku), s2.peerCertificates[0], "the server sees the new client certificate")
            closeAll(c2, s2)
            x.close()
        }

    @Test fun reloadOfCurrentDoesNothing() {
        val a = identityA()
        val r = TlsIdentity.reloadable(a)
        r.reload(a)
        assertSame(a, r.current)
        assertTrue(!a.isClosed)
        r.close()
        assertTrue(a.isClosed, "close closes the current identity")
    }

    @Test fun negative_handshakeAndReloadAfterCloseFail(): Unit =
        runBlocking {
            val r = TlsIdentity.reloadable(identityA())
            r.close()
            assertFailsWith<IllegalStateException> { KslContext.create(server(r), quic = false).close() }
            val b = identityB()
            assertFailsWith<IllegalStateException> { r.reload(b) }
            assertTrue(!b.isClosed, "a refused identity stays the caller's")
            b.close()
        }

    /**
     * 200 handshakes race 200 reloads between A and B: each handshake presents one whole identity. A chain from one and a key
     * from the other is refused when the context is built (`SSL_CTX_check_private_key` in `ksl_ctx_set_identity_key`), which
     * fails that handshake, so every handshake succeeding with a leaf of A or B shows no pair was torn (RFC 9846 section 4.5.2:
     * CertificateVerify is signed with the key of the Certificate's leaf).
     */
    @Test fun reloadDuringHandshakesNeverTearsThePair(): Unit =
        runBlocking(Dispatchers.Default) {
            val r = TlsIdentity.reloadable(identityA())
            val n = 200
            val reloads =
                launch {
                    repeat(n) { i -> r.reload(if (i % 2 == 0) identityB() else identityA()) }
                }
            val conns = List(n) { async { open(r) } }.awaitAll()
            reloads.join()
            for ((c, _) in conns) assertTrue(c.peerCertificates[0] == leafA || c.peerCertificates[0] == leafB, "${c.peerCertificates}")
            conns.forEach { (c, s) -> closeAll(c, s) }
            r.close()
        }

    /**
     * A ticket is bound to the leaf certificate it was issued under (RFC 9846 section 4.7.1: resumption keying material is limited
     * by the certificate's lifetime): after a reload it resumes nothing, the client runs a full handshake and sees the new leaf,
     * and the ticket of that handshake resumes under the new identity.
     */
    @Test fun negative_ticketIssuedBeforeReloadIsNotResumed(): Unit =
        runBlocking {
            val r = TlsIdentity.reloadable(identityA())
            val cache = SessionCache()
            val client = TcpFixtures.client()
            val key = SessionCache.key(client.serverName, "server.test", client.trust, null)
            val (c0, s0) = open(r, cache)
            exchange(c0, s0) // the server's tickets travel before its data, so they are cached once the data arrived
            closeAll(c0, s0)
            val (c1, s1) = open(r, cache)
            assertTrue(c1.sessionReused && s1.sessionReused, "control: before the reload the ticket resumes")
            exchange(c1, s1)
            closeAll(c1, s1)
            assertTrue(cache.peek(key), "a renewed ticket cached")
            r.reload(identityB())
            val (c2, s2) = open(r, cache)
            assertTrue(!c2.sessionReused && !s2.sessionReused, "a ticket from before the reload is not resumed")
            assertEquals(leafB, c2.peerCertificates[0], "the full handshake presents the new identity")
            exchange(c2, s2)
            closeAll(c2, s2)
            val (c3, s3) = open(r, cache)
            assertTrue(c3.sessionReused && s3.sessionReused, "the ticket issued under the new identity resumes")
            assertEquals(leafB, c3.peerCertificates[0])
            closeAll(c3, s3)
            r.close()
        }

    /**
     * Many reloads with connections built from each identity: once the connections and the reloadable identity are closed, every
     * native key and context is gone again (`ksl.pkey`, `ksl.ctx`), so a long-running server leaks nothing per rotation.
     */
    @Test fun reloadManyTimesFreesEveryNativeKey(): Unit =
        runBlocking {
            withContext(Dispatchers.Default) {
                val before = Ksl.liveObjects()
                val r = TlsIdentity.reloadable(identityA())
                val conns = ArrayList<Pair<TlsConnection, TlsConnection>>()
                repeat(300) { i ->
                    r.reload(if (i % 2 == 0) identityB() else identityA())
                    if (i % 30 == 0) conns += open(r) // a connection holds the key of its identity past that identity's close
                }
                val during = Ksl.liveObjects()
                assertEquals(1L, during[KslConst.LIVE_PKEY] - before[KslConst.LIVE_PKEY], "only the current key is a live handle")
                conns.forEach { (c, s) -> exchange(c, s) }
                conns.forEach { (c, s) -> closeAll(c, s) }
                r.close()
                // a closed connection frees its context once its pumps stopped, on another coroutine: wait for that, with a deadline
                val settled =
                    withTimeoutOrNull(20.seconds) {
                        while (Ksl.liveObjects()[KslConst.LIVE_CTX] > before[KslConst.LIVE_CTX]) yield()
                        true
                    }
                val after = Ksl.liveObjects()
                assertEquals(before[KslConst.LIVE_PKEY], after[KslConst.LIVE_PKEY], "native keys left after 300 reloads")
                assertTrue(
                    settled == true,
                    "native contexts left after 300 reloads: ${before[KslConst.LIVE_CTX]} before, ${after[KslConst.LIVE_CTX]} after",
                )
            }
        }
}
