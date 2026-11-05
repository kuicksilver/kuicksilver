// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(ExperimentalKuicksilverApi::class, io.kuicksilver.annotations.InternalKuicksilverApi::class)

package io.kuicksilver.tls

import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.native.Ksl
import io.kuicksilver.native.KslConst
import io.kuicksilver.native.KslLoader
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotSame
import kotlin.test.assertSame
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.seconds

/**
 * One native context (`SSL_CTX`) per server configuration and identity snapshot, shared by every handshake of that
 * configuration (P.3): built once, freed when the identity snapshot is closed (a reload closes the one it replaces) and its
 * last connection is gone, never while a connection uses it.
 */
class SharedServerContextTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    private fun identityA() = TlsIdentity.fromDer(listOf(TestCerts.server), TestCerts.serverKey.copyOf())

    private fun identityB() =
        TlsIdentity.fromDer(listOf(TestCerts.serverViaIntermediate, TestCerts.intermediate), TestCerts.serverViaIntermediateKey.copyOf())

    private fun quicServer(id: TlsIdentity) =
        tlsConfig(TlsRole.Server) {
            alpn = listOf("h3")
            identity = id
        }

    private fun session(
        config: TlsConfig,
        earlyData: Boolean = true,
    ) = KslQuicCrypto.newSession(config, earlyData) as KslQuicTlsSession

    /** `ksl.ctx`; other tests' connections may still be freeing theirs, so counts are compared as "never more than". */
    private fun liveContexts() = Ksl.liveObjects()[KslConst.LIVE_CTX]

    @Test fun quicServerSessionsShareOneContext() {
        val id = identityA()
        val config = quicServer(id)
        val before = liveContexts()
        val sessions = List(20) { session(config) }
        val ctx = sessions[0].context
        for (s in sessions) assertSame(ctx, s.context, "every session of one configuration uses one context")
        assertTrue(liveContexts() <= before + 1, "20 sessions built one native context (ksl.ctx $before -> ${liveContexts()})")
        sessions.forEach { it.close() }
        assertFalse(ctx.isFreed, "kept for the next connection while the identity is open")
        val later = session(config)
        assertSame(ctx, later.context, "a later connection reuses it")
        later.close()
        id.close()
        assertTrue(ctx.isFreed, "closing the identity frees the context once no connection uses it")
        assertTrue(liveContexts() <= before, "ksl.ctx back to $before (now ${liveContexts()})")
    }

    @Test fun contextOutlivesIdentityCloseUntilItsLastSession() {
        val id = identityA()
        val config = quicServer(id)
        val s = session(config)
        id.close()
        assertFalse(s.context.isFreed, "a running connection keeps its context after the identity closed")
        assertFailsWith<IllegalStateException>("no new handshake on a closed identity") { session(config) }
        s.close()
        assertTrue(s.context.isFreed, "freed with its last connection")
    }

    @Test fun reloadBuildsOneMoreContextAndFreesTheOldOneAfterItsLastSession() {
        val before = liveContexts()
        val r = TlsIdentity.reloadable(identityA())
        val config = quicServer(r)
        val old = List(5) { session(config) }
        val ctxA = old[0].context
        for (s in old) assertSame(ctxA, s.context)
        r.reload(identityB())
        assertFalse(ctxA.isFreed, "the old context serves its connections after the reload")
        val new = List(5) { session(config) }
        val ctxB = new[0].context
        assertNotSame(ctxA, ctxB, "the first handshake after the reload builds a context from the new identity")
        for (s in new) assertSame(ctxB, s.context, "and the next ones share it")
        assertTrue(liveContexts() <= before + 2, "exactly one more context (ksl.ctx $before -> ${liveContexts()})")
        old.dropLast(1).forEach { it.close() }
        assertFalse(ctxA.isFreed, "not freed while one connection still uses it")
        old.last().close()
        assertTrue(ctxA.isFreed, "the old context is freed after its last connection")
        new.forEach { it.close() }
        assertFalse(ctxB.isFreed, "the current identity keeps its context")
        r.close()
        assertTrue(ctxB.isFreed)
        assertTrue(liveContexts() <= before, "ksl.ctx back to $before (now ${liveContexts()})")
    }

    @Test fun eachConfigurationAndKindHasItsOwnContext() {
        val id = identityA()
        val one = quicServer(id)
        val two = quicServer(id)
        val a = session(one)
        val b = session(two)
        val c = session(one, earlyData = false)
        assertNotSame(a.context, b.context, "another configuration with the same identity: another context")
        assertNotSame(a.context, c.context, "a session without 0-RTT tickets: another context")
        assertSame(c.context, session(one, earlyData = false).also { it.close() }.context)
        listOf(a, b, c).forEach { it.close() }
        id.close()
        assertTrue(a.context.isFreed && b.context.isFreed && c.context.isFreed)
    }

    @Test fun anIdentityKeepsAtMostEightIdleContexts() {
        val id = identityA()
        val configs = List(9) { quicServer(id) }
        val contexts = configs.map { cfg -> session(cfg).also { it.close() }.context }
        assertTrue(contexts[0].isFreed, "the ninth configuration's context evicts the oldest idle one")
        assertTrue(contexts.drop(1).none { it.isFreed }, "the other eight stay")
        val busy = session(configs[1])
        assertSame(contexts[1], busy.context)
        val more = List(8) { quicServer(id) }.map { cfg -> session(cfg).also { it.close() }.context }
        assertFalse(contexts[1].isFreed, "an evicted context in use lives until its last connection")
        busy.close()
        assertTrue(contexts[1].isFreed)
        id.close()
        assertTrue(more.all { it.isFreed } && contexts.all { it.isFreed })
    }

    @Test fun tcpServerConnectionsShareOneContext(): Unit =
        runBlocking {
            val id = identityA()
            val server =
                tlsConfig(TlsRole.Server) {
                    alpn = listOf("x1")
                    identity = id
                }
            val conns =
                List(4) {
                    val (c, s) = connect(TcpFixtures.client(), server, clientCache = SessionCache())
                    withTimeout(20.seconds) { c.await() to s.await() }
                }
            val ctx = conns[0].second.contextForTest
            for ((_, s) in conns) assertSame(ctx, s.contextForTest, "every TCP connection of one server configuration uses one context")
            assertEquals(4, conns.map { it.first.peerCertificates[0] }.count { it == Certificate(TestCerts.server) })
            conns.forEach { (c, s) ->
                c.close()
                s.close()
            }
            id.close()
        }
}
