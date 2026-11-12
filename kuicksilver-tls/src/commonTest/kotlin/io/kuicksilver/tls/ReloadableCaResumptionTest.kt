// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(ExperimentalKuicksilverApi::class, io.kuicksilver.annotations.InternalKuicksilverApi::class)

package io.kuicksilver.tls

import io.ktor.utils.io.ByteReadChannel
import io.ktor.utils.io.ByteWriteChannel
import io.ktor.utils.io.readAvailable
import io.ktor.utils.io.writeFully
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.native.Ksl
import io.kuicksilver.native.KslConst
import io.kuicksilver.native.KslLoader
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.async
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotEquals
import kotlin.test.assertSame
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.seconds

/**
 * [TrustConfig.ReloadableCa] and resumption beyond TLS 1.3 over TCP: QUIC tickets (the session ID context of a QUIC server
 * that issues them), 0-RTT, and TLS 1.2 tickets. A session authenticated under one bundle never resumes under another; a
 * server that asks for no client certificate is not affected by reloads at all.
 */
class ReloadableCaResumptionTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    private val testCa = TrustConfig.AnchoredCa(listOf(Certificate(TestCerts.testCa)))
    private val otherCa = TrustConfig.AnchoredCa(listOf(Certificate(TestCerts.otherCa)))
    private val both = TrustConfig.AnchoredCa(listOf(Certificate(TestCerts.testCa), Certificate(TestCerts.otherCa)))

    /** Admits every hello once. */
    private class Once : EarlyDataAdmission {
        val seen = ArrayList<ByteArray>()

        override fun admit(ticketId: ByteArray): Boolean = seen.none { it.contentEquals(ticketId) }.also { if (it) seen += ticketId }

        override fun release(ticketId: ByteArray) {
            seen.removeAll { it.contentEquals(ticketId) }
        }
    }

    private class Run(
        val pump: Pump,
        val tickets: List<QuicSessionTicket>,
        val earlyKeys: Int,
    )

    private fun handshake(
        client: QuicTlsSession,
        server: QuicTlsSession,
    ): Run {
        client.setTransportParameters(Fixtures.tp)
        server.setTransportParameters(Fixtures.tp)
        val tickets = ArrayList<QuicSessionTicket>()
        var early = 0
        val p = Pump(client, server)
        p.onEvent = { fromClient, ev ->
            if (fromClient && ev is TlsEvent.SessionTicket) tickets += ev.ticket
            if (!fromClient && ev is TlsEvent.Keys && ev.level == EncryptionLevel.EarlyData) early++
        }
        p.run()
        return Run(p, tickets, early)
    }

    private fun quicClientA() = Fixtures.client { identity = TlsIdentity.fromDer(listOf(TestCerts.client), TestCerts.clientKey.copyOf()) }

    /**
     * QUIC with client certificates and tickets (a server whose tickets carry no 0-RTT, since 0-RTT and client certificates
     * do not combine): a ticket resumes under its bundle, not after a reload, and not at all once the client's CA is dropped.
     */
    @Test fun negative_quicTicketFromBeforeCaReloadIsNotResumed() {
        val r = TrustConfig.reloadable(testCa)
        val config =
            Fixtures.server {
                clientAuth = ClientAuth.Required
                trust = r
            }

        fun server() =
            KslQuicCrypto.newSessionForTest(config, ticketsWithoutEarlyData = true).also {
                assertTrue(it.enableEarlyData(byteArrayOf(1), Once()))
            }

        fun resumeWith(ticket: QuicSessionTicket): Run {
            val c = KslQuicCrypto.newSession(quicClientA(), earlyData = true)
            assertTrue(c.resume(ticket))
            return handshake(c, server())
        }
        val first = handshake(KslQuicCrypto.newSession(quicClientA(), earlyData = true), server())
        assertTrue(first.pump.cs.done && first.pump.ss.done)
        assertTrue(first.tickets.isNotEmpty(), "a full handshake issues tickets")
        first.pump.close()
        val resumed = resumeWith(first.tickets[0])
        assertTrue(resumed.pump.ss.done)
        assertTrue((resumed.pump.s as KslQuicTlsSession).sessionReusedForTest, "control: before the reload the ticket resumes")
        resumed.pump.close()
        r.reload(both)
        val afterReload = resumeWith(resumed.tickets[0])
        assertTrue(afterReload.pump.ss.done, "the client's CA is still in the bundle: a full handshake succeeds")
        assertFalse((afterReload.pump.s as KslQuicTlsSession).sessionReusedForTest, "a full handshake, not a resumption")
        afterReload.pump.close()
        r.reload(otherCa)
        val dropped = resumeWith(afterReload.tickets[0])
        assertIs<DriveResult.Failed>(dropped.pump.ss.last, "the dropped CA's client gets in neither by handshake nor by ticket")
        dropped.pump.close()
        (first.tickets.drop(1) + resumed.tickets.drop(1) + afterReload.tickets.drop(1) + dropped.tickets).forEach { it.close() }
        (config.identity as TlsIdentity.InMemory).close()
    }

    /**
     * A QUIC server with 0-RTT asks for no client certificate, so its ReloadableCa plays no part: a reload builds no other
     * context, and a ticket from before it resumes with 0-RTT accepted.
     */
    @Test fun quicZeroRttUnaffectedByReloadWithoutClientCertificates() {
        val r = TrustConfig.reloadable(testCa)
        val config = Fixtures.server { trust = r }
        val s0 = KslQuicCrypto.newSession(config, earlyData = true) as KslQuicTlsSession
        assertTrue(s0.enableEarlyData(byteArrayOf(1), Once()))
        val first = handshake(KslQuicCrypto.newSession(Fixtures.client(), earlyData = true), s0)
        val ctx = s0.context
        first.pump.close()
        r.reload(otherCa)
        val c = KslQuicCrypto.newSession(Fixtures.client(), earlyData = true)
        assertTrue(c.resume(first.tickets[0]))
        assertTrue(c.enableEarlyData(null, null))
        val s = KslQuicCrypto.newSession(config, earlyData = true) as KslQuicTlsSession
        assertSame(ctx, s.context, "no context of its own for the new bundle")
        assertTrue(s.enableEarlyData(byteArrayOf(1), Once()))
        val again = handshake(c, s)
        assertEquals(1, again.earlyKeys, "0-RTT accepted after the reload")
        assertEquals(true, s.earlyDataAccepted)
        again.pump.close()
        (first.tickets.drop(1) + again.tickets).forEach { it.close() }
        (config.identity as TlsIdentity.InMemory).close()
    }

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)

    /** A raw `ksl` TLS 1.2 client presenting the test CA's client certificate, resuming [session] when given. */
    private suspend fun tls12(
        server: TlsConfig,
        session: Long = 0L,
    ): Triple<Int, Long, Result<TlsConnection>> {
        val pair = ChannelPair()
        val sd = scope.async { runCatching { TlsConnection.server(pair.serverIn, pair.serverOut, server) } }
        val ctx = Ksl.ctxNew(KslConst.CLIENT)
        try {
            Ksl.ctxSetAlpn(ctx, byteArrayOf(2, 'x'.code.toByte(), '1'.code.toByte()))
            Ksl.ctxSetIdentity(ctx, listOf(TestCerts.client), TestCerts.clientKey.copyOf())
            Ksl.ctxSetOption(ctx, KslConst.OPT_MIN_VERSION, KslConst.TLS1_2)
            Ksl.ctxSetOption(ctx, KslConst.OPT_MAX_VERSION, KslConst.TLS1_2)
            Ksl.ctxSetOption(ctx, KslConst.OPT_VERIFY_MODE, KslConst.VERIFY_NONE)
            Ksl.ctxFreeze(ctx)
            val ssl = Ksl.sslNew(ctx, KslConst.MODE_TCP)
            try {
                if (session != 0L) Ksl.sslSetSession(ssl, session)
                val rc = withTimeout(20.seconds) { rawHandshake(ssl, pair.clientIn, pair.clientOut) }
                val reused = if (rc == KslConst.OK) Ksl.sslGet(ssl, KslConst.GET_SESSION_REUSED)[0].toInt() else -1
                val got = if (rc == KslConst.OK) Ksl.sslGet1Session(ssl) else 0L
                return Triple(reused, got, withTimeout(20.seconds) { sd.await() })
            } finally {
                Ksl.sslFree(ssl)
            }
        } finally {
            Ksl.ctxFree(ctx)
        }
    }

    private suspend fun rawHandshake(
        ssl: Long,
        input: ByteReadChannel,
        output: ByteWriteChannel,
    ): Int {
        val buf = ByteArray(16 * 1024)
        while (true) {
            val rc =
                try {
                    Ksl.drive(ssl)
                } catch (_: io.kuicksilver.native.KslException) {
                    return KslConst.ERROR
                }
            while (true) {
                val n = Ksl.tcpDrain(ssl, buf, 0, buf.size)
                if (n <= 0) break
                output.writeFully(buf, 0, n)
            }
            output.flush()
            if (rc != KslConst.WANT_READ) return rc
            val n = input.readAvailable(buf, 0, buf.size)
            if (n < 0) return rc
            var off = 0
            while (off < n) {
                val used = Ksl.tcpFeed(ssl, buf, off, n - off)
                if (used <= 0) return rc
                off += used
            }
        }
    }

    /** TLS 1.2 tickets (issued in the handshake) are bound to the bundle as TLS 1.3 ones are. */
    @Test fun negative_tls12TicketFromBeforeCaReloadIsNotResumed(): Unit =
        runBlocking {
            val r = TrustConfig.reloadable(testCa)
            val server =
                TcpFixtures.server {
                    versions = TlsVersions.Tls12And13
                    clientAuth = ClientAuth.Required
                    trust = r
                }
            val (reused0, session, s0) = tls12(server)
            assertEquals(0, reused0, "a full handshake")
            assertNotEquals(0L, session, "a TLS 1.2 ticket was issued")
            s0.getOrThrow().close()
            val (reused1, session1, s1) = tls12(server, session)
            assertEquals(1, reused1, "control: the ticket resumes under its bundle")
            s1.getOrThrow().close()
            if (session1 != 0L) Ksl.sessionFree(session1)
            r.reload(both)
            val (reused2, session2, s2) = tls12(server, session)
            assertEquals(0, reused2, "after the reload: a full handshake")
            s2.getOrThrow().close()
            if (session2 != 0L) Ksl.sessionFree(session2)
            r.reload(otherCa)
            val (_, session3, s3) = tls12(server, session)
            assertFailsWith<TlsException.Verify>("the dropped CA's client is refused, ticket or not") { s3.getOrThrow() }
            if (session3 != 0L) Ksl.sessionFree(session3)
            Ksl.sessionFree(session)
        }
}
