// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(io.kuicksilver.annotations.InternalKuicksilverApi::class)

package io.kuicksilver.tls

import io.ktor.utils.io.ByteReadChannel
import io.ktor.utils.io.ByteWriteChannel
import io.ktor.utils.io.readAvailable
import io.ktor.utils.io.writeFully
import io.kuicksilver.native.Ksl
import io.kuicksilver.native.KslConst
import io.kuicksilver.native.KslLoader
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.async
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue
import kotlin.time.Duration
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.seconds
import kotlin.time.TimeSource

/**
 * RFC 9325 section 3.4: "TLS 1.2 does not roll the session key forward within a single session. Thus, to prevent an attack
 * where the server's ticket-encryption key is stolen and used to decrypt the entire content of a session (negating the concept
 * of forward secrecy), a TLS 1.2 server SHOULD NOT resume sessions that are too old, e.g., sessions that have been open longer
 * than two ticket-encryption key rotation periods." A TLS 1.2 session resumes for at most [SessionTicketConfig.ticketLifetime]
 * after its full handshake, however often its ticket was renewed: OpenSSL keeps the session's time in a renewed TLS 1.2 ticket
 * (only a TLS 1.3 ticket gets a fresh one, `ssl/statem/statem_srvr.c` `tls_construct_new_session_ticket`), and the lifetime is
 * at most half of [SessionTicketConfig.rotateEvery], well inside two rotation periods.
 */
class Tls12ResumptionWindowTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)

    @AfterTest fun stop() = scope.cancel()

    /**
     * Rotation every 4 s (explicit keys, which the library never rotates, so other tests' tickets are not touched), tickets
     * for 2 s: renewed every half second, the chain still ends within the first ticket's lifetime (whole seconds of the
     * session time, so between 1 and 2 s after the full handshake) and a full handshake runs. The wait between attempts lets
     * the wall clock, which the ticket checks read, move on.
     */
    @Test fun negative_tls12SessionNotResumedPastTheFirstTicketsLifetime(): Unit =
        runBlocking {
            val server =
                TcpFixtures.server {
                    versions = TlsVersions.Tls12And13
                    sessionTickets =
                        SessionTicketConfig(
                            listOf(ByteArray(80) { (it * 5 + 9).toByte() }),
                            rotateEvery = 4.seconds,
                            ticketLifetime = 2.seconds,
                        )
                }
            val started = TimeSource.Monotonic.markNow()
            var (reused, session) = tls12(server, 0L)
            assertEquals(0, reused, "a full handshake")
            assertNotEquals(0L, session, "a TLS 1.2 ticket was issued")
            var resumptions = 0
            var refusedAt: Duration? = null
            while (started.elapsedNow() < 8.seconds) {
                delay(250.milliseconds)
                val (r, next) = tls12(server, session)
                Ksl.sessionFree(session)
                session = next
                if (r == 0) {
                    refusedAt = started.elapsedNow()
                    break
                }
                assertEquals(1, r, "the handshake completed")
                resumptions++
            }
            if (session != 0L) Ksl.sessionFree(session)
            assertTrue(resumptions > 0, "control: the renewed ticket resumed at first")
            assertNotNull(refusedAt, "the renewed TLS 1.2 tickets kept resuming for 8 s")
            assertTrue(refusedAt <= 3.seconds, "the chain outlived the first ticket's 2 s lifetime: $refusedAt")
        }

    /** A raw `ksl` client capped at TLS 1.2 (TlsConfig cannot cap a client there), resuming [session] when not 0. */
    private suspend fun tls12(
        server: TlsConfig,
        session: Long,
    ): Pair<Int, Long> {
        val pair = ChannelPair()
        val sd = scope.async { runCatching { TlsConnection.server(pair.serverIn, pair.serverOut, server) } }
        val ctx = Ksl.ctxNew(KslConst.CLIENT)
        try {
            Ksl.ctxSetAlpn(ctx, byteArrayOf(2, 'x'.code.toByte(), '1'.code.toByte()))
            Ksl.ctxSetOption(ctx, KslConst.OPT_MIN_VERSION, KslConst.TLS1_2)
            Ksl.ctxSetOption(ctx, KslConst.OPT_MAX_VERSION, KslConst.TLS1_2)
            Ksl.ctxSetOption(ctx, KslConst.OPT_VERIFY_MODE, KslConst.VERIFY_NONE)
            Ksl.ctxFreeze(ctx)
            val ssl = Ksl.sslNew(ctx, KslConst.MODE_TCP)
            try {
                if (session != 0L) Ksl.sslSetSession(ssl, session)
                val rc = withTimeout(20.seconds) { rawHandshake(ssl, pair.clientIn, pair.clientOut) }
                assertEquals(KslConst.OK, rc, "the TLS 1.2 handshake completes")
                assertEquals(listOf<Byte>(3, 3), Ksl.sslGet(ssl, KslConst.GET_VERSION).toList())
                val reused = Ksl.sslGet(ssl, KslConst.GET_SESSION_REUSED)[0].toInt()
                val got = Ksl.sslGet1Session(ssl)
                withTimeout(20.seconds) { sd.await() }.getOrThrow().close()
                return reused to got
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
}
