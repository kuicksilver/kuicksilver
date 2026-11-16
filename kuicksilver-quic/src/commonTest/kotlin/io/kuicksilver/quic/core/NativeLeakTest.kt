// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.core

import io.kuicksilver.annotations.DelicateKuicksilverApi
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.native.KslLoader
import io.kuicksilver.native.PacketBuffer
import io.kuicksilver.native.of
import io.kuicksilver.native.toByteArray
import io.kuicksilver.quic.ConnectionCore
import io.kuicksilver.quic.ConnectionEvent
import io.kuicksilver.quic.ConnectionState
import io.kuicksilver.quic.CoreFixtures
import io.kuicksilver.quic.CorePair
import io.kuicksilver.quic.Ecn
import io.kuicksilver.quic.LeakTrackingCrypto
import io.kuicksilver.quic.QuicConfig
import io.kuicksilver.quic.VersionProfile
import io.kuicksilver.quic.ksl
import io.kuicksilver.quic.nativeConnectionObjects
import io.kuicksilver.quic.quicConfig
import io.kuicksilver.quic.wire.ConnectionId
import io.kuicksilver.quic.wire.PacketHeaderCodec
import io.kuicksilver.quic.wire.PacketHeaderView
import io.kuicksilver.quic.wire.VersionNegotiationPacket
import io.kuicksilver.tls.Certificate
import io.kuicksilver.tls.EarlyDataState
import io.kuicksilver.tls.QuicCrypto
import io.kuicksilver.tls.QuicSessionTicket
import io.kuicksilver.tls.QuicTlsSession
import io.kuicksilver.tls.TlsConfig
import io.kuicksilver.tls.TlsEvent
import io.kuicksilver.tls.TlsRole
import io.kuicksilver.tls.TrustConfig
import kotlin.random.Random
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.seconds

/**
 * Every native object a connection makes (TLS session, packet protectors of every level and key phase, keys the provider
 * hands it) is freed by the connection itself once it reached its terminal state, however it ended: closed by either
 * side, a failed handshake, Version Negotiation, Retry, a rejected or accepted 0-RTT, key updates, a lost peer (idle and
 * handshake timeouts), a stateless reset; and a connection whose construction failed holds none. Checked twice: per
 * object through [LeakTrackingCrypto] before anything else releases the cores (the test's own release would hide a
 * connection that never frees), and through ksl's live-object counters after the test released everything (an object
 * made inside ksl that never reached Kotlin).
 */
@OptIn(ExperimentalKuicksilverApi::class, DelicateKuicksilverApi::class)
class NativeLeakTest {
    @BeforeTest fun load() {
        KslLoader.ensureLoaded()
        // what a process makes once and keeps (the receivers' shared empty buffer, cached contexts) is made before counting
        ConnectionCore
            .client(
                QuicConfig.Default,
                CoreFixtures.client(),
                ksl,
                CoreFixtures.serverAddr,
                Random(1),
                io.kuicksilver.quic.TimeMark(1),
                null,
            ).release()
    }

    private fun CorePair.bothClosed(): Boolean =
        client.state == ConnectionState.Closed && (server?.state ?: ConnectionState.Closed) == ConnectionState.Closed

    /**
     * Runs [scenario] on a pair built by [pair] with a [LeakTrackingCrypto] over ksl, then lets virtual time pass until both
     * cores are Closed (idle timeouts included), and checks that nothing they made is still open.
     */
    private fun leakFree(
        pair: (QuicCrypto) -> CorePair,
        scenario: (CorePair) -> Unit,
    ) {
        val before = nativeConnectionObjects()
        val crypto = LeakTrackingCrypto(ksl)
        val p = pair(crypto)
        try {
            scenario(p)
            assertTrue(
                p.runUntil(limit = 120.seconds, tick = 50.milliseconds) {
                    p.bothClosed()
                },
                "both cores end: ${p.client.state} ${p.server?.state}",
            )
            assertEquals(emptyList(), crypto.live, "native objects left open by connections that ended")
            assertTrue(crypto.made > 0)
        } finally {
            p.close()
        }
        assertEquals(before, nativeConnectionObjects(), "ksl objects (sessions, keys, session references) left after the test")
    }

    private fun handshakeAndRun(p: CorePair) {
        assertTrue(p.handshake())
        assertTrue(
            p.runUntil(limit = 2.seconds) {
                p.client.state == ConnectionState.Confirmed &&
                    p.server!!.state == ConnectionState.Confirmed
            },
        )
    }

    @Test fun closedByTheClient() =
        leakFree({ CorePair(crypto = it) }) { p ->
            handshakeAndRun(p)
            p.client.close(0, "bye", p.now)
        }

    @Test fun closedByTheServer() =
        leakFree({ CorePair(crypto = it) }) { p ->
            handshakeAndRun(p)
            p.server!!.close(7, "bye", p.now)
        }

    @Test fun negative_handshakeFailure() =
        leakFree({
            CorePair(
                clientTls = CoreFixtures.client(trust = TrustConfig.AnchoredCa(listOf(Certificate(io.kuicksilver.quic.TestCerts.otherCa)))),
                crypto = it,
            )
        }) { p ->
            assertTrue(p.runUntil(limit = 3.seconds) { p.closedReason(p.clientEvents) != null })
        }

    /** RFC 9001 section 8.2: the 1-RTT keys arrive in the same flight as the missing extension's verdict. */
    @Test fun negative_missingTransportParameters() {
        for (role in listOf(TlsRole.Server, TlsRole.Client)) {
            leakFree({ CorePair(crypto = WithoutPeerTp(it, role)) }) { p ->
                assertTrue(
                    p.runUntil(limit = 3.seconds) {
                        p.closedReason(if (role == TlsRole.Client) p.clientEvents else p.serverEvents) !=
                            null
                    },
                )
            }
        }
    }

    /** Three updates by the client, each followed by the server: every generation's keys and the derived next ones. */
    @Test fun negative_keyUpdates() =
        leakFree({ CorePair(crypto = it) }) { p ->
            handshakeAndRun(p)
            repeat(3) { round ->
                assertTrue(p.runUntil(limit = 5.seconds) { p.client.initiateKeyUpdate(p.now) }, "update $round")
                // ack-eliciting packets in the new phase: the client may update again once the server acknowledged one
                val id = p.client.openStream(bidi = true)
                p.client.writeStream(id, ByteArray(3000) { it.toByte() }, 0, 3000, fin = true)
                p.runUntil(limit = 2.seconds) { false } // the server follows, the old read key's window passes
            }
            assertEquals(3L, p.client.stats.keyUpdates)
            assertEquals(3L, p.server!!.stats.keyUpdates)
            p.client.close(0, "", p.now)
        }

    /**
     * The derivation of the next 1-RTT keys fails (a native allocation that fails) while a side builds its key phase, for
     * its read or its write key, server (calls 1 and 2) or client (3 and 4): the connection fails, and what was derived
     * before the failure is closed with it.
     */
    @Test fun negative_nextKeysFailToDerive() {
        for (failAt in 1..4) {
            val before = nativeConnectionObjects()
            val crypto = LeakTrackingCrypto(ksl, failNext = failAt)
            val p = CorePair(crypto = crypto)
            p.use { _ ->
                // as the endpoint loop does: what a core throws fails it (failInternal); here both cores, whichever threw
                var failed = false
                while (!failed && p.now < io.kuicksilver.quic.TimeMark(1_000_000_000L) + 3.seconds) {
                    try {
                        p.step()
                    } catch (e: IllegalStateException) {
                        p.client.failInternal(e)
                        p.server?.failInternal(e)
                        failed = true
                    }
                    p.advance(5.milliseconds)
                }
                assertTrue(failed, "failing at next() call $failAt: the derivation was reached")
                assertTrue(p.runUntil(limit = 1.seconds) { p.bothClosed() }, "failing at $failAt: ${p.client.state} ${p.server?.state}")
                assertEquals(emptyList(), crypto.live, "failing at next() call $failAt")
            }
            assertEquals(before, nativeConnectionObjects(), "failing at $failAt")
        }
    }

    /** Ended while the previous generation's read key is still kept for reordered packets (RFC 9001 section 6.1). */
    @Test fun negative_endedRightAfterAKeyUpdate() =
        leakFree({ CorePair(crypto = it) }) { p ->
            handshakeAndRun(p)
            // the first update keeps generation 0 as the old key, which is also the header-protection key: the second
            // keeps generation 1, which only the key phase holds
            assertTrue(p.client.initiateKeyUpdate(p.now))
            val first = p.client.openStream(bidi = true)
            p.client.writeStream(first, ByteArray(3000) { it.toByte() }, 0, 3000, fin = true)
            p.runUntil(limit = 2.seconds) { false }
            assertTrue(p.runUntil(limit = 5.seconds) { p.client.initiateKeyUpdate(p.now) })
            val id = p.client.openStream(bidi = true)
            p.client.writeStream(id, ByteArray(3000) { it.toByte() }, 0, 3000, fin = true)
            // the server's first packets of the new phase reach the client, which keeps its old read key for 3 x PTO
            assertTrue(
                p.runUntil(limit = 1.seconds, tick = 1.milliseconds) {
                    p.client.keyPhaseForTest!!.discardAt != io.kuicksilver.quic.TimeMark.NEVER
                },
            )
            // ended at once (an internal failure closes silently): the old key is still held when the core is released
            p.client.failInternal(IllegalStateException("ended at once (test)"))
            p.server!!.close(0, "", p.now)
        }

    @Test fun negative_peerLostAfterTheHandshake() =
        leakFree({ CorePair(crypto = it) }) { p ->
            handshakeAndRun(p)
            p.filterToServer = { _, _ -> false }
            p.filterToClient = { _, _ -> false } // idle timeout on both sides
        }

    @Test fun negative_peerLostDuringTheHandshake() =
        leakFree({ CorePair(crypto = it) }) { p ->
            p.step()
            p.filterToServer = { _, _ -> false }
            p.filterToClient = { _, _ -> false } // handshake timeout
        }

    @Test fun negative_versionNegotiationRestart() =
        leakFree({ CorePair(clientQuic = quicConfig { versions = listOf(VersionProfile.V2, VersionProfile.V1) }, crypto = it) }) { p ->
            var fed = false
            p.filterToServer = { _, b ->
                if (!fed) {
                    fed = true
                    feed(p, vn(b, VersionProfile.V1.version))
                    false
                } else {
                    true
                }
            }
            handshakeAndRun(p)
            p.client.close(0, "", p.now)
        }

    @Test fun negative_versionNegotiationWithoutACommonVersion() =
        leakFree({ CorePair(crypto = it) }) { p ->
            p.filterToServer = { _, b ->
                feed(p, vn(b, 0x0a0a0a0a))
                false
            }
            assertTrue(p.runUntil(limit = 1.seconds) { p.client.state == ConnectionState.Closed })
        }

    /** RFC 9368: the server answers in the version the client prefers less, keeping the original version's Initial keys. */
    @Test fun negative_compatibleVersionUpgrade() =
        leakFree({
            CorePair(
                clientQuic = quicConfig { versions = listOf(VersionProfile.V1, VersionProfile.V2) },
                serverQuic = quicConfig { versions = listOf(VersionProfile.V2, VersionProfile.V1) },
                crypto = it,
            )
        }) { p ->
            handshakeAndRun(p)
            assertEquals(VersionProfile.V2, p.client.version)
            p.server!!.close(0, "", p.now)
        }

    /** The upgraded server is cut off before it dropped its Initial keys: the original version's read key goes with it. */
    @Test fun negative_compatibleUpgradeLostDuringTheHandshake() =
        leakFree({
            CorePair(
                clientQuic = quicConfig { versions = listOf(VersionProfile.V1, VersionProfile.V2) },
                serverQuic = quicConfig { versions = listOf(VersionProfile.V2, VersionProfile.V1) },
                crypto = it,
            )
        }) { p ->
            assertTrue(p.runUntil(limit = 1.seconds) { p.server?.initialReadOriginal != null }, "the server switched to version 2")
            p.filterToServer = { _, _ -> false }
            p.filterToClient = { _, _ -> false } // handshake timeouts
        }

    @Test fun negative_retry() =
        leakFree({ CorePair(crypto = it) }) { p ->
            var retried = false
            p.filterToServer = { _, _ -> retried } // the first flight reaches a stateless server, which answers with a Retry
            p.step()
            retried = true
            val scid = ConnectionId(ByteArray(8) { 0x42 })
            p.serverAfterRetry = p.client.odcid to scid
            p.client.onRetry(scid, ByteArray(16) { 7 })
            handshakeAndRun(p)
            p.client.close(0, "", p.now)
        }

    @Test fun negative_statelessReset() =
        leakFree({ CorePair(crypto = it) }) { p ->
            handshakeAndRun(p)
            // the token of the server's handshake ID, the one in use
            val token =
                p.client.cids
                    .peerTokensForTest()
                    .first()
                    .second
            val reset = Random(5).nextBytes(40).also { it[0] = 0x40 }
            token!!.copyInto(reset, reset.size - 16)
            feed(p, reset)
            assertEquals(ConnectionState.Draining, p.client.state, "the datagram was taken as a stateless reset")
            p.filterToServer = { _, _ -> false } // the client sends nothing more; the server ends at its idle timeout
        }

    /** Endpoints with stateless reset keys: every connection ID's token is computed in a scratch buffer, freed each time. */
    @Test fun negative_resetTokensFromKeys() {
        val keys = listOf(ksl.newResetKey(), ksl.newResetKey())
        try {
            leakFree({ CorePair(crypto = it, clientResetKey = keys[0], serverResetKey = keys[1]) }) { p ->
                handshakeAndRun(p)
                p.runUntil(limit = 1.seconds) { false } // NEW_CONNECTION_ID frames, each with its token
                p.client.close(0, "", p.now)
            }
        } finally {
            keys.forEach { it.close() }
        }
    }

    @Test fun negative_zeroRttRejected() {
        val ticket = ticket()
        try {
            leakFree({
                CorePair(
                    crypto = it,
                    clientEarly = EarlyDataState.Allowed,
                    serverEarly = early(app = byteArrayOf(9)), // another application context: the server refuses the 0-RTT
                    clientSetup = { c -> early0Rtt(c, ticket) },
                )
            }) { p ->
                handshakeAndRun(p)
                assertTrue(p.clientEvents.any { it === ConnectionEvent.EarlyDataRejected })
                p.client.close(0, "", p.now)
            }
        } finally {
            ticket.close()
        }
    }

    @Test fun zeroRttAccepted() {
        val ticket = ticket()
        try {
            leakFree({
                CorePair(crypto = it, clientEarly = EarlyDataState.Allowed, serverEarly = early(), clientSetup = { c ->
                    early0Rtt(c, ticket)
                })
            }) { p ->
                handshakeAndRun(p)
                assertTrue(p.clientEvents.any { it === ConnectionEvent.EarlyDataAccepted })
                p.client.close(0, "", p.now)
            }
        } finally {
            ticket.close()
        }
    }

    /**
     * 0-RTT accepted, rejected: the connection runs past 3 x PTO after the client's first 1-RTT packet, so the server drops
     * its 0-RTT read key on its timer (RFC 9001 section 4.9.3) before the connection ends.
     */
    @Test fun negative_zeroRttKeysDroppedOnTheirTimer() {
        for (accepted in listOf(true, false)) {
            val ticket = ticket()
            try {
                leakFree({
                    CorePair(
                        crypto = it,
                        clientEarly = EarlyDataState.Allowed,
                        serverEarly = if (accepted) early() else early(app = byteArrayOf(9)),
                        clientSetup = { c -> early0Rtt(c, ticket) },
                    )
                }) { p ->
                    handshakeAndRun(p)
                    if (accepted) {
                        assertTrue(p.server!!.readKeys[1] != null, "the server still holds its 0-RTT read key")
                        assertTrue(p.runUntil(limit = 5.seconds) { p.server!!.readKeys[1] == null }, "dropped on its timer")
                    }
                    p.runUntil(limit = 2.seconds) { false }
                    p.client.close(0, "", p.now)
                }
            } finally {
                ticket.close()
            }
        }
    }

    /** RFC 9369 section 5: a version 1 ticket is not used for a version 2 connection; the core closes it unused. */
    @Test fun negative_aTicketOfAnotherVersionIsClosed() {
        val v2 = quicConfig { versions = listOf(VersionProfile.V2) }
        var used: Boolean? = null
        var ticket: QuicSessionTicket? = null
        leakFree({
            // the ticket is made after the count began: the core must close it, or the count stays one session higher
            ticket = ticket()
            CorePair(
                clientQuic = v2,
                serverQuic = quicConfig { versions = listOf(VersionProfile.V2, VersionProfile.V1) },
                crypto = it,
                clientEarly = EarlyDataState.Allowed,
                serverEarly = early(),
                clientSetup = { c -> used = c.useTicket(ticket) },
            )
        }) { p ->
            assertEquals(false, used)
            assertEquals(true, ticket?.closed, "closed unused")
            handshakeAndRun(p)
            p.runUntil(limit = 1.seconds) { false }
            // the new connection's own tickets are the application's: it closes them
            p.clientEvents.filterIsInstance<ConnectionEvent.SessionTicket>().forEach { it.ticket.close() }
            p.client.close(0, "", p.now)
        }
    }

    /**
     * Session tickets where the core takes none: one on a server's session, and one on a client's before the server's
     * transport parameters (a TLS stack a conformant one is not); the core closes each.
     */
    @Test fun negative_unexpectedTicketsAreClosed() {
        for (role in listOf(TlsRole.Server, TlsRole.Client)) {
            leakFree({ CorePair(crypto = WithTicket(it, role, ticket())) }) { p ->
                handshakeAndRun(p)
                p.client.close(0, "", p.now)
            }
        }
    }

    /**
     * A provider whose TLS stack hands out keys a conformant one never does (QuicCrypto is a public interface): a second
     * Handshake key for each direction, a 0-RTT key in the direction a client never uses, a Handshake key after the
     * handshake was confirmed and its space dropped. The core closes every key it does not keep.
     */
    @Test fun negative_unexpectedKeysFromTheTlsStack() {
        var odd: OddKeys? = null
        leakFree({ OddKeys(it).also { k -> odd = k }.let { k -> CorePair(crypto = k) } }) { p ->
            handshakeAndRun(p)
            odd!!.releaseLate = true
            p.client.tlsDirty = true // a post-handshake TLS message (a NewSessionTicket) runs the client's TLS again
            assertTrue(p.runUntil(limit = 2.seconds) { odd.lateDelivered }, "the late Handshake key reached the client")
            p.client.close(0, "", p.now)
        }
        assertEquals(4, odd!!.extra, "two Handshake duplicates, a 0-RTT read key, a late Handshake key")
    }

    /** The connection's construction fails after its TLS session was made: nobody can close the core, so it frees it. */
    @Test fun negative_clientConstructionFailsAfterTheSession() {
        val before = nativeConnectionObjects()
        val crypto = LeakTrackingCrypto(ksl, failInitialProtectors = 1)
        assertFailsWith<IllegalStateException> {
            ConnectionCore.client(
                QuicConfig.Default,
                CoreFixtures.client(),
                crypto,
                CoreFixtures.serverAddr,
                Random(1),
                io.kuicksilver.quic.TimeMark(1),
                null,
            )
        }
        assertEquals(emptyList(), crypto.live)
        assertEquals(before, nativeConnectionObjects())
    }

    /** The reset token of the client's first connection ID, computed with the endpoint's key, fails. */
    @Test fun negative_clientConstructionFailsInTheResetToken() {
        val before = nativeConnectionObjects()
        val crypto = LeakTrackingCrypto(ksl)
        val key = ksl.newResetKey()
        val failing =
            object : io.kuicksilver.tls.ResetKey by key {
                override fun token(
                    cid: PacketBuffer,
                    offset: Int,
                    length: Int,
                    out: ByteArray,
                    outOffset: Int,
                ): Unit = throw IllegalStateException("reset token refused (test)")
            }
        try {
            assertFailsWith<IllegalStateException> {
                ConnectionCore.client(
                    QuicConfig.Default,
                    CoreFixtures.client(),
                    crypto,
                    CoreFixtures.serverAddr,
                    Random(1),
                    io.kuicksilver.quic.TimeMark(1),
                    failing,
                )
            }
            assertEquals(emptyList(), crypto.live)
        } finally {
            key.close()
        }
        assertEquals(before, nativeConnectionObjects())
    }

    @Test fun negative_serverConstructionFailsAfterTheSession() {
        for (failing in listOf("transport parameters", "initial keys")) {
            val before = nativeConnectionObjects()
            val crypto =
                LeakTrackingCrypto(
                    ksl,
                    failTransportParameters = TlsRole.Server.takeIf { failing == "transport parameters" },
                    // call 1 is the client's; call 2 the server's
                    failInitialProtectors = if (failing == "initial keys") 2 else Int.MAX_VALUE,
                )
            val p = CorePair(crypto = crypto)
            p.use { _ ->
                assertFailsWith<IllegalStateException>(failing) { p.step() }
                assertTrue(crypto.live.none { "Server" in it }, "$failing: ${crypto.live}")
            }
            assertEquals(emptyList(), crypto.live, failing)
            assertEquals(before, nativeConnectionObjects(), failing)
        }
    }

    // ---- helpers ----

    private fun feed(
        p: CorePair,
        bytes: ByteArray,
    ) {
        val b = PacketBuffer.of(bytes)
        try {
            p.client.handleDatagram(b, bytes.size, CoreFixtures.serverAddr, Ecn.NotEct, p.now)
        } finally {
            b.close()
        }
    }

    private fun vn(
        initial: ByteArray,
        vararg versions: Int,
    ): ByteArray {
        val b = PacketBuffer.of(initial)
        val out = PacketBuffer.allocate(1200)
        try {
            val v = PacketHeaderView()
            check(PacketHeaderCodec.parse(b, 0, initial.size, 8, v))
            val n = VersionNegotiationPacket.write(out, b, v.scidOff, v.scidLen, b, v.dcidOff, v.dcidLen, versions, 0x12, 1200)
            return out.toByteArray(n)
        } finally {
            b.close()
            out.close()
        }
    }

    private val register =
        io.kuicksilver.quic.endpoint
            .ZeroRttReplayRegister(Random(5))

    private fun early(app: ByteArray? = null) = ServerEarlyData.of(QuicConfig.Default, CoreFixtures.server().alpn, app, register)

    /** A full handshake (plain ksl, not counted) that leaves the client a ticket for 0-RTT. */
    private fun ticket(): QuicSessionTicket {
        val p = CorePair(crypto = ksl, clientEarly = EarlyDataState.Allowed, serverEarly = early())
        p.use { _ ->
            assertTrue(p.handshake())
            assertTrue(p.runUntil(limit = 2.seconds) { p.clientEvents.any { it is ConnectionEvent.SessionTicket } })
            val tickets = p.clientEvents.filterIsInstance<ConnectionEvent.SessionTicket>().map { it.ticket }
            tickets.dropLast(1).forEach { it.close() }
            return tickets.last()
        }
    }

    private fun early0Rtt(
        c: ConnectionCore,
        ticket: QuicSessionTicket,
    ) {
        assertTrue(c.useTicket(ticket))
        val id = c.openStream(bidi = true)
        c.writeStream(id, "GET /".encodeToByteArray(), 0, 5, fin = true)
    }
}

/**
 * Client sessions whose events carry extra keys: before each Handshake key, one derived from it (the real one replaces
 * it); with the first 1-RTT key, a 0-RTT read key; and, at the first TLS run once [releaseLate] is set, a late Handshake key.
 */
@OptIn(DelicateKuicksilverApi::class, ExperimentalKuicksilverApi::class)
private class OddKeys(
    private val inner: QuicCrypto,
) : QuicCrypto by inner {
    var extra = 0
    var lateDelivered = false

    /** Set by the test once the handshake is confirmed: the late key goes out at the client's next TLS run. */
    var releaseLate = false

    override fun newSession(config: TlsConfig): QuicTlsSession = wrap(config, inner.newSession(config))

    override fun newSession(
        config: TlsConfig,
        earlyData: Boolean,
    ): QuicTlsSession = wrap(config, inner.newSession(config, earlyData))

    private fun wrap(
        config: TlsConfig,
        s: QuicTlsSession,
    ): QuicTlsSession {
        if (config.role != TlsRole.Client) return s
        val queued = ArrayDeque<TlsEvent>()
        var late: TlsEvent? = null
        return object : QuicTlsSession by s {
            override fun nextEvent(): TlsEvent? {
                queued.removeFirstOrNull()?.let { return it }
                val e = s.nextEvent()
                if (e == null) {
                    if (releaseLate && late != null) {
                        lateDelivered = true
                        return late.also { late = null }
                    }
                    return null
                }
                if (e !is TlsEvent.Keys) return e
                when (e.level) {
                    io.kuicksilver.tls.EncryptionLevel.Handshake -> {
                        extra++
                        queued += e
                        return TlsEvent.Keys(e.level, e.direction, e.protector.next())
                    }

                    io.kuicksilver.tls.EncryptionLevel.Application -> {
                        if (late == null && !lateDelivered) {
                            extra += 2
                            queued +=
                                TlsEvent.Keys(
                                    io.kuicksilver.tls.EncryptionLevel.EarlyData,
                                    io.kuicksilver.tls.Direction.Read,
                                    e.protector.next(),
                                )
                            late =
                                TlsEvent.Keys(
                                    io.kuicksilver.tls.EncryptionLevel.Handshake,
                                    io.kuicksilver.tls.Direction.Read,
                                    e.protector.next(),
                                )
                        }
                        return e
                    }

                    else -> {
                        return e
                    }
                }
            }
        }
    }
}

/** The session of [role] never reports the peer's transport parameters, as if the extension were absent. */
@OptIn(DelicateKuicksilverApi::class)
private class WithoutPeerTp(
    private val inner: QuicCrypto,
    private val role: TlsRole,
) : QuicCrypto by inner {
    override fun newSession(config: TlsConfig): QuicTlsSession = wrap(config, inner.newSession(config))

    override fun newSession(
        config: TlsConfig,
        earlyData: Boolean,
    ): QuicTlsSession = wrap(config, inner.newSession(config, earlyData))

    private fun wrap(
        config: TlsConfig,
        s: QuicTlsSession,
    ): QuicTlsSession =
        if (config.role != role) {
            s
        } else {
            object : QuicTlsSession by s {
                override fun nextEvent(): TlsEvent? {
                    while (true) {
                        val e = s.nextEvent() ?: return null
                        if (e !is TlsEvent.PeerTransportParameters) return e
                    }
                }
            }
        }
}

/** The first event of the [role]'s session is a session ticket ([ticket]), before anything else of its handshake. */
@OptIn(DelicateKuicksilverApi::class, ExperimentalKuicksilverApi::class)
private class WithTicket(
    private val inner: QuicCrypto,
    private val role: TlsRole,
    private var ticket: QuicSessionTicket?,
) : QuicCrypto by inner {
    override fun newSession(config: TlsConfig): QuicTlsSession = wrap(config, inner.newSession(config))

    override fun newSession(
        config: TlsConfig,
        earlyData: Boolean,
    ): QuicTlsSession = wrap(config, inner.newSession(config, earlyData))

    private fun wrap(
        config: TlsConfig,
        s: QuicTlsSession,
    ): QuicTlsSession =
        if (config.role != role) {
            s
        } else {
            object : QuicTlsSession by s {
                override fun nextEvent(): TlsEvent? = ticket?.let { t -> TlsEvent.SessionTicket(t).also { ticket = null } } ?: s.nextEvent()
            }
        }
}
