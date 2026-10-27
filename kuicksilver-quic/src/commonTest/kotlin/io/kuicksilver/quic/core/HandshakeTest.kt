// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.core

import io.kuicksilver.annotations.DelicateKuicksilverApi
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.native.KslLoader
import io.kuicksilver.native.PacketBuffer
import io.kuicksilver.native.of
import io.kuicksilver.native.toByteArray
import io.kuicksilver.quic.ConnectionEvent
import io.kuicksilver.quic.ConnectionState
import io.kuicksilver.quic.CoreFixtures
import io.kuicksilver.quic.CorePair
import io.kuicksilver.quic.Initiator
import io.kuicksilver.quic.QuicException
import io.kuicksilver.quic.StreamPriority
import io.kuicksilver.quic.TestCerts
import io.kuicksilver.quic.ksl
import io.kuicksilver.quic.nullDatagramHasAckElicitingInitial
import io.kuicksilver.quic.wire.PacketHeaderCodec
import io.kuicksilver.quic.wire.PacketHeaderView
import io.kuicksilver.tls.Certificate
import io.kuicksilver.tls.EncryptionLevel
import io.kuicksilver.tls.QuicCrypto
import io.kuicksilver.tls.QuicTlsSession
import io.kuicksilver.tls.TlsConfig
import io.kuicksilver.tls.TlsEvent
import io.kuicksilver.tls.TlsException
import io.kuicksilver.tls.TlsRole
import io.kuicksilver.tls.TrustConfig
import io.kuicksilver.tls.VerifyResult
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.seconds

@OptIn(ExperimentalKuicksilverApi::class, DelicateKuicksilverApi::class)
class HandshakeTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    /**
     * A Null-crypto pair whose client completed its handshake while every client datagram after the ClientHello was held back:
     * [held] carries the client's Finished; [oneRtt] are 1-RTT packets (cut out of their datagrams) with a STREAM frame
     * opening client stream 0 with "hello". The server holds 1-RTT read keys from the ClientHello on (as BoringSSL's QUIC API).
     */
    private class HeldFinished(
        val p: CorePair,
        val held: List<ByteArray>,
        val oneRtt: List<ByteArray>,
    )

    private fun heldFinished(): HeldFinished {
        val p = CorePair()
        val held = ArrayList<ByteArray>()
        p.filterToServer = { i, b ->
            if (i > 0) held += b
            i == 0
        }
        assertTrue(p.runUntil { p.clientEvents.any { it is ConnectionEvent.HandshakeCompleted } })
        val s = p.server!!
        assertTrue(s.readKeys[3] != null && s.state == ConnectionState.Handshaking, "the server reads 1-RTT before the Finished")
        val id = p.client.openStream(true)
        val hello = "hello".encodeToByteArray()
        p.client.writeStream(id, hello, 0, hello.size, true)
        val oneRtt = pollOneRtt(p)
        assertTrue(oneRtt.isNotEmpty(), "the client sent 1-RTT packets")
        return HeldFinished(p, held, oneRtt)
    }

    /** Polls the client once; the 1-RTT packets of its datagrams, cut out of them (a short header runs to the datagram's end). */
    private fun pollOneRtt(p: CorePair): List<ByteArray> {
        p.batch.clear()
        val n = p.client.poll(p.batch, p.now)
        val oneRtt = ArrayList<ByteArray>()
        val hv = PacketHeaderView()
        for (i in 0 until n) {
            val d = p.batch.buffer(i).toByteArray(p.batch.length(i))
            val b = PacketBuffer.of(d)
            try {
                var off = 0
                while (off < d.size && PacketHeaderCodec.parse(b, off, d.size, p.server!!.localCid.length, hv)) {
                    if (d[off].toInt() and 0x80 == 0) {
                        oneRtt += d.copyOfRange(off, d.size)
                        break
                    }
                    off = hv.packetEnd
                }
            } finally {
                b.close()
            }
        }
        return oneRtt
    }

    private fun feed(
        p: CorePair,
        d: ByteArray,
    ) {
        val b = PacketBuffer.of(d)
        try {
            p.server!!.handleDatagram(b, d.size, CoreFixtures.clientAddr, io.kuicksilver.quic.Ecn.NotEct, p.now)
        } finally {
            b.close()
        }
        p.drainEvents(p.server!!, p.serverEvents)
    }

    private fun streamEvents(events: List<ConnectionEvent>) =
        events.filter { it is ConnectionEvent.StreamOpened || it is ConnectionEvent.StreamReadable }

    /**
     * RFC 9001 section 5.7: "a server MUST NOT process incoming 1-RTT protected packets before the TLS handshake is complete";
     * they "MAY be stored and later decrypted and used once the handshake is complete." A client's STREAM in 1-RTT, alone or
     * coalesced behind a Finished that fails, must not reach the application; after a valid Finished it does.
     */
    @Test fun negative_serverDefersOneRttUntilFinished() {
        // 1. the 1-RTT packets arrive before the Finished: held; the Finished then completes the handshake and releases them
        val a = heldFinished()
        try {
            val s = a.p.server!!
            for (d in a.oneRtt) feed(a.p, d)
            assertEquals(emptyList(), streamEvents(a.p.serverEvents), "no stream before the Finished")
            assertEquals(ConnectionState.Handshaking, s.state)
            for (d in a.held) feed(a.p, d)
            val done = a.p.serverEvents.indexOfFirst { it is ConnectionEvent.HandshakeCompleted }
            assertTrue(done >= 0, "the Finished completes the handshake: ${a.p.serverEvents}")
            val opened = a.p.serverEvents.indexOfFirst { it is ConnectionEvent.StreamOpened }
            assertTrue(opened > done, "the stored 1-RTT packet is used once the handshake completed: ${a.p.serverEvents}")
            val buf = ByteArray(16)
            assertEquals("hello", buf.decodeToString(0, s.readStream(0, buf, 0, buf.size)))
        } finally {
            a.p.close()
        }
        // 2. one datagram, [Initial][Handshake(Finished, corrupted)][1-RTT(STREAM)]: the Finished fails, the STREAM is never used
        val b = heldFinished()
        try {
            val withFinished = b.held.first { d -> finishedAt(d) >= 0 }.copyOf()
            withFinished[finishedAt(withFinished)] = 21 // a TLS message other than Finished (type 20): NullTlsSession fails
            feed(b.p, withFinished + b.oneRtt.first())
            b.p.runUntil(limit = 1.seconds) { b.p.closedReason(b.p.serverEvents) != null }
            assertTrue(b.p.closedReason(b.p.serverEvents) != null, "the bad Finished fails the handshake")
            assertEquals(emptyList(), streamEvents(b.p.serverEvents), "the STREAM behind the bad Finished was not processed")
        } finally {
            b.p.close()
        }
    }

    /**
     * A datagram whose only packet is a held 1-RTT packet (RFC 9001 section 5.7) was processed, just not yet: it is no
     * candidate Stateless Reset (RFC 9000 section 10.3.1) and must not count as an invalid one.
     */
    @Test fun heldOneRttPacketIsNoStatelessResetCandidate() {
        val a = heldFinished()
        try {
            val s = a.p.server!!
            val before = s.invalidResets
            for (d in a.oneRtt) feed(a.p, d)
            assertTrue(s.receiver.bufferedCount >= a.oneRtt.size, "held: ${s.receiver.bufferedCount}")
            assertEquals(before, s.invalidResets, "no Stateless Reset check on a held packet")
        } finally {
            a.p.close()
        }
    }

    /**
     * RFC 9001 section 5.7: held 1-RTT packets share the 32-slot cap (`QuicLimits.undecryptablePackets`) with packets waiting
     * for keys; the 33rd is dropped ("MAY be stored"), and the client's loss recovery resends what it carried once the
     * handshake completed.
     */
    @Test fun heldOneRttBeyondTheCapIsDroppedAndResent() {
        val a = heldFinished()
        try {
            val p = a.p
            val s = p.server!!
            val id = p.client.openStream(true)
            val packets = ArrayList<ByteArray>(a.oneRtt)
            var written = 0
            while (packets.size < 40 && written < 400) {
                p.client.writeStream(id, byteArrayOf(written.toByte()), 0, 1, false)
                written++
                packets += pollOneRtt(p)
                p.advance(1.milliseconds)
            }
            p.client.writeStream(id, ByteArray(0), 0, 0, true)
            packets += pollOneRtt(p)
            assertTrue(packets.size >= 33, "${packets.size} client 1-RTT packets")
            val dropped = s.stats.datagramsDropped
            for (d in packets) feed(p, d)
            assertEquals(32, s.receiver.bufferedCount, "held up to the cap")
            assertEquals(packets.size - 32L, s.stats.datagramsDropped - dropped, "the rest dropped")
            for (d in a.held) feed(p, d)
            p.filterToServer = { _, _ -> true }
            val buf = ByteArray(1024)
            var got = 0
            var fin = false
            assertTrue(
                p.runUntil(limit = 10.seconds) {
                    while (!fin) {
                        val n = s.readStream(id, buf, 0, buf.size)
                        if (n > 0) {
                            got += n
                        } else {
                            if (n < 0) fin = true
                            break
                        }
                    }
                    fin
                },
                "the stream completes: $got of $written bytes",
            )
            assertEquals(written, got)
            val buf0 = ByteArray(16)
            assertEquals("hello", buf0.decodeToString(0, s.readStream(0, buf0, 0, buf0.size)))
        } finally {
            a.p.close()
        }
    }

    /** The offset of the Finished message type in a Null-crypto datagram: CRYPTO at offset 0, length 4, then 0x14 and a zero length. */
    private fun finishedAt(d: ByteArray): Int {
        val pattern = byteArrayOf(0x06, 0x00, 0x04, 0x14, 0x00, 0x00, 0x00)
        for (i in 0..d.size - pattern.size) {
            if ((pattern.indices).all { d[i + it] == pattern[it] }) return i + 3
        }
        return -1
    }

    /**
     * RFC 9000 section 7.2: "When an Initial packet is sent by a client that has not previously received an Initial or Retry
     * packet from the server, the client populates the Destination Connection ID field with an unpredictable value. This
     * Destination Connection ID MUST be at least 8 bytes in length." Whatever length the client uses for its own IDs.
     */
    @Test fun clientFirstDestinationConnectionIdIsAtLeast8Bytes() {
        for (len in listOf(4, 8, 20)) {
            val p = CorePair(clientQuic = io.kuicksilver.quic.quicConfig { connectionIdLength = len })
            try {
                p.step()
                val d = p.lastClientInitial!!
                val dcidLen = d[5].toInt() and 0xff
                assertTrue(dcidLen >= 8, "connectionIdLength $len: first DCID of $dcidLen bytes")
                assertEquals(len, d[6 + dcidLen].toInt() and 0xff, "the SCID has the configured length")
                assertTrue(p.handshake(), "connectionIdLength $len")
            } finally {
                p.close()
            }
        }
    }

    /** RFC 9001 section 8.4: a server treats a ClientHello with a non-empty legacy_session_id as a PROTOCOL_VIOLATION. */
    @Test fun negative_clientHelloWithLegacySessionIdIsProtocolViolation() {
        val p = CorePair(crypto = WithLegacySessionId(ksl))
        try {
            p.runUntil(limit = 2.seconds) { p.closedReason(p.serverEvents) != null }
            val r = p.closedReason(p.serverEvents)
            assertIs<QuicException.ConnectionLost.TransportClosed>(r)
            assertEquals(0x0aL, r.code, r.reason)
        } finally {
            p.close()
        }
    }

    /** RFC 9001 section 8.2: a peer without the quic_transport_parameters extension is closed with 0x016d (missing_extension). */
    @Test fun negative_missingTransportParametersIsMissingExtension() {
        for (role in listOf(TlsRole.Server, TlsRole.Client)) {
            // the session of [role] never reports the peer's transport parameters, as if the extension were absent
            val p = CorePair(crypto = WithoutPeerTransportParameters(ksl, role))
            try {
                p.runUntil(limit = 2.seconds) {
                    (if (role == TlsRole.Server) p.closedReason(p.serverEvents) else p.closedReason(p.clientEvents)) != null
                }
                val events = if (role == TlsRole.Server) p.serverEvents else p.clientEvents
                val r = p.closedReason(events)
                assertIs<QuicException.ConnectionLost.TransportClosed>(r, "$role")
                assertEquals(0x16dL, r.code, "$role")
                assertFalse(events.any { it is ConnectionEvent.HandshakeCompleted }, "$role")
            } finally {
                p.close()
            }
        }
    }

    @Test fun nullHandshakeCompletesBothSides() {
        val p = CorePair()
        try {
            assertTrue(p.handshake())
            assertTrue(p.runUntil { p.client.state == ConnectionState.Confirmed })
            assertEquals(ConnectionState.Confirmed, p.server!!.state)
            assertEquals("hq-interop", p.client.negotiatedAlpn)
        } finally {
            p.close()
        }
    }

    @Test fun kslHandshakeAlpnHqInterop() {
        val p = CorePair(crypto = ksl)
        try {
            assertTrue(p.handshake(), "client=${p.closedReason(p.clientEvents)} server=${p.closedReason(p.serverEvents)}")
            assertEquals("hq-interop", p.client.negotiatedAlpn)
            assertEquals(1, p.client.peerCertificates.size)
            assertEquals(Certificate(TestCerts.server), p.client.peerCertificates[0])
            assertTrue(p.runUntil { p.client.state == ConnectionState.Confirmed && p.server!!.state == ConnectionState.Confirmed })
            assertContentEquals(p.client.exportKeyingMaterial("test", null, 16), p.server!!.exportKeyingMaterial("test", null, 16))
        } finally {
            p.close()
        }
    }

    @Test fun clientInitialDatagramsAtLeast1200() {
        val p = CorePair(crypto = ksl)
        val sizes = ArrayList<Int>()
        p.filterToServer =
            { _, b ->
                if (b[0].toInt() and 0xf0 == 0xc0) sizes += b.size
                true
            }
        try {
            assertTrue(p.handshake())
            assertTrue(sizes.isNotEmpty() && sizes.all { it >= 1200 }, "$sizes")
        } finally {
            p.close()
        }
    }

    /**
     * RFC 9000 section 14.1: a server MUST expand every datagram carrying an ack-eliciting Initial to 1200 bytes. The first flight
     * is Initial + Handshake with a 1-RTT frame queued behind them; the Handshake flight is swept so it ends at every offset before
     * 1200, including the last 64 bytes, where the 1-RTT packet no longer fits and could not pad the datagram.
     */
    @Test fun negative_serverInitialDatagramPaddedWhenTheNextPacketDoesNotFit() {
        val short = ArrayList<String>()
        for (len in 1..1150) {
            val p = CorePair()
            p.onServerCreated = { s ->
                s.testInjectCrypto = Triple(2, 10_000L, len)
                s.testInjectFrames += 3 to byteArrayOf(0x01) // PING
            }
            p.filterToClient = { _, b ->
                if (b.size < 1200 && nullDatagramHasAckElicitingInitial(b)) short += "Handshake CRYPTO $len: ${b.size} bytes"
                true
            }
            try {
                p.step() // the ClientHello makes the server
                p.step() // the server answers it
            } finally {
                p.close()
            }
        }
        assertTrue(short.isEmpty(), short.joinToString())
    }

    /**
     * RFC 9000 section 14.1: a client MUST expand every datagram carrying Initial packets to 1200 bytes. Its second flight is
     * Initial + Handshake (Finished) + 1-RTT; the Initial is swept so it ends at every offset before 1200, including the last
     * 64 bytes, where the Handshake packet no longer fits behind it.
     */
    @Test fun negative_clientInitialDatagramPaddedWhenTheNextPacketDoesNotFit() {
        val short = ArrayList<String>()
        for (len in 1..1150) {
            val p = CorePair()
            try {
                p.step() // the ClientHello makes the server
                p.step() // the server's first flight is queued for the client
                p.client.testInjectCrypto = Triple(0, 10_000L, len)
                p.filterToServer = { _, b ->
                    if (b[0].toInt() and 0xf0 == 0xc0 && b.size < 1200) short += "Initial CRYPTO $len: ${b.size} bytes"
                    true
                }
                p.step()
            } finally {
                p.close()
            }
        }
        assertTrue(short.isEmpty(), short.joinToString())
    }

    @Test fun largeClientHelloSpansMultipleInitials() {
        val p = CorePair(crypto = ksl)
        var initials = 0
        p.filterToServer = { i, _ ->
            if (i == 0 || i == 1) initials++
            true
        }
        try {
            p.step()
            assertTrue(p.toServer.size >= 2 || initials >= 2, "ClientHello with X25519MLKEM768 needs two Initial packets")
            assertTrue(p.handshake())
        } finally {
            p.close()
        }
    }

    @Test fun transportParametersCidAuthentication() {
        val p = CorePair(crypto = ksl)
        p.client.testForgeInitialSourceCid = true
        try {
            assertFalse(p.handshake())
            val r = p.closedReason(p.serverEvents)
            assertIs<QuicException.ConnectionLost.TransportClosed>(r)
            assertEquals(0x08L, r.code)
        } finally {
            p.close()
        }
    }

    @Test fun tlsFailureMapsToCryptoError() {
        val p =
            CorePair(clientTls = CoreFixtures.client(trust = TrustConfig.AnchoredCa(listOf(Certificate(TestCerts.otherCa)))), crypto = ksl)
        try {
            assertFalse(p.handshake())
            val r = p.closedReason(p.clientEvents)
            assertIs<QuicException.ConnectionLost.TransportClosed>(r)
            assertEquals(0x0130L, r.code)
            assertEquals(Initiator.Local, r.initiator)
            assertIs<TlsException.Verify>(r.cause)
            val s = p.closedReason(p.serverEvents)
            assertIs<QuicException.ConnectionLost.TransportClosed>(s)
            assertEquals(0x0130L, s.code)
            assertEquals(Initiator.Peer, s.initiator)
            assertIs<TlsException.AlertReceived>(s.cause)
            assertEquals(48, (s.cause as TlsException.AlertReceived).code)
        } finally {
            p.close()
        }
    }

    @Test fun alpnMismatchCloses0x0178() {
        val p = CorePair(clientTls = CoreFixtures.client(alpn = "h3"), serverTls = CoreFixtures.server(alpn = "hq-interop"), crypto = ksl)
        try {
            assertFalse(p.handshake())
            val s = p.closedReason(p.serverEvents)
            assertIs<QuicException.ConnectionLost.TransportClosed>(s)
            assertEquals(0x0178L, s.code)
            val c = p.closedReason(p.clientEvents)
            assertIs<QuicException.ConnectionLost.TransportClosed>(c)
            assertEquals(0x0178L, c.code)
        } finally {
            p.close()
        }
    }

    @Test fun verifyPauseRoundTrip() {
        var asked = 0
        val p =
            CorePair(
                clientTls =
                    CoreFixtures.client(
                        trust =
                            TrustConfig.Custom {
                                chain,
                                _,
                                _,
                                ->
                                asked++
                                VerifyResult.Accepted(chain)
                            },
                    ),
                crypto = ksl,
            )
        p.autoVerify =
            false
        try {
            p.runUntil(limit = 500.milliseconds()) { p.clientEvents.any { it is ConnectionEvent.VerifyRequested } }
            val req = p.clientEvents.filterIsInstance<ConnectionEvent.VerifyRequested>().single()
            assertEquals(1, req.chain.size)
            p.runUntil(limit = 300.milliseconds()) { false }
            assertFalse(p.clientEvents.any { it is ConnectionEvent.HandshakeCompleted }, "handshake waits for the verdict")
            p.client.resumeVerify(kotlinx.coroutines.runBlocking { req.session.verifyPeer(req.chain) })
            assertEquals(1, asked)
            assertTrue(p.handshake())
        } finally {
            p.close()
        }
    }

    @Test fun postHandshakeWantReadIsNotAnError() {
        val p = CorePair(crypto = ksl)
        try {
            assertTrue(p.handshake())
            p.runUntil(limit = 200.milliseconds()) { false }
            assertNull(p.closedReason(p.clientEvents))
            assertNull(p.closedReason(p.serverEvents))
        } finally {
            p.close()
        }
    }

    @Test fun streamEchoOneMiB() {
        val p = CorePair()
        try {
            assertTrue(p.handshake())
            val data = ByteArray(1 shl 20) { (it * 31).toByte() }
            val id = p.client.openStream(bidi = true, StreamPriority.Default)
            var written = 0
            val echoed = ByteArray(data.size)
            var echoedLen = 0
            val buf = ByteArray(16384)
            var serverRead = 0
            var serverDone = false
            assertTrue(
                p.runUntil(limit = 60_000.milliseconds()) {
                    if (written <
                        data.size
                    ) {
                        written +=
                            p.client.writeStream(
                                id,
                                data,
                                written,
                                minOf(65536, data.size - written),
                                fin =
                                    written + minOf(65536, data.size - written) == data.size,
                            )
                    }
                    val s = p.server!!
                    while (true) {
                        val n = s.readStream(id, buf, 0, buf.size)
                        if (n >
                            0
                        ) {
                            s.writeStream(id, buf, 0, n, false)
                            serverRead += n
                        } else {
                            if (n < 0 &&
                                !serverDone
                            ) {
                                serverDone = true
                                s.writeStream(id, buf, 0, 0, true)
                            }
                            break
                        }
                    }
                    while (true) {
                        val n = p.client.readStream(id, echoed, echoedLen, echoed.size - echoedLen)
                        if (n >
                            0
                        ) {
                            echoedLen += n
                        } else {
                            break
                        }
                    }
                    echoedLen == data.size
                },
                "echoed $echoedLen of ${data.size}, server read $serverRead",
            )
            assertContentEquals(data, echoed)
        } finally {
            p.close()
        }
    }

    /** RFC 9002 section 6.2.4 in practice (interop `handshakeloss`): a server whose Initial PTO fires while Handshake data is also unacknowledged resends both, coalesced, instead of leaving the client waiting for the Handshake flight. */
    @Test fun serverInitialPtoAlsoProbesHandshakeSpace() {
        val p = CorePair()
        p.filterToClient = { _, _ -> false } // the client never sees the server: no ACKs reach the server
        assertTrue(
            p.runUntil(2_000.milliseconds()) {
                p.server?.loss?.space(io.kuicksilver.quic.recovery.SpaceId.Handshake)?.let {
                    it.ackElicitingInFlight >
                        0
                } ==
                    true
            },
            "server sent its Initial and Handshake flight",
        )
        val s = p.server!!
        val hsBefore =
            s.loss
                .space(io.kuicksilver.quic.recovery.SpaceId.Handshake)
                .sent.size
        p.filterToServer = { _, _ -> false } // and the client's probes stop too: only the server's own PTO can move things
        assertTrue(p.runUntil(3_000.milliseconds()) { s.loss.ptoCount >= 1 }, "the server's PTO fired")
        assertTrue(
            s.loss
                .space(io.kuicksilver.quic.recovery.SpaceId.Handshake)
                .sent.size > hsBefore,
            "the PTO probe carried a Handshake packet, not only the Initial one",
        )
    }
}

private fun Int.milliseconds() = kotlin.time.Duration.parse("${this}ms")

/** Hides the peer's transport parameters from the sessions of [role] (a peer that sent no quic_transport_parameters). */
private class WithoutPeerTransportParameters(
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

/** A client whose ClientHello carries a 32-byte legacy_session_id (TLS 1.3 middlebox compatibility mode, RFC 9846 appendix E.4). */
private class WithLegacySessionId(
    private val inner: QuicCrypto,
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
        if (config.role != TlsRole.Client) {
            s
        } else {
            object : QuicTlsSession by s {
                private var done = false

                override fun nextEvent(): TlsEvent? {
                    val e = s.nextEvent()
                    if (done || e !is TlsEvent.CryptoData || e.level != EncryptionLevel.Initial || e.data[38].toInt() != 0) return e
                    done = true
                    // handshake header (4), legacy_version (2), random (32), then the session ID length byte at 38
                    val d = e.data
                    val out = d.copyOfRange(0, 38) + byteArrayOf(32) + ByteArray(32) { 0x5a } + d.copyOfRange(39, d.size)
                    val len = ((d[1].toInt() and 0xff) shl 16) or ((d[2].toInt() and 0xff) shl 8) or (d[3].toInt() and 0xff)
                    val n = len + 32
                    out[1] = (n ushr 16).toByte()
                    out[2] = (n ushr 8).toByte()
                    out[3] = n.toByte()
                    return TlsEvent.CryptoData(e.level, out)
                }
            }
        }
}
