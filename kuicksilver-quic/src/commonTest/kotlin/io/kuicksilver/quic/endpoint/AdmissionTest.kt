// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.endpoint

import io.ktor.network.sockets.InetSocketAddress
import io.kuicksilver.annotations.DelicateKuicksilverApi
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.native.KslLoader
import io.kuicksilver.native.PacketBuffer
import io.kuicksilver.native.of
import io.kuicksilver.quic.AdmissionDecision
import io.kuicksilver.quic.ConnectionAdmission
import io.kuicksilver.quic.ConnectionAttempt
import io.kuicksilver.quic.ConnectionCore
import io.kuicksilver.quic.ConnectionEvent
import io.kuicksilver.quic.ConnectionState
import io.kuicksilver.quic.CoreFixtures
import io.kuicksilver.quic.EndpointCore
import io.kuicksilver.quic.NullCryptoProvider
import io.kuicksilver.quic.PacketBatch
import io.kuicksilver.quic.QuicClientConfig
import io.kuicksilver.quic.QuicEndpointConfig
import io.kuicksilver.quic.QuicException
import io.kuicksilver.quic.QuicServerConfig
import io.kuicksilver.quic.TransportError
import io.kuicksilver.quic.wire.PacketHeaderCodec
import io.kuicksilver.quic.wire.PacketHeaderView
import io.kuicksilver.quic.wire.PacketType
import io.kuicksilver.tls.KslQuicCrypto
import kotlin.random.Random
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.seconds

/** `ConnectionAdmission`, the bounded Initial queue and the endpoint limits (threat-model 3.2, 5 items 4, 5, 7). */
@OptIn(ExperimentalKuicksilverApi::class, DelicateKuicksilverApi::class)
class AdmissionTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    /** Records every attempt it sees and answers with [decision]. */
    private class Recording(
        val decision: AdmissionDecision = AdmissionDecision.Allow,
    ) : ConnectionAdmission {
        val attempts = ArrayList<ConnectionAttempt>()

        override fun admit(attempt: ConnectionAttempt): AdmissionDecision {
            attempts += attempt
            return decision
        }
    }

    private fun packetType(b: ByteArray): PacketType? {
        val v = PacketHeaderView()
        val buf = PacketBuffer.of(b)
        try {
            return if (PacketHeaderCodec.parse(buf, 0, b.size, 8, v)) v.type else null
        } finally {
            buf.close()
        }
    }

    private fun attempt(
        inflight: Int = 0,
        buffer: Long = 0,
        validated: Boolean = false,
    ) = ConnectionAttempt(InetSocketAddress("10.0.0.1", 1), inflight, inflight, 1, buffer, validated)

    /** First datagram of a fresh client core on [p]'s client endpoint. */
    private fun firstInitial(p: EndpointPair): ByteArray {
        val c = p.connect()
        val b = PacketBatch(4)
        try {
            check(c.poll(b, p.now) >= 1)
            return b.buffer(0).toByteArray(b.length(0))
        } finally {
            b.close()
        }
    }

    private fun io.kuicksilver.native.PacketBuffer.toByteArray(n: Int): ByteArray = ByteArray(n).also { copyTo(it, 0, 0, n) }

    private fun addr(
        i: Int,
        port: Int = 40000,
    ) = InetSocketAddress("10.1.${i / 256}.${i % 256}", port)

    // ---- the default policy ----
    @Test fun defaultAllowsBelowThresholds() {
        assertEquals(AdmissionDecision.Allow, ConnectionAdmission.default().admit(attempt(inflight = 255, buffer = 8_388_608)))
    }

    @Test fun negative_inflightHandshakeRetry() {
        // Retry above 256 handshakes in flight (the 257th attempt), connection not created
        assertEquals(
            AdmissionDecision.Retry,
            ConnectionAdmission.default().admit(attempt(inflight = 256)),
            "the 257th attempt sees 256 in flight",
        )
        val p = EndpointPair { admission = ConnectionAdmission.default(maxInflightHandshakes = 2) }
        try {
            repeat(2) { p.feed(p.server, firstInitial(p), addr(it)) }
            assertEquals(2, p.server.connectionCount)
            assertEquals(0, p.stateless(p.server).size)
            assertNull(p.feed(p.server, firstInitial(p), addr(7)))
            assertEquals(2, p.server.connectionCount, "the third handshake in flight is not created")
            val out = p.stateless(p.server)
            assertEquals(1, out.size)
            assertEquals(PacketType.Retry, packetType(out[0]))
            assertEquals(1L, p.server.stats.retriesSent)
        } finally {
            p.close()
        }
    }

    @Test fun handshakeBufferBytesTriggersRetry() {
        assertEquals(AdmissionDecision.Retry, ConnectionAdmission.default().admit(attempt(buffer = 8_388_609)))
        assertEquals(AdmissionDecision.Retry, ConnectionAdmission.default(maxHandshakeBufferBytes = 10).admit(attempt(buffer = 11)))
        // the endpoint reports the handshake buffers of its unfinished handshakes: a Handshake packet buffered before its keys counts
        val rec = Recording()
        val p = EndpointPair(crypto = KslQuicCrypto) { admission = rec }
        try {
            p.feed(p.server, firstInitial(p), addr(1))
            val s = p.server.connections().single()
            val hs = ByteArray(300) { 0x33 }
            hs[0] = 0xe0.toByte()
            hs[1] = 0
            hs[2] = 0
            hs[3] = 0
            hs[4] = 1
            hs[5] = 8
            s.localCid.toByteArray().copyInto(hs, 6)
            hs[14] =
                8
            hs[23] = 0x41
            hs[24] = 0x10 // Handshake long header to our CID, length 272
            assertEquals(s, p.feed(p.server, hs, addr(1)))
            assertTrue(s.handshakeBufferBytes > 0L, "undecryptable Handshake bytes are buffered against the connection")
            p.feed(p.server, firstInitial(p), addr(2))
            assertEquals(s.handshakeBufferBytes, rec.attempts.last().handshakeBufferBytes)
            assertEquals(1, rec.attempts.last().inflightHandshakes)
        } finally {
            p.close()
        }
    }

    // ---- the Initial queue ----
    @Test fun negative_initialQueueCap() {
        // at most 1024 Initials wait for admit; the rest are dropped and counted
        val p = EndpointPair()
        try {
            val initial = firstInitial(p)
            for (i in 0 until 1100) {
                val d = initial.copyOf()
                d[6] = (i and 0xff).toByte()
                d[7] = (i shr 8).toByte()
                p.feedNoAdmit(p.server, d, addr(i))
            }
            assertEquals(1024, p.server.pendingInitials)
            assertEquals(76L, p.server.stats.initialsDropped)
            assertEquals(0, p.server.connectionCount)
        } finally {
            p.close()
        }
    }

    @Test fun secondInitialOfAQueuedFlightReachesTheNewConnection() {
        // a flight of two Initial datagrams is queued whole; processPending creates the connection from the first and routes the second to it
        val p = EndpointPair(crypto = KslQuicCrypto)
        try {
            val c = p.connect()
            val b = PacketBatch(4)
            val flight = ArrayList<ByteArray>()
            try {
                val n = c.poll(b, p.now)
                for (i in 0 until
                    n) {
                    flight += b.buffer(i).toByteArray(b.length(i))
                }
            } finally {
                b.close()
            }
            assertEquals(2, flight.size, "ksl ClientHello spans two Initial datagrams")
            for (d in flight) assertNull(p.feedNoAdmit(p.server, d, p.clientAddr))
            assertEquals(2, p.server.pendingInitials)
            assertEquals(1, p.server.processPending(p.now))
            assertEquals(0, p.server.pendingInitials)
            assertEquals(1, p.server.connectionCount)
            assertEquals(
                2L,
                p.server
                    .connections()
                    .single()
                    .stats.packetsReceived,
            )
        } finally {
            p.close()
        }
    }

    @Test fun cheapChecksBeforeAdmit() {
        // only the cheap checks run before admit: a 1199-byte Initial and a 7-byte DCID never reach it
        val rec = Recording()
        val p = EndpointPair { admission = rec }
        try {
            val initial = firstInitial(p)
            assertNull(p.feed(p.server, initial.copyOf(1199), addr(1)))
            val short = initial.copyOf()
            short[5] = 7
            assertNull(p.feed(p.server, short, addr(2)))
            assertEquals(0, rec.attempts.size)
            assertEquals(0L, p.server.stats.initialsDropped, "sub-1200 and short-DCID datagrams are noise, not admission drops")
            assertNotNull(p.feed(p.server, initial, addr(3)))
            assertEquals(1, rec.attempts.size)
            val a = rec.attempts[0]
            assertEquals(addr(3), a.remote)
            assertEquals(0, a.inflightHandshakes)
            assertEquals(0, a.connections)
            assertEquals(0, a.connectionsFromAddress)
            assertFalse(a.addressValidated)
        } finally {
            p.close()
        }
    }

    // ---- decisions ----
    @Test fun negative_admitRetryForValidatedAttemptRejected() {
        // fail closed: a Retry decision for an attempt that already carries a valid token is a contract violation (quinn CVE-2024-45311); neither a second Retry nor a connection
        val p = EndpointPair(crypto = KslQuicCrypto) { admission = ConnectionAdmission { AdmissionDecision.Retry } }
        try {
            var retries = 0
            p.filterToClient = { _, b ->
                if (packetType(b) == PacketType.Retry) retries++
                true
            }
            val c = p.connect()
            p.runUntil(2.seconds) { retries >= 1 && p.server.stats.admissionContractViolations >= 1L }
            assertTrue(p.server.stats.admissionContractViolations >= 1L)
            assertEquals(0, p.server.connectionCount)
            assertTrue(retries <= 2, "no Retry answers the token-bearing Initial: $retries")
            assertTrue(c.state == ConnectionState.Handshaking)
        } finally {
            p.close()
        }
    }

    @Test fun negative_noTokenHandlerDoesNotValidate() {
        // a token we did not mint (not a Retry token) validates nothing: the attempt is unvalidated and the amplification limit stays
        val rec = Recording()
        val p = EndpointPair { admission = rec }
        try {
            val c = p.connect()
            c.testInitialToken = ByteArray(50) { 0x7f }
            val b = PacketBatch(4)
            val initial =
                try {
                    check(c.poll(b, p.now) >= 1)
                    b.buffer(0).toByteArray(b.length(0))
                } finally {
                    b.close()
                }
            val s = assertNotNull(p.feed(p.server, initial, p.clientAddr))
            assertFalse(rec.attempts.single().addressValidated)
            var sent = 0L
            val out = PacketBatch(8)
            try {
                val n = s.poll(out, p.now)
                for (i in 0 until n) sent += out.length(i)
            } finally {
                out.close()
            }
            assertTrue(sent in 1..(3L * initial.size), "amplification limit holds for an unvalidated address: $sent")
        } finally {
            p.close()
        }
    }

    @Test fun acceptQueueFullRefusesStatelessly() {
        // RFC 9000 section 5.2.2: a server that will not take the connection answers with an Initial CONNECTION_CLOSE
        // (quic-go sendConnectionRefused) instead of leaving the client to its handshake timeout
        val p = EndpointPair { acceptQueue = 2 }
        try {
            repeat(3) { p.feed(p.server, firstInitial(p), addr(it)) }
            assertEquals(2, p.server.connectionCount)
            assertEquals(0L, p.server.stats.initialsDropped)
            assertEquals(1L, p.server.acceptQueueRefusals)
            val answers = p.stateless(p.server)
            assertEquals(1, answers.size)
            assertEquals(PacketType.Initial, packetType(answers.single()))
        } finally {
            p.close()
        }
    }

    @Test fun initialWhileAcceptQueueFullIsRefusedStatelessly() {
        // a handshaken connection waits for accept(): the next client learns CONNECTION_REFUSED from its first Initial, no
        // connection (and so no TLS handshake) is created for it, and its connect fails at once, not at the handshake timeout
        val p = EndpointPair(crypto = KslQuicCrypto) { acceptQueue = 1 }
        try {
            val first = p.connect()
            assertTrue(p.confirmed(first))
            val created = p.server.stats.connectionsCreated
            var serverCores = 0
            p.onServerCreated = { serverCores++ }
            val second = p.connect()
            assertTrue(p.runUntil(200.milliseconds) { p.closed(second) != null }, "refused within a round trip")
            val lost = assertIs<QuicException.ConnectionLost.TransportClosed>(p.closed(second))
            assertEquals(TransportError.CONNECTION_REFUSED, lost.code)
            assertEquals(1, p.server.connectionCount)
            assertEquals(created, p.server.stats.connectionsCreated, "no connection state for the refused client")
            assertEquals(0, serverCores)
            assertTrue(p.server.acceptQueueRefusals >= 1, "every datagram of its first flight is refused alike")
            assertNull(p.closed(first), "the waiting connection is untouched")
        } finally {
            p.close()
        }
    }

    @Test fun negative_refusalIsAmplificationLimited() {
        // threat-model 3.1, RFC 9000 section 8.1: a refusal answers a spoofable datagram, so it is small (far below 3x the
        // Initial) and goes through the stateless rate limits like Retry, Version Negotiation and INVALID_TOKEN
        val p =
            EndpointPair {
                acceptQueue = 1
                statelessPerAddressPerSecond = 2
                statelessTotalPerSecond = 3
            }
        try {
            p.server.acceptBacklog = { 1 }
            val received = HashMap<Int, Long>()
            for (i in 0 until 8) {
                val from = if (i < 5) 1 else i
                val initial = firstInitial(p)
                received[from] = (received[from] ?: 0L) + initial.size
                assertNull(p.feed(p.server, initial, addr(from)))
            }
            val answers = p.stateless(p.server)
            assertEquals(3, answers.size, "the total limit")
            assertEquals(5L, p.server.stats.statelessRateLimited)
            assertEquals(0, p.server.connectionCount)
            val sent = answers.sumOf { it.size.toLong() }
            assertTrue(
                answers.all { 3L * it.size <= 1200 },
                "each answer is under a third of a minimum Initial: ${answers.map { it.size }}",
            )
            assertTrue(sent <= 3L * received.values.sum(), "amplification: $sent for ${received.values.sum()}")
        } finally {
            p.close()
        }
    }

    @Test fun maxConnectionsPerIpDrops() {
        val rec = Recording()
        val p =
            EndpointPair {
                admission = rec
                maxConnectionsPerIp = 2
            }
        try {
            val ip = InetSocketAddress("10.9.9.9", 1)
            val same = (0 until 3).map { InetSocketAddress("10.9.9.9", 1000 + it) }
            assertNotNull(p.feed(p.server, firstInitial(p), same[0]))
            assertNotNull(p.feed(p.server, firstInitial(p), same[1]))
            assertNull(p.feed(p.server, firstInitial(p), same[2]))
            assertEquals(2, p.server.connectionCount)
            assertEquals(1L, p.server.stats.initialsDropped)
            assertEquals(2, rec.attempts.size, "the per-IP limit is checked before admit")
            assertEquals(1, rec.attempts[1].connectionsFromAddress)
            assertNotNull(p.feed(p.server, firstInitial(p), InetSocketAddress("10.9.9.10", 1)), "another IP is not affected")
            p.server.connections().first { it.remoteAddressForTest == same[0] }.let {
                it.close(0, "", p.now)
                p.server.remove(it)
            }
            assertNotNull(p.feed(p.server, firstInitial(p), ip), "a removed connection frees its IP slot")
        } finally {
            p.close()
        }
    }

    @Test fun maxConnectionLifetimeClosesWithNoError() {
        val p = EndpointPair(crypto = KslQuicCrypto) { maxConnectionLifetime = 3.seconds }
        try {
            val c = p.connect()
            assertTrue(p.confirmed(c))
            val s = p.server.connections().single()
            assertTrue(p.runUntil(10.seconds) { p.closed(c) != null }, "the server closes at the lifetime")
            val lost = assertIs<QuicException.ConnectionLost.TransportClosed>(p.closed(c))
            assertEquals(TransportError.NO_ERROR, lost.code)
            assertTrue(s.state == ConnectionState.Closing || s.state == ConnectionState.Closed)
            val lifetime =
                p.now - s.createdAtForTest
            assertTrue(lifetime >= 3.seconds && lifetime < 4.seconds, "closed at the lifetime, not the idle timer: $lifetime")
        } finally {
            p.close()
        }
    }

    @Test fun reflectiveSourcePortsDropped() {
        // an Initial "from" port 53/123/1900/5353/11211 is a reflection attempt: silence (threat-model 3.1)
        for (port in intArrayOf(53, 123, 1900, 5353, 11211)) {
            val rec = Recording()
            val p = EndpointPair { admission = rec }
            try {
                assertNull(p.feed(p.server, firstInitial(p), InetSocketAddress("10.0.0.5", port)))
                assertEquals(0, rec.attempts.size)
                assertEquals(0, p.stateless(p.server).size)
                assertEquals(0, p.server.connectionCount)
                assertEquals(1L, p.server.stats.initialsDropped)
            } finally {
                p.close()
            }
        }
        val p = EndpointPair { rejectInitialFromReflectivePorts = false }
        try {
            assertNotNull(p.feed(p.server, firstInitial(p), InetSocketAddress("10.0.0.5", 53)), "the option opens the ports")
        } finally {
            p.close()
        }
    }

    @Test fun closeDecisionSendsInitialConnectionClose() {
        val p =
            EndpointPair(crypto = KslQuicCrypto) {
                admission =
                    ConnectionAdmission { AdmissionDecision.Close(TransportError.CONNECTION_REFUSED) }
            }
        try {
            val c = p.connect()
            assertTrue(p.runUntil(2.seconds) { p.closed(c) != null })
            assertEquals(0, p.server.connectionCount)
            val lost = assertIs<QuicException.ConnectionLost.TransportClosed>(p.closed(c))
            assertEquals(TransportError.CONNECTION_REFUSED, lost.code)
        } finally {
            p.close()
        }
    }

    @Test fun dropDecisionIsSilent() {
        val p = EndpointPair { admission = ConnectionAdmission { AdmissionDecision.Drop } }
        try {
            assertNull(p.feed(p.server, firstInitial(p), addr(1)))
            assertEquals(0, p.stateless(p.server).size)
            assertEquals(1L, p.server.stats.initialsDropped)
        } finally {
            p.close()
        }
    }

    @Test fun alwaysRetryUsedByInteropRetryCase() {
        // the interop `retry` case runs the server with ConnectionAdmission.AlwaysRetry: one Retry, then a validated handshake
        val p = EndpointPair(crypto = KslQuicCrypto) { admission = ConnectionAdmission.AlwaysRetry }
        try {
            var retries = 0
            p.filterToClient = { _, b ->
                if (packetType(b) == PacketType.Retry) retries++
                true
            }
            val c = p.connect()
            assertTrue(p.confirmed(c))
            assertTrue(retries in 1..2, "retries: $retries")
            assertEquals(retries.toLong(), p.server.stats.retriesSent)
            assertEquals(0L, p.server.stats.admissionContractViolations)
            assertTrue(
                p.server
                    .connections()
                    .single()
                    .validatedByToken,
            )
        } finally {
            p.close()
        }
    }

    @Test fun statsSnapshotCountsStatelessAnswers() {
        val p = EndpointPair { statelessPerAddressPerSecond = 1 }
        try {
            val initial = firstInitial(p)
            val vn = initial.copyOf()
            vn[1] = 0x1a
            vn[2] = 0x2a
            vn[3] = 0x3a
            vn[4] = 0x4a
            assertNull(p.feed(p.server, vn, addr(1)))
            assertNull(p.feed(p.server, vn, addr(1)))
            val st = p.server.stats
            assertEquals(1L, st.versionNegotiations)
            assertEquals(1L, st.statelessRateLimited)
            assertEquals(1, p.stateless(p.server).size)
        } finally {
            p.close()
        }
    }

    @Test fun configDefaults() {
        val c = QuicEndpointConfig.Default
        assertEquals(1024, c.initialQueueCap)
        assertEquals(256, c.maxConnectionsPerIp)
        assertNull(c.maxConnectionLifetime)
        assertTrue(c.rejectInitialFromReflectivePorts)
        assertEquals(8, c.statelessPerAddressPerSecond)
        assertEquals(128, c.acceptQueue)
        assertEquals(1000, c.statelessTotalPerSecond)
        assertEquals(AdmissionDecision.Allow, c.admission.admit(attempt()))
        assertEquals(AdmissionDecision.Retry, ConnectionAdmission.AlwaysRetry.admit(attempt()))
        assertEquals(AdmissionDecision.Allow, ConnectionAdmission.AlwaysRetry.admit(attempt(validated = true)))
    }

    @Test fun processPendingHonoursMax() {
        val p = EndpointPair()
        try {
            repeat(5) { p.feedNoAdmit(p.server, firstInitial(p), addr(it)) }
            assertEquals(2, p.server.processPending(p.now, max = 2))
            assertEquals(3, p.server.pendingInitials)
            assertEquals(3, p.server.processPending(p.now))
            assertEquals(5, p.server.connectionCount)
        } finally {
            p.close()
        }
    }
}
