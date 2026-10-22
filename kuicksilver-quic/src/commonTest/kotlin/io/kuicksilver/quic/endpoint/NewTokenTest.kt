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
import io.kuicksilver.quic.ConnectionState
import io.kuicksilver.quic.CoreFixtures
import io.kuicksilver.quic.EndpointCore
import io.kuicksilver.quic.QuicEndpointConfig
import io.kuicksilver.quic.QuicServerConfig
import io.kuicksilver.quic.TimeMark
import io.kuicksilver.quic.wire.ConnectionId
import io.kuicksilver.quic.wire.PacketHeaderCodec
import io.kuicksilver.quic.wire.PacketHeaderView
import io.kuicksilver.quic.wire.PacketType
import io.kuicksilver.tls.KslQuicCrypto
import kotlin.random.Random
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.hours
import kotlin.time.Duration.Companion.nanoseconds
import kotlin.time.Duration.Companion.seconds

/** RFC 9000 sections 8.1.3, 8.1.4 and 19.7: the server issues NEW_TOKEN tokens and admits their holders without a Retry. */
@OptIn(ExperimentalKuicksilverApi::class, DelicateKuicksilverApi::class)
class NewTokenTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    /** Records every attempt and answers like [ConnectionAdmission.AlwaysRetry]. */
    private class Recording(
        val inner: ConnectionAdmission = ConnectionAdmission.AlwaysRetry,
    ) : ConnectionAdmission {
        val attempts = ArrayList<ConnectionAttempt>()

        override fun admit(attempt: ConnectionAttempt): AdmissionDecision {
            attempts += attempt
            return inner.admit(attempt)
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

    private fun EndpointPair.serverCore(c: Int = -1): ConnectionCore = server.connections().let { if (c < 0) it.last() else it[c] }

    /** A full connection whose server issued a token; returns that token. */
    private fun EndpointPair.tokenFromNewConnection(): ByteArray {
        val c = connect()
        assertTrue(confirmed(c), "handshake: ${closed(c)}")
        val s = server.connections().last()
        assertTrue(runUntil { s.newTokenSendsForTest.isNotEmpty() }, "the server sent no NEW_TOKEN")
        return s.newTokenSendsForTest.first()
    }

    @Test fun serverIssuesOneTokenAfterHandshake() {
        val p = EndpointPair(crypto = KslQuicCrypto)
        var dropped = false
        var lostToken: ByteArray? = null
        p.filterToClient = { _, _ ->
            // every datagram of the round that carried the first NEW_TOKEN is lost
            val s = p.server.connections().firstOrNull()
            if (s != null && s.newTokenSendsForTest.size == 1 && (!dropped || lostToken != null)) {
                if (!dropped) lostToken = s.newTokenSendsForTest[0]
                dropped = true
                false
            } else {
                true
            }
        }
        try {
            val c = p.connect()
            assertTrue(p.confirmed(c), "${p.closed(c)}")
            val s = p.serverCore()
            assertTrue(p.runUntil { s.newTokenSendsForTest.size >= 2 }, "the lost NEW_TOKEN is sent again: ${s.newTokenSendsForTest.size}")
            lostToken = null
            p.runUntil(2.seconds) { false }
            assertTrue(s.newTokenAfterHandshakeDoneForTest, "NEW_TOKEN only goes out after HANDSHAKE_DONE")
            val sent = s.newTokenSendsForTest
            for (t in sent) assertContentEquals(sent[0], t, "a repeat carries the same token bytes")
            assertEquals(1L, p.server.stats.newTokensIssued, "one token for the connection")
            assertEquals(33, sent[0].size, "type, nonce(8), issuedAt(8) and the tag(16)")
            assertEquals(0x02, sent[0][0].toInt())
            assertEquals(ConnectionState.Confirmed, c.state)
        } finally {
            p.close()
        }
    }

    @Test fun noTokenWhenLifetimeIsNull() {
        val p = EndpointPair(crypto = KslQuicCrypto, newTokenLifetime = null)
        try {
            val c = p.connect()
            assertTrue(p.confirmed(c))
            p.runUntil(1.seconds) { false }
            assertTrue(p.serverCore().newTokenSendsForTest.isEmpty())
            assertEquals(0L, p.server.stats.newTokensIssued)
        } finally {
            p.close()
        }
    }

    @Test fun validTokenSkipsRetryAndLiftsAmplification() {
        val rec = Recording()
        val p = EndpointPair(crypto = KslQuicCrypto) { admission = rec }
        try {
            val token = p.tokenFromNewConnection()
            val retriesBefore = p.server.stats.retriesSent
            assertTrue(retriesBefore >= 1, "the first connection went through a Retry")
            rec.attempts.clear()
            // the second client goes silent after its first flight: the server keeps sending (PTO) past three times what it got
            var received = 0L
            var firstFlight = true
            p.filterToServer = { _, b ->
                if (firstFlight && packetType(b) == PacketType.Initial) {
                    received += b.size
                    true
                } else {
                    false
                }
            }
            val c2 = p.connect()
            c2.initialToken = token
            p.step()
            firstFlight = false
            p.runUntil(10.seconds) { false }
            assertEquals(retriesBefore, p.server.stats.retriesSent, "no Retry for a token holder")
            assertTrue(rec.attempts.isNotEmpty() && rec.attempts.all { it.addressValidated }, "${rec.attempts}")
            assertEquals(1L, p.server.stats.newTokensAccepted)
            val s2 = p.serverCore()
            assertTrue(s2.validatedByToken, "the token validated the address")
            val sent = s2.stats.bytesSent
            assertTrue(sent > 3 * received, "the anti-amplification limit is lifted: $sent bytes sent for $received received")
        } finally {
            p.close()
        }
    }

    @Test fun tokenBoundToIpNotPort() {
        val rec = Recording()
        val p = EndpointPair(crypto = KslQuicCrypto) { admission = rec }
        try {
            val a = p.tokenFromNewConnection()
            val b = p.tokenFromNewConnection()
            rec.attempts.clear()
            p.clientSource = InetSocketAddress("10.0.0.1", 40001)
            val samePort = p.connect()
            samePort.initialToken = a
            assertTrue(p.confirmed(samePort), "${p.closed(samePort)}")
            assertTrue(rec.attempts.first().addressValidated, "another port of the same IP: still validated")
            rec.attempts.clear()
            p.clientSource = InetSocketAddress("10.0.0.9", 40000)
            p.clientListens += p.clientSource
            val otherIp = p.connect()
            otherIp.initialToken = b
            assertTrue(p.confirmed(otherIp), "${p.closed(otherIp)}")
            assertFalse(rec.attempts.first().addressValidated, "another IP: the token does not validate it")
            // counted per Initial: the first flight of a post-quantum ClientHello spans two datagrams, each answered by a Retry
            assertTrue(p.server.stats.newTokensRejected >= 1, "${p.server.stats}")
            assertEquals(1L, p.server.stats.newTokensAccepted)
        } finally {
            p.close()
        }
    }

    @Test fun negative_invalidNewTokenIsTreatedAsAbsent() {
        // RFC 9000 section 8.1.3: "If the server cannot validate the token, the server ... MUST NOT" close with INVALID_TOKEN for a
        // NEW_TOKEN token: it treats the Initial as one without a token (a Retry here, the policy's answer to an unvalidated client)
        for (case in listOf("corrupted", "expired", "otherIp")) {
            val rec = Recording()
            val p = EndpointPair(crypto = KslQuicCrypto) { admission = rec }
            try {
                var token = p.tokenFromNewConnection()
                when (case) {
                    "corrupted" -> {
                        token = token.copyOf().also { it[20] = (it[20].toInt() xor 1).toByte() }
                    }

                    "expired" -> {
                        p.now += 24.hours + 1.nanoseconds
                    }

                    "otherIp" -> {
                        p.clientSource = InetSocketAddress("10.0.0.9", 40000)
                        p.clientListens += p.clientSource
                    }
                }
                rec.attempts.clear()
                val retries = p.server.stats.retriesSent
                val c = p.connect()
                c.initialToken = token
                assertTrue(p.confirmed(c), "$case: the client connects as one without a token: ${p.closed(c)}")
                assertFalse(rec.attempts.first().addressValidated, case)
                assertTrue(p.server.stats.retriesSent > retries, "$case: a Retry, as for a client without a token")
                assertEquals(0L, p.server.stats.invalidTokens, "$case: no INVALID_TOKEN")
                assertTrue(p.server.stats.newTokensRejected >= 1, "$case: ${p.server.stats}")
                assertEquals(0L, p.server.stats.newTokensAccepted, case)
            } finally {
                p.close()
            }
        }
    }

    @Test fun tokenAcceptedUpToItsLifetime() {
        val rec = Recording()
        val p = EndpointPair(crypto = KslQuicCrypto) { admission = rec }
        try {
            val token = p.tokenFromNewConnection()
            p.now += 23.hours // 24 rotations of the hourly key later the token still opens
            rec.attempts.clear()
            val c = p.connect()
            c.initialToken = token
            assertTrue(p.confirmed(c), "${p.closed(c)}")
            assertTrue(rec.attempts.first().addressValidated)
        } finally {
            p.close()
        }
    }

    @Test fun negative_replayedNewTokenValidatesOnce() {
        // RFC 9000 section 8.1.4: "Servers SHOULD ensure that tokens sent in Retry packets are only accepted for a short time" and
        // a NEW_TOKEN token "SHOULD" not validate more than one connection: the replay register lets it through once
        val rec = Recording()
        val p = EndpointPair(crypto = KslQuicCrypto) { admission = rec }
        try {
            val token = p.tokenFromNewConnection()
            rec.attempts.clear()
            val first = p.connect()
            first.initialToken = token
            assertTrue(p.confirmed(first), "${p.closed(first)}")
            assertTrue(rec.attempts.first().addressValidated)
            rec.attempts.clear()
            val replay = p.connect()
            replay.initialToken = token
            assertTrue(p.confirmed(replay), "${p.closed(replay)}")
            assertFalse(rec.attempts.first().addressValidated, "the same token a second time validates nothing")
            assertEquals(1L, p.server.stats.newTokensAccepted)
            assertTrue(p.server.stats.newTokensRejected >= 1, "${p.server.stats}")
        } finally {
            p.close()
        }
    }

    @Test fun negative_tokenOfAnInitialThatMadeNoConnectionCanBeUsedAgain() {
        // the register entry is released when the Initial that carried the token creates no connection (here: the policy drops it), so
        // a client whose first Initial was refused is not turned into a replay of itself
        var drop = true
        val rec = Recording(ConnectionAdmission { a -> if (drop) AdmissionDecision.Drop else ConnectionAdmission.AlwaysRetry.admit(a) })
        val p = EndpointPair(crypto = KslQuicCrypto) { admission = rec }
        try {
            drop = false
            val token = p.tokenFromNewConnection()
            drop = true
            rec.attempts.clear()
            val c = p.connect()
            c.initialToken = token
            p.step()
            assertTrue(rec.attempts.isNotEmpty())
            drop = false
            rec.attempts.clear()
            assertTrue(p.confirmed(c), "${p.closed(c)}")
            assertTrue(rec.attempts.first().addressValidated, "the retransmitted Initial is still validated by the token")
        } finally {
            p.close()
        }
    }

    @Test fun negative_retryTokenNotAcceptedAsNewTokenAndViceVersa() {
        val tokens = AddressTokens(KslQuicCrypto, Random(1))
        val client = InetSocketAddress("10.0.0.1", 40000)
        val t0 = TimeMark(1_000_000_000L)
        try {
            val retry = tokens.mint(ConnectionId(ByteArray(8) { 1 }), ConnectionId(ByteArray(8) { 2 }), client, 1, t0)
            val newToken = tokens.mintNewToken(client, t0)

            fun check(t: ByteArray): TokenCheck {
                val b = PacketBuffer.of(t)
                try {
                    return tokens.check(b, 0, t.size, client, 1, t0 + 1.seconds)
                } finally {
                    b.close()
                }
            }
            assertIs<TokenCheck.Valid>(check(retry))
            assertIs<TokenCheck.NewTokenValid>(check(newToken))
            assertEquals(TokenCheck.NewTokenRejected, check(retry.copyOf().also { it[0] = 0x02 }), "a Retry token retagged as NEW_TOKEN")
            assertEquals(TokenCheck.Invalid, check(newToken.copyOf().also { it[0] = 0x01 }), "a NEW_TOKEN token retagged as Retry")
            assertEquals(TokenCheck.NewTokenRejected, check(newToken.copyOf(newToken.size - 1)), "truncated")
            assertEquals(TokenCheck.NewTokenRejected, check(newToken + 0), "extended")
        } finally {
            tokens.close()
        }
    }

    @Test fun negative_fullReplayRegisterFailsClosed() {
        // a register at its load limit admits nothing more: the token holder is treated as a client without a token (at worst a Retry)
        val r = Random(4)
        val tokens = AddressTokens(KslQuicCrypto, r, register = ZeroRttReplayRegister(r, stripeCount = 1, slots = 4, halfSpan = 24.hours))
        val client = InetSocketAddress("10.0.0.1", 40000)
        val t0 = TimeMark(1_000_000_000L)
        try {
            val admitted =
                List(4) {
                    val t = tokens.mintNewToken(client, t0)
                    val b = PacketBuffer.of(t)
                    val check =
                        try {
                            tokens.check(b, 0, t.size, client, 1, t0)
                        } finally {
                            b.close()
                        }
                    tokens.admitNewToken(assertIs<TokenCheck.NewTokenValid>(check).nonce, t0)
                }
            assertEquals(listOf(true, true, true, false), admitted, "three of four slots, then fail closed")
        } finally {
            tokens.close()
        }
    }

    @Test fun negative_newTokenNonceIsUniqueAndCarriesNoConnectionData() {
        // RFC 9000 section 8.1.3: a token MUST NOT carry anything that links it to the connection it was issued on; each one is unique
        val tokens = AddressTokens(KslQuicCrypto, Random(1))
        val client = InetSocketAddress("10.0.0.1", 40000)
        try {
            val seen = HashSet<String>()
            repeat(200) { seen += tokens.mintNewToken(client, TimeMark(1_000_000_000L)).toHexForTest() }
            assertEquals(200, seen.size)
        } finally {
            tokens.close()
        }
    }

    @Test fun tokenFromOneLoopValidOnAnother() {
        // the loops of a group share one AddressTokens: a client the kernel hashes onto another loop next time is still validated
        val shared = AddressTokens(KslQuicCrypto, Random(3), owners = 2)
        val rec = Recording()
        val p = EndpointPair(crypto = KslQuicCrypto, sharedTokens = shared) { admission = rec }
        val other =
            EndpointCore(
                QuicEndpointConfig
                    .Builder()
                    .apply {
                        server = QuicServerConfig.Builder(CoreFixtures.server()).build()
                        crypto = KslQuicCrypto
                        admission = rec
                    }.build(),
                Random(9),
                1,
                shared,
            )
        try {
            val token = p.tokenFromNewConnection()
            val c = p.connect()
            c.initialToken = token
            rec.attempts.clear()
            val batch = io.kuicksilver.quic.PacketBatch(16)
            try {
                val n = c.poll(batch, p.now)
                assertTrue(n > 0)
                for (i in 0 until n) {
                    val bytes = ByteArray(batch.length(i)).also { batch.buffer(i).copyTo(it, 0, 0, it.size) }
                    p.feedNoAdmit(other, bytes, p.clientAddr)
                }
                other.processPending(p.now)
            } finally {
                batch.close()
            }
            assertEquals(1, other.connectionCount, "loop 1 admitted the client")
            assertTrue(rec.attempts.first().addressValidated, "with the token loop 0 issued")
            assertEquals(0L, other.stats.retriesSent)
            assertEquals(1L, other.stats.newTokensAccepted)
        } finally {
            other.close()
            p.close()
        }
    }

    @Test fun secondTokenAfterMigrationToNewIp() {
        // ngtcp2's NGTCP2_PATH_VALIDATION_FLAG_NEW_TOKEN: a client validated on a new IP gets a token for that IP; at most four per connection
        val p = EndpointPair(crypto = KslQuicCrypto)
        try {
            val c = p.connect()
            assertTrue(p.confirmed(c))
            val s = p.serverCore()
            assertTrue(p.runUntil { s.newTokenSendsForTest.isNotEmpty() })
            for (i in 1..6) {
                val addr = InetSocketAddress("10.0.1.$i", 40000)
                p.clientSource = addr
                p.clientListens += addr
                val id = c.openStream(true)
                c.writeStream(id, ByteArray(100) { 0x41 }, 0, 100, true)
                assertTrue(
                    p.runUntil { s.remoteAddressForTest == addr && s.path.state == io.kuicksilver.quic.PathState.Validated },
                    "migration $i",
                )
                p.runUntil(1.seconds) { false }
            }
            val distinct = s.newTokenSendsForTest.map { it.toHexForTest() }.distinct()
            assertEquals(4, distinct.size, "one token at the handshake, then one per new IP, four at most")
            assertEquals(4L, p.server.stats.newTokensIssued)
            assertNotNull(c)
        } finally {
            p.close()
        }
    }
}

internal fun ByteArray.toHexForTest(): String = joinToString("") { (it.toInt() and 0xff).toString(16).padStart(2, '0') }
