// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.core

import io.kuicksilver.annotations.DelicateKuicksilverApi
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.native.KslLoader
import io.kuicksilver.quic.ConnectionEvent
import io.kuicksilver.quic.CoreFixtures
import io.kuicksilver.quic.CorePair
import io.kuicksilver.quic.Initiator
import io.kuicksilver.quic.QuicConfig
import io.kuicksilver.quic.QuicException
import io.kuicksilver.quic.endpoint.ZeroRttReplayRegister
import io.kuicksilver.quic.ksl
import io.kuicksilver.tls.EarlyDataState
import io.kuicksilver.tls.KeyExchangeGroups
import io.kuicksilver.tls.QuicSessionTicket
import io.kuicksilver.tls.TlsConfig
import io.kuicksilver.tls.TlsException
import kotlin.random.Random
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.seconds

/**
 * Key-exchange groups over a QUIC connection with the real handshake: a HelloRetryRequest travels in Initial packets like any
 * other handshake message (RFC 9001 section 4.7) and rejects 0-RTT (section 4.6.2); no group in common closes the connection
 * with CRYPTO_ERROR 0x0128, `handshake_failure` plus 0x0100 (section 4.8).
 */
@OptIn(ExperimentalKuicksilverApi::class, DelicateKuicksilverApi::class)
class KeyExchangeGroupsCoreTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    private val register = ZeroRttReplayRegister(Random(7))

    private fun groups(vararg names: String) = KeyExchangeGroups(names.toList())

    @Test fun aHelloRetryRequestCompletesTheConnection() {
        val p =
            CorePair(
                clientTls = CoreFixtures.client { keyExchangeGroups = groups(KeyExchangeGroups.X25519, KeyExchangeGroups.SECP256R1) },
                serverTls =
                    CoreFixtures.server { keyExchangeGroups = groups(KeyExchangeGroups.SECP384R1, KeyExchangeGroups.SECP256R1) },
                crypto = ksl,
            )
        p.use { _ ->
            assertTrue(p.handshake(), "${p.closedReason(p.clientEvents)} / ${p.closedReason(p.serverEvents)}")
            assertEquals(KeyExchangeGroups.SECP256R1, p.client.keyExchangeGroup)
            assertEquals(KeyExchangeGroups.SECP256R1, p.server!!.keyExchangeGroup)
        }
    }

    @Test fun negative_noCommonGroupCloses0x0128() {
        val p =
            CorePair(
                clientTls = CoreFixtures.client { keyExchangeGroups = groups(KeyExchangeGroups.X25519, KeyExchangeGroups.X448) },
                serverTls = CoreFixtures.server { keyExchangeGroups = groups(KeyExchangeGroups.SECP384R1) },
                crypto = ksl,
            )
        p.use { _ ->
            assertFalse(p.handshake())
            val s = p.closedReason(p.serverEvents)
            assertIs<QuicException.ConnectionLost.TransportClosed>(s)
            assertEquals(0x0128L, s.code)
            assertEquals(Initiator.Local, s.initiator)
            val c = p.closedReason(p.clientEvents)
            assertIs<QuicException.ConnectionLost.TransportClosed>(c)
            assertEquals(0x0128L, c.code)
            assertEquals(Initiator.Peer, c.initiator)
            assertIs<TlsException.AlertReceived>(c.cause)
            assertEquals(40, (c.cause as TlsException.AlertReceived).code)
        }
    }

    private fun ticket(): QuicSessionTicket {
        val p =
            CorePair(
                crypto = ksl,
                clientEarly = EarlyDataState.Allowed,
                serverEarly = ServerEarlyData.of(QuicConfig.Default, CoreFixtures.server().alpn, null, register),
            )
        assertTrue(p.handshake())
        assertTrue(p.runUntil(limit = 2.seconds) { p.clientEvents.any { it is ConnectionEvent.SessionTicket } })
        val tickets = p.clientEvents.filterIsInstance<ConnectionEvent.SessionTicket>().map { it.ticket }
        tickets.drop(1).forEach { it.close() }
        p.close()
        return tickets.last()
    }

    /**
     * A ticket from a server that took X25519MLKEM768, resumed with 0-RTT at a server of secp384r1 alone: the client's second
     * ClientHello goes in an Initial packet without early_data, the server rejects 0-RTT (it sent a HelloRetryRequest), and the
     * connection completes resumed. Before the fix in `ksl` the second ClientHello was handed out at the 0-RTT level, which
     * the server never reads, and the handshake timed out.
     */
    @Test fun negative_zeroRttAfterAHelloRetryRequestIsRejectedAndTheConnectionCompletes() {
        val t = ticket()
        var id = -1L
        val server: TlsConfig = CoreFixtures.server { keyExchangeGroups = groups(KeyExchangeGroups.SECP384R1) }
        val p =
            CorePair(
                serverTls = server,
                crypto = ksl,
                clientEarly = EarlyDataState.Allowed,
                serverEarly = ServerEarlyData.of(QuicConfig.Default, server.alpn, null, register),
                clientSetup = { c ->
                    assertTrue(c.useTicket(t), "0-RTT available with this ticket")
                    id = c.openStream(bidi = true)
                    c.writeStream(id, "early".encodeToByteArray(), 0, 5, fin = true)
                },
            )
        p.use { _ ->
            assertTrue(p.handshake(), "${p.closedReason(p.clientEvents)} / ${p.closedReason(p.serverEvents)}")
            assertEquals(false, p.client.earlyDataAccepted)
            assertEquals(false, p.server!!.earlyDataAccepted)
            assertTrue(p.clientEvents.any { it is ConnectionEvent.EarlyDataRejected }, p.clientEvents.toString())
            assertTrue(p.serverEvents.none { it is ConnectionEvent.StreamReadable && it.id == id }, "no 0-RTT stream reached the server")
        }
    }

    /**
     * A 0-RTT stream retired by our reset before the server answered, its size held for that answer, and the answer a
     * HelloRetryRequest, which rejects 0-RTT (RFC 9001 section 4.6.2): the rejection drops the stream with the rest of our
     * 0-RTT streams. Nothing of it is offered again as at an acceptance, no size is reported, and no reset waits for an
     * acknowledgment the server, which discarded our 0-RTT packets, will never send.
     */
    @Test fun negative_aStreamResetInZeroRttIsDroppedWhenAHelloRetryRequestRejectsIt() {
        val t = ticket()
        var id = -1L
        val server: TlsConfig = CoreFixtures.server { keyExchangeGroups = groups(KeyExchangeGroups.SECP384R1) }
        val p =
            CorePair(
                serverTls = server,
                crypto = ksl,
                clientEarly = EarlyDataState.Allowed,
                serverEarly = ServerEarlyData.of(QuicConfig.Default, server.alpn, null, register),
                clientSetup = { c ->
                    assertTrue(c.useTicket(t), "0-RTT available with this ticket")
                    id = c.openStream(bidi = false)
                    c.writeStream(id, "early".encodeToByteArray(), 0, 5, fin = false)
                },
            )
        p.use { _ ->
            p.filterToClient = { _, _ -> false } // the HelloRetryRequest waits until the reset went out
            p.step() // the ClientHello and the 0-RTT bytes go out
            p.client.resetStream(id, 4)
            p.step() // the RESET_STREAM goes out in 0-RTT, which the server discards
            p.filterToClient = { _, _ -> true }
            assertEquals(listOf(id), p.client.streams.takeRetiredAwaitingAck(), "retired at the reset")
            assertTrue(p.client.streams.heldForAnswer(id), "its size is held for the answer")
            assertTrue(p.handshake(), "${p.closedReason(p.clientEvents)} / ${p.closedReason(p.serverEvents)}")
            assertEquals(false, p.client.earlyDataAccepted)
            assertTrue(p.clientEvents.any { it is ConnectionEvent.EarlyDataRejected }, p.clientEvents.toString())
            assertFalse(p.client.streams.heldForAnswer(id))
            assertEquals(null, p.client.streams.takeRetiredAwaitingAck(), "a rejection offers nothing again")
            assertEquals(
                listOf(0, 0),
                p.client.streams
                    .resetAcksPendingForTest()
                    .toList(),
                "no reset waits for its acknowledgment",
            )
            assertTrue(
                p.clientEvents.none { (it is ConnectionEvent.StreamFinished && it.id == id) },
                "the dropped stream is never reported finished",
            )
        }
    }
}
