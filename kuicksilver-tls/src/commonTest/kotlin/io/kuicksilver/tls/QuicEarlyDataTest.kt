// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(ExperimentalKuicksilverApi::class)

package io.kuicksilver.tls

import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.native.KslLoader
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** QUIC resumption and 0-RTT at the TLS layer (ADR-0015): tickets, the early-data verdict, the configuration context. */
class QuicEarlyDataTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    /** An admission that remembers what it saw: the second hello with the same ticket is refused (a replay register). */
    private class SetAdmission : EarlyDataAdmission {
        val seen = ArrayList<ByteArray>()
        val released = ArrayList<ByteArray>()

        override fun admit(ticketId: ByteArray): Boolean {
            if (seen.any { it.contentEquals(ticketId) }) return false
            seen += ticketId
            return true
        }

        override fun release(ticketId: ByteArray) {
            released += ticketId
            seen.removeAll { it.contentEquals(ticketId) }
        }
    }

    private class Run(
        val pump: Pump,
        val clientEvents: List<TlsEvent>,
        val earlyLevels: Pair<Int, Int>,
    )

    /** A handshake; returns the tickets the client received and the 0-RTT keys each side got. */
    private fun handshake(
        client: QuicTlsSession,
        server: QuicTlsSession,
    ): Run {
        client.setTransportParameters(Fixtures.tp)
        server.setTransportParameters(Fixtures.tp)
        val events = ArrayList<TlsEvent>()
        var clientEarly = 0
        var serverEarly = 0
        val p = Pump(client, server)
        p.onEvent = { fromClient, ev ->
            if (fromClient) events += ev
            if (ev is TlsEvent.Keys && ev.level == EncryptionLevel.EarlyData) {
                if (fromClient) {
                    assertEquals(Direction.Write, ev.direction)
                    clientEarly++
                } else {
                    assertEquals(Direction.Read, ev.direction)
                    serverEarly++
                }
            }
        }
        p.run()
        return Run(p, events, clientEarly to serverEarly)
    }

    private fun tickets(r: Run): List<QuicSessionTicket> = r.clientEvents.filterIsInstance<TlsEvent.SessionTicket>().map { it.ticket }

    private fun firstTicket(
        server: () -> QuicTlsSession,
        context: ByteArray = byteArrayOf(1),
    ): QuicSessionTicket {
        val s = server()
        assertTrue(s.enableEarlyData(context, SetAdmission()))
        val r = handshake(KslQuicCrypto.newSession(Fixtures.client(), earlyData = true), s)
        assertTrue(r.pump.cs.done && r.pump.ss.done)
        val t = tickets(r)
        assertTrue(t.isNotEmpty(), "a full handshake issues tickets (two NewSessionTickets, the newest one kept)")
        t.drop(1).forEach { it.close() }
        r.pump.close()
        return t[0]
    }

    @Test fun zeroRttAcceptedOnResumption() {
        val ticket = firstTicket({ KslQuicCrypto.newSession(Fixtures.server(), earlyData = true) })
        val c = KslQuicCrypto.newSession(Fixtures.client(), earlyData = true)
        assertTrue(c.resume(ticket))
        assertTrue(c.enableEarlyData(null, null), "the ticket allows early data")
        val s = KslQuicCrypto.newSession(Fixtures.server(), earlyData = true)
        val admission = SetAdmission()
        assertTrue(s.enableEarlyData(byteArrayOf(1), admission))
        val r = handshake(c, s)
        try {
            assertEquals(1 to 1, r.earlyLevels, "0-RTT write key on the client, read key on the server")
            assertEquals(true, c.earlyDataAccepted)
            assertEquals(true, s.earlyDataAccepted)
            assertEquals(1, admission.seen.size)
            assertEquals(32, admission.seen[0].size, "the ticket identity is key_name and iv")
            assertTrue(admission.released.isEmpty())
            assertEquals(1, tickets(r).size, "a resumption issues one fresh ticket")
            tickets(r).forEach { it.close() }
        } finally {
            r.pump.close()
        }
    }

    @Test fun negative_0rttReplayRejected() {
        val ticket = firstTicket({ KslQuicCrypto.newSession(Fixtures.server(), earlyData = true) })
        val c = KslQuicCrypto.newSession(Fixtures.client(), earlyData = true)
        c.resume(ticket)
        c.enableEarlyData(null, null)
        c.setTransportParameters(Fixtures.tp)
        c.drive()
        val hello = ArrayList<ByteArray>()
        while (true) {
            val ev = c.nextEvent() ?: break
            if (ev is TlsEvent.CryptoData) hello += ev.data
            if (ev is TlsEvent.Keys) ev.protector.close()
        }
        val admission = SetAdmission()
        val verdicts =
            (0 until 2).map {
                val s = KslQuicCrypto.newSession(Fixtures.server(), earlyData = true)
                s.enableEarlyData(byteArrayOf(1), admission)
                s.setTransportParameters(Fixtures.tp)
                hello.forEach { b -> s.provide(EncryptionLevel.Initial, b) }
                s.drive()
                while (true) {
                    val ev = s.nextEvent() ?: break
                    if (ev is TlsEvent.Keys) ev.protector.close()
                }
                s.earlyDataAccepted.also { s.close() }
            }
        assertEquals(listOf<Boolean?>(true, false), verdicts, "the replayed ClientHello gets no early data")
        c.close()
    }

    @Test fun contextMismatchRejectsEarlyDataButResumes() {
        val ticket = firstTicket({ KslQuicCrypto.newSession(Fixtures.server(), earlyData = true) }, byteArrayOf(1))
        val c = KslQuicCrypto.newSession(Fixtures.client(), earlyData = true)
        c.resume(ticket)
        assertTrue(c.enableEarlyData(null, null))
        val s = KslQuicCrypto.newSession(Fixtures.server(), earlyData = true)
        val admission = SetAdmission()
        s.enableEarlyData(byteArrayOf(2), admission)
        val r = handshake(c, s)
        try {
            assertEquals(1 to 0, r.earlyLevels)
            assertEquals(false, c.earlyDataAccepted)
            assertEquals(false, s.earlyDataAccepted)
            assertTrue(r.pump.cs.done && r.pump.ss.done)
            assertEquals(1, admission.released.size, "a refused hello gives its reservation back")
            tickets(r).forEach { it.close() }
        } finally {
            r.pump.close()
        }
    }

    @Test fun ticketWithoutEarlyDataPermissionGivesNoZeroRtt() {
        val ticket = firstTicket({ KslQuicCrypto.newSessionForTest(Fixtures.server(), ticketsWithoutEarlyData = true) })
        val c = KslQuicCrypto.newSession(Fixtures.client(), earlyData = true)
        assertTrue(c.resume(ticket))
        assertFalse(c.enableEarlyData(null, null), "the ticket carries no early_data")
        assertNull(c.earlyDataAccepted)
        c.close()
    }

    /**
     * Fuzzing finding (zeroRttHello): reading the early-data verdict of a session whose handshake failed threw the native
     * layer's KslException, which the session contract keeps inside. It reads as "no early data".
     */
    @Test fun negative_earlyDataVerdictAfterFailedHandshake() {
        val s = KslQuicCrypto.newSession(Fixtures.server(), earlyData = true)
        try {
            assertTrue(s.enableEarlyData(byteArrayOf(1), SetAdmission()))
            s.setTransportParameters(Fixtures.tp)
            s.provide(EncryptionLevel.Initial, byteArrayOf(1, 0, 0, 4, 3, 3, 0, 0))
            assertIs<DriveResult.Failed>(s.drive())
            assertNull(s.earlyDataAccepted, "a failed hello got no early data")
        } finally {
            s.close()
        }
    }

    @Test fun noTicketsWithoutEarlyDataOption() {
        val s = KslQuicCrypto.newSession(Fixtures.server())
        val r = handshake(KslQuicCrypto.newSession(Fixtures.client(), earlyData = true), s)
        try {
            assertTrue(r.pump.cs.done)
            assertTrue(tickets(r).isEmpty(), "a QUIC server issues tickets only with 0-RTT on")
        } finally {
            r.pump.close()
        }
    }

    @Test fun clientHelloScanFindsTicketIdentity() {
        val ticket = firstTicket({ KslQuicCrypto.newSession(Fixtures.server(), earlyData = true) })
        val c = KslQuicCrypto.newSession(Fixtures.client(), earlyData = true)
        c.resume(ticket)
        c.enableEarlyData(null, null)
        c.setTransportParameters(Fixtures.tp)
        c.drive()
        var hello = ByteArray(0)
        while (true) {
            val ev = c.nextEvent() ?: break
            if (ev is TlsEvent.CryptoData && ev.level == EncryptionLevel.Initial) hello += ev.data
            if (ev is TlsEvent.Keys) ev.protector.close()
        }
        c.close()
        val whole = ClientHelloScan().feed(hello, 0, hello.size)
        assertNotNull(whole)
        assertTrue(whole.earlyData)
        val id = assertNotNull(whole.ticketId)
        val scan = ClientHelloScan()
        var bytewise: ClientHelloScan.Result? = null
        for (i in hello.indices) bytewise = scan.feed(hello, i, 1) ?: bytewise
        assertContentEquals(id, assertNotNull(bytewise).ticketId, "byte-by-byte feeding finds the same identity")
        val plain = ClientHelloScan().feed(hello.copyOf(40), 0, 40)
        assertNull(plain, "incomplete")
        val huge = byteArrayOf(1, 0x01, 0, 0) // a 64 KiB ClientHello
        assertEquals(false, ClientHelloScan().feed(huge, 0, 4)?.earlyData, "beyond the bound: decided, no early data")
    }
}
