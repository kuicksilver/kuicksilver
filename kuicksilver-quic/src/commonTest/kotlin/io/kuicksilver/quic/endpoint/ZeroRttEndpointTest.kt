// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.endpoint

import io.kuicksilver.annotations.DelicateKuicksilverApi
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.native.KslLoader
import io.kuicksilver.quic.ConnectionCore
import io.kuicksilver.quic.ConnectionEvent
import io.kuicksilver.quic.ConnectionState
import io.kuicksilver.quic.CoreFixtures
import io.kuicksilver.quic.QuicClientConfig
import io.kuicksilver.quic.ksl
import io.kuicksilver.tls.EarlyDataState
import io.kuicksilver.tls.QuicSessionTicket
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/** 0-RTT datagrams that reach the endpoint before the Initial that creates their connection wait for it (as quic-go). */
@OptIn(ExperimentalKuicksilverApi::class, DelicateKuicksilverApi::class)
class ZeroRttEndpointTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    private val cfg = QuicClientConfig.Builder(CoreFixtures.client()).apply { earlyData = EarlyDataState.Allowed }.build()

    private fun ticket(p: EndpointPair): QuicSessionTicket {
        val c = p.client.connect(cfg, p.serverAddr, p.now)
        assertTrue(p.runUntil { p.events[c]?.any { it is ConnectionEvent.SessionTicket } == true })
        return p.events[c]!!
            .filterIsInstance<ConnectionEvent.SessionTicket>()
            .last()
            .ticket
    }

    @Test fun zeroRttBeforeInitialIsBuffered() {
        val p = EndpointPair(crypto = ksl, serverEarlyData = true)
        val t = ticket(p)
        // the whole first flight (Initial datagrams, then 0-RTT ones) reaches the server before it admits the Initial
        val c = p.client.connect(cfg, p.serverAddr, p.now, t)
        val id = c.openStream(bidi = true)
        val req = "x".repeat(3000).encodeToByteArray() // more than one datagram of 0-RTT
        assertEquals(req.size, c.writeStream(id, req, 0, req.size, fin = true))
        var server: io.kuicksilver.quic.ConnectionCore? = null
        p.onServerCreated = { server = it }
        p.step()
        val s = server!!
        assertTrue(s.state == ConnectionState.Handshaking)
        assertEquals(true, s.earlyDataAccepted)
        assertTrue(s.streamReceivedEarly(id), "the 0-RTT datagrams that came with or before the Initial were read early")
        val buf = ByteArray(4096)
        var n = 0
        while (true) {
            val r = s.readStream(id, buf, 0, buf.size)
            if (r <= 0) break
            n += r
        }
        assertEquals(req.size, n, "all of the early request is readable before the handshake completes")
    }

    /** The client's first flight of a 0-RTT connection to [p]'s server, captured on the wire; the server accepted its early data. */
    private fun capturedEarlyFlight(p: EndpointPair): List<ByteArray> {
        val t = ticket(p)
        val flight = ArrayList<ByteArray>()
        p.filterToServer = { _, b ->
            flight += b
            true
        }
        val c = p.client.connect(cfg, p.serverAddr, p.now, t)
        val id = c.openStream(bidi = true)
        val req = "POST /transfer".encodeToByteArray()
        assertEquals(req.size, c.writeStream(id, req, 0, req.size, fin = true))
        var server: ConnectionCore? = null
        p.onServerCreated = { server = it }
        p.step()
        assertEquals(true, server!!.earlyDataAccepted, "the original connection gets its early data")
        return flight.toList()
    }

    /** Replays [flight] to [q]'s server as an attacker on the path would; returns the connection it creates there. */
    private fun replayTo(
        q: EndpointPair,
        flight: List<ByteArray>,
    ): ConnectionCore {
        var created: ConnectionCore? = null
        for (b in flight) q.feed(q.server, b, q.clientAddr)?.let { if (created == null) created = it }
        return created!!
    }

    @Test fun negative_0rttReplayToSecondEndpointRejected() {
        // the same configuration bound twice in one process (IPv4 and IPv6 listeners, two ports, an HTTP/3 endpoint per bind):
        // the ticket keys are process-wide, so the second endpoint decrypts the ticket and must still refuse its early data
        val p = EndpointPair(crypto = ksl, serverEarlyData = true)
        val flight = capturedEarlyFlight(p)
        val q = EndpointPair(crypto = ksl, serverEarlyData = true)
        val replay = replayTo(q, flight)
        assertEquals(false, replay.earlyDataAccepted, "a second endpoint of this process refuses the replayed early data")
        assertTrue(!replay.isStreamOpenForTest(0), "nothing of the replay reaches the application")
        // the endpoints stop and a new one starts in the same process (an engine restart): the register outlives them
        p.close()
        q.close()
        val r = EndpointPair(crypto = ksl, serverEarlyData = true)
        assertEquals(false, replayTo(r, flight).earlyDataAccepted, "a restarted endpoint refuses the replayed early data")
        r.close()
    }
}
