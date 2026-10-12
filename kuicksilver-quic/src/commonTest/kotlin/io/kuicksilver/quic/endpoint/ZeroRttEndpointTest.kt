// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.endpoint

import io.kuicksilver.annotations.DelicateKuicksilverApi
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.native.KslLoader
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
}
