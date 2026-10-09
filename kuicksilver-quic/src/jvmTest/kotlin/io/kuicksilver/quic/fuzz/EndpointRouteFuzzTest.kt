// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.fuzz

import com.code_intelligence.jazzer.junit.FuzzTest
import io.ktor.network.sockets.InetSocketAddress
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.quic.ConnectionState

/**
 * Fuzz target: a server endpoint that already holds one established Null-crypto connection receives arbitrary
 * datagrams — Initials with tokens, short headers to known and unknown IDs (Stateless Reset candidates), Version
 * Negotiation — from the connection's address or from a stranger. Input: `[bit 0: from a stranger][length-prefixed datagrams]`.
 */
@OptIn(ExperimentalKuicksilverApi::class)
class EndpointRouteFuzzTest {
    @FuzzTest(maxDuration = "60s")
    fun endpointRoute(data: ByteArray) {
        if (data.isEmpty()) return
        CoreDriver().use { d ->
            val ep = d.serverEndpoint()
            val c = d.client()
            var rounds = 0
            while (c.state != ConnectionState.Confirmed && rounds++ < 100) {
                for (dg in d.service(c)) d.deliver(ep, dg, fuzzClientAddr)
                while (ep.nextAccepted() != null) { /* the application takes every connection */ }
                for (s in ep.connections().toList()) for (dg in d.service(s)) d.deliver(c, dg, fuzzServerAddr)
                d.tick(5)
            }
            check(c.state == ConnectionState.Confirmed) { "Null-crypto handshake did not complete" }
            val from = if (data[0].toInt() and 1 != 0) InetSocketAddress("10.0.0.9", 4444) else fuzzClientAddr
            for (dg in Framing.split(data, 1)) {
                d.deliver(ep, dg, from)
                d.service(ep)
                d.tick(5)
            }
            d.tick()
            d.service(ep)
            for (dg in d.service(c)) d.deliver(ep, dg, fuzzClientAddr)
            d.service(ep)
        }
    }
}
