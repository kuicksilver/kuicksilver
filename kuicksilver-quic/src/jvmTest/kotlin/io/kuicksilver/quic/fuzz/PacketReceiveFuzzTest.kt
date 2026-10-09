// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.fuzz

import com.code_intelligence.jazzer.junit.FuzzTest
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.native.KslLoader
import io.kuicksilver.quic.ConnectionCore
import io.kuicksilver.quic.ConnectionEvent
import io.kuicksilver.quic.ConnectionState
import io.kuicksilver.quic.CorePair
import io.kuicksilver.quic.Dgram
import kotlin.time.Duration.Companion.milliseconds

/**
 * Fuzz targets on the receive path of the sans-IO core with NullCryptoProvider (packets are plaintext with a zero
 * tag, so mutations reach the frame handlers). The core must never throw out of handleDatagram/poll/onTimeout;
 * errors surface as [ConnectionEvent.Closed]. Seeds come from a Null-crypto handshake (`tools/fuzz/gen-seeds.sh`).
 */
@OptIn(ExperimentalKuicksilverApi::class)
class PacketReceiveFuzzTest {
    /** `packetRecvServer`: one datagram from a client to a fresh server endpoint. */
    @FuzzTest(maxDuration = "60s")
    fun packetRecvServer(data: ByteArray) {
        CoreDriver().use { d ->
            val ep = d.serverEndpoint()
            d.deliver(ep, data, fuzzClientAddr)
            d.service(ep)
            d.tick()
            d.service(ep)
        }
    }

    /** `packetRecvClient`: one datagram from the server to a client that has sent its first Initial. */
    @FuzzTest(maxDuration = "60s")
    fun packetRecvClient(data: ByteArray) {
        CoreDriver().use { d ->
            val c = d.client()
            d.service(c)
            d.deliver(c, data, fuzzServerAddr)
            d.service(c)
            d.tick()
            d.service(c)
        }
    }

    /** `multiPacket`: a sequence of length-prefixed datagrams (see [Framing]) to one server endpoint. */
    @FuzzTest(maxDuration = "60s")
    fun multiPacket(data: ByteArray) {
        CoreDriver().use { d ->
            val ep = d.serverEndpoint()
            for (dg in Framing.split(data)) {
                d.deliver(ep, dg, fuzzClientAddr)
                d.service(ep)
                d.tick(5)
            }
            d.tick()
            d.service(ep)
        }
    }

    /**
     * `postHandshake`: a Null-crypto pair completes its handshake, then input = [flags][length-prefixed datagrams] is
     * injected into one side while the pair keeps exchanging packets. Flags: bit 0 — to the client instead of the
     * server; bit 1 — the client starts a key update first (packets of both phases are in flight); bit 2 — the client
     * sends PATH_CHALLENGEs; bit 3 — the client sends DATAGRAM frames.
     */
    @FuzzTest(maxDuration = "60s")
    fun postHandshake(data: ByteArray) {
        if (data.isEmpty()) return
        KslLoader.ensureLoaded()
        val p = CorePair()
        try {
            check(p.handshake()) { "Null-crypto handshake did not complete" }
            val flags = data[0].toInt()
            val toServer = flags and 1 == 0
            if (flags and 2 != 0) {
                p.runUntil(limit = 200.milliseconds) { p.client.initiateKeyUpdate(p.now) }
            }
            if (flags and 4 != 0) p.client.testInjectPathChallenges = 2
            if (flags and 8 != 0) {
                p.client.datagramSender =
                    object : io.kuicksilver.quic.DatagramSender {
                        var left = 3

                        override fun onTransmit(packet: io.kuicksilver.quic.DatagramPacketWriter) {
                            if (left > 0 &&
                                packet.write(ByteArray(100) { 7 }, 0, 100)
                            ) {
                                left--
                            }
                        }

                        override fun hasPending(): Boolean = left > 0
                    }
            }
            for (dg in Framing.split(data, 1)) {
                if (toServer) p.toServer += Dgram(dg, fuzzClientAddr) else p.toClient += Dgram(dg, fuzzServerAddr)
                p.step()
                p.advance(5.milliseconds)
            }
            repeat(3) {
                p.step()
                p.advance(30.milliseconds)
            }
            closedReported(p.client, p.clientEvents)
            p.server?.let { closedReported(it, p.serverEvents) }
        } finally {
            p.close()
        }
    }

    private fun closedReported(
        core: ConnectionCore,
        events: List<ConnectionEvent>,
    ) {
        if (core.state == ConnectionState.Closing || core.state == ConnectionState.Draining || core.state == ConnectionState.Closed) {
            check(events.any { it is ConnectionEvent.Closed }) { "connection reached ${core.state} without a Closed event" }
        }
    }
}
