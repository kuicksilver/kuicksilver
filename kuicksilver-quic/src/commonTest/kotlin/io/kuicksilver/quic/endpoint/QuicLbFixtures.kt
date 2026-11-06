// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(ExperimentalKuicksilverApi::class, DelicateKuicksilverApi::class)

package io.kuicksilver.quic.endpoint

import io.ktor.network.sockets.InetSocketAddress
import io.kuicksilver.annotations.DelicateKuicksilverApi
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.native.PacketBuffer
import io.kuicksilver.native.of
import io.kuicksilver.native.toByteArray
import io.kuicksilver.quic.ConnectionCore
import io.kuicksilver.quic.ConnectionEvent
import io.kuicksilver.quic.ConnectionState
import io.kuicksilver.quic.CoreFixtures
import io.kuicksilver.quic.Ecn
import io.kuicksilver.quic.EndpointCore
import io.kuicksilver.quic.NullCryptoProvider
import io.kuicksilver.quic.PacketBatch
import io.kuicksilver.quic.QuicClientConfig
import io.kuicksilver.quic.QuicEndpointConfig
import io.kuicksilver.quic.QuicLbConfig
import io.kuicksilver.quic.QuicServerConfig
import io.kuicksilver.quic.TimeMark
import io.kuicksilver.quic.quicConfig
import io.kuicksilver.tls.KslQuicCrypto
import io.kuicksilver.tls.LoadBalancerKey
import io.kuicksilver.tls.QuicCrypto
import kotlinx.coroutines.runBlocking
import kotlin.random.Random
import kotlin.time.Duration.Companion.milliseconds

/** [NullCryptoProvider] for the connections, OpenSSL for the QUIC-LB keys: deterministic handshakes, real AES in the IDs. */
internal object LbNullCrypto : QuicCrypto by NullCryptoProvider {
    override fun newLoadBalancerKey(key: ByteArray?): LoadBalancerKey = KslQuicCrypto.newLoadBalancerKey(key)
}

internal object QuicLbFixtures {
    val KEY = "8f95f09245765f80256934e50c66207f"
    val SID = byteArrayOf(0xed.toByte(), 0x79, 0x3a)

    fun hex(s: String) = ByteArray(s.length / 2) { s.substring(2 * it, 2 * it + 2).toInt(16).toByte() }

    private val keys = HashMap<String, LoadBalancerKey>()

    /** One native key per hex string for the test process (never closed: configurations may outlive a test's endpoints). */
    fun key(hexKey: String = KEY): LoadBalancerKey = keys.getOrPut(hexKey) { KslQuicCrypto.newLoadBalancerKey(hex(hexKey)) }

    /** An 8-byte configuration: a 3-byte server ID and a 4-byte nonce, encrypted with [keyHex] unless [plaintext]. */
    fun config(
        configId: Int = 2,
        sid: ByteArray = SID,
        plaintext: Boolean = false,
        keyHex: String = KEY,
    ) = QuicLbConfig(configId, sid, 4, if (plaintext) null else key(keyHex))

    fun endpointConfig(
        lb: QuicLbConfig?,
        loops: Int = 1,
    ): QuicEndpointConfig =
        QuicEndpointConfig
            .Builder()
            .apply {
                server =
                    QuicServerConfig
                        .Builder(CoreFixtures.server())
                        .apply { quic = quicConfig { connectionIdLength = lb?.connectionIdLength ?: 8 } }
                        .build()
                connectionIdLength = lb?.connectionIdLength ?: 8
                crypto = LbNullCrypto
                loadBalancer = lb
                this.loops = loops
            }.build()

    /** A short-header datagram of [size] bytes addressed to [dcid]. */
    fun shortTo(
        dcid: ByteArray,
        size: Int = 100,
    ): ByteArray {
        val r = Random(1)
        val b = ByteArray(size) { r.nextInt().toByte() }
        b[0] = (0x40 or (b[0].toInt() and 0x3f)).toByte()
        dcid.copyInto(b, 1)
        return b
    }

    /** The ID [config] gives [nonce] (and [sid] in place of the configuration's own). */
    fun cidOf(
        config: QuicLbConfig,
        nonce: ByteArray,
    ): ByteArray {
        val out = ByteArray(config.connectionIdLength)
        QuicLbCodec(config).encode(nonce, out)
        return out
    }

    fun decodeSid(
        config: QuicLbConfig,
        cid: ByteArray,
    ): ByteArray? = QuicLbCodec(config).decodeServerId(cid, 0)

    fun owner(
        ep: EndpointCore,
        bytes: ByteArray,
    ): Int {
        val b = PacketBuffer.of(bytes)
        try {
            return ep.ownerLoop(b, bytes.size)
        } finally {
            b.close()
        }
    }
}

/** A QUIC-LB server and a plain client, sans IO, with a step function that moves every datagram once. */
internal class LbPair(
    lb: QuicLbConfig?,
    serverSeed: Long = 5,
) {
    val clientAddr = InetSocketAddress("10.0.0.1", 4433)
    val serverAddr = InetSocketAddress("10.0.0.2", 443)
    var now = TimeMark(1_000_000_000L)
    val server = EndpointCore(QuicLbFixtures.endpointConfig(lb), Random(serverSeed))
    val client = EndpointCore(QuicEndpointConfig.Builder().apply { crypto = NullCryptoProvider }.build(), Random(6))
    private val batch = PacketBatch(16)

    fun connect(): ConnectionCore = client.connect(QuicClientConfig.Builder(CoreFixtures.client()).build(), serverAddr, now)

    private fun drain(c: ConnectionCore) {
        while (true) {
            val e = c.nextEvent() ?: break
            if (e is ConnectionEvent.VerifyRequested) c.resumeVerify(runBlocking { e.session.verifyPeer(e.chain) })
        }
    }

    private fun move(
        from: EndpointCore,
        to: EndpointCore,
        fromAddr: InetSocketAddress,
    ) {
        for (c in from.connections().toList()) {
            batch.clear()
            val n = c.poll(batch, now)
            for (i in 0 until n) feed(to, batch.buffer(i).toByteArray(batch.length(i)), fromAddr)
        }
        to.processPending(now)
    }

    fun feed(
        to: EndpointCore,
        bytes: ByteArray,
        fromAddr: InetSocketAddress = clientAddr,
    ): ConnectionCore? {
        val b = PacketBuffer.of(bytes)
        try {
            return to.handleDatagram(b, bytes.size, fromAddr, Ecn.NotEct, now)
        } finally {
            b.close()
        }
    }

    fun step() {
        now += 10.milliseconds
        for (c in client.connections().toList() + server.connections().toList()) if (c.nextTimeoutOrNever() <= now) c.onTimeout(now)
        move(client, server, clientAddr)
        for (c in server.connections()) drain(c)
        move(server, client, serverAddr)
        for (c in client.connections()) drain(c)
        for (c in server.connections()) drain(c)
    }

    fun handshake(c: ConnectionCore): Boolean {
        repeat(400) {
            step()
            if (c.state == ConnectionState.Confirmed && server.connections().any { it.state == ConnectionState.Confirmed }) return true
        }
        return false
    }

    fun stateless(): Int {
        batch.clear()
        return server.pollStateless(batch)
    }

    fun close() {
        batch.close()
        client.close()
        server.close()
    }
}
