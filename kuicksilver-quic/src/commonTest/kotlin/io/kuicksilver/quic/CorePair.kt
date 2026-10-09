// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic

import io.kotest.property.Arb
import io.ktor.network.sockets.InetSocketAddress
import io.kuicksilver.annotations.DelicateKuicksilverApi
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.native.PacketBuffer
import io.kuicksilver.native.of
import io.kuicksilver.native.toByteArray
import io.kuicksilver.quic.VersionProfile
import io.kuicksilver.tls.Certificate
import io.kuicksilver.tls.KslQuicCrypto
import io.kuicksilver.tls.QuicCrypto
import io.kuicksilver.tls.TlsConfig
import io.kuicksilver.tls.TlsIdentity
import io.kuicksilver.tls.TlsRole
import io.kuicksilver.tls.TrustConfig
import io.kuicksilver.tls.tlsConfig
import kotlinx.coroutines.runBlocking
import kotlin.random.Random
import kotlin.time.Duration
import kotlin.time.Duration.Companion.milliseconds

/** TLS configurations for the core tests. */
@OptIn(DelicateKuicksilverApi::class)
internal object CoreFixtures {
    val testCa = Certificate(TestCerts.testCa)
    val accept =
        TrustConfig.Custom { chain, _, _ ->
            io.kuicksilver.tls.VerifyResult
                .Accepted(chain)
        }

    fun client(
        alpn: String = "hq-interop",
        trust: TrustConfig = TrustConfig.AnchoredCa(listOf(testCa)),
        name: String? = "server.test",
        block: TlsConfig.Builder.() -> Unit = {
        },
    ): TlsConfig =
        tlsConfig(TlsRole.Client) {
            this.alpn = listOf(alpn)
            serverName = name
            this.trust = trust
            block()
        }

    fun server(
        alpn: String = "hq-interop",
        chain: List<ByteArray> = listOf(TestCerts.server),
        key: ByteArray = TestCerts.serverKey,
        block: TlsConfig.Builder.() -> Unit = {
        },
    ): TlsConfig =
        tlsConfig(TlsRole.Server) {
            this.alpn = listOf(alpn)
            identity = TlsIdentity.fromDer(chain, key.copyOf())
            block()
        }

    val clientAddr = InetSocketAddress("10.0.0.1", 40000)
    val serverAddr = InetSocketAddress("10.0.0.2", 443)
}

/** A datagram in flight between the two cores. */
internal class Dgram(
    val bytes: ByteArray,
    val from: InetSocketAddress,
)

/**
 * Two cores joined by in-memory queues under virtual time. The server core is created from the client's first
 * Initial (as EndpointCore does). Datagram hooks let tests drop, delay or inspect traffic.
 */
@OptIn(ExperimentalKuicksilverApi::class, DelicateKuicksilverApi::class)
internal class CorePair(
    clientTls: TlsConfig = CoreFixtures.client(),
    private val serverTls: TlsConfig = CoreFixtures.server(),
    clientQuic: QuicConfig = QuicConfig.Default,
    private val serverQuic: QuicConfig = QuicConfig.Default,
    private val crypto: QuicCrypto = NullCryptoProvider,
    seed: Long = 1,
) {
    var now: TimeMark = TimeMark(1_000_000_000L)
    val random = Random(seed)
    val client: ConnectionCore = ConnectionCore.client(clientQuic, clientTls, crypto, CoreFixtures.serverAddr, Random(seed + 1), now)
    var server: ConnectionCore? = null
        private set
    val toServer = ArrayDeque<Dgram>()
    val toClient = ArrayDeque<Dgram>()
    val clientEvents = ArrayList<ConnectionEvent>()
    val serverEvents = ArrayList<ConnectionEvent>()

    /** Return false to drop a datagram; index counts datagrams per direction. */
    var filterToServer: (index: Int, bytes: ByteArray) -> Boolean = { _, _ -> true }
    var filterToClient: (index: Int, bytes: ByteArray) -> Boolean = { _, _ -> true }
    var sentToServer = 0
    var sentToClient = 0

    /** The most recent client datagram starting with an Initial packet. */
    var lastClientInitial: ByteArray? = null
    val batch = PacketBatch(16)
    var autoVerify = true
    var onServerCreated: (ConnectionCore) -> Unit = {}

    fun poll(
        core: ConnectionCore,
        queue: ArrayDeque<Dgram>,
        from: InetSocketAddress,
        toServer: Boolean,
    ) {
        batch.clear()
        val n = core.poll(batch, now)
        for (i in 0 until n) {
            val bytes = batch.buffer(i).toByteArray(batch.length(i))
            if (toServer && bytes[0].toInt() and 0xf0 == 0xc0) lastClientInitial = bytes
            val keep = if (toServer) filterToServer(sentToServer++, bytes) else filterToClient(sentToClient++, bytes)
            if (keep) queue += Dgram(bytes, from)
        }
    }

    fun deliver(
        core: ConnectionCore,
        queue: ArrayDeque<Dgram>,
    ) {
        while (true) {
            val d =
                queue.removeFirstOrNull() ?: break
            val b = PacketBuffer.of(d.bytes)
            try {
                core.handleDatagram(b, d.bytes.size, d.from, Ecn.NotEct, now)
            } finally {
                b.close()
            }
        }
    }

    fun drainEvents(
        core: ConnectionCore,
        into: MutableList<ConnectionEvent>,
    ) {
        while (true) {
            val e =
                core.nextEvent() ?: break
            into += e
            if (e is ConnectionEvent.VerifyRequested &&
                autoVerify
            ) {
                core.resumeVerify(runBlocking { e.session.verifyPeer(e.chain) })
            }
        }
    }

    private fun serverFromFirstInitial() {
        val d = toServer.firstOrNull() ?: return
        val b = PacketBuffer.of(d.bytes)
        try {
            server = ConnectionCore.server(serverQuic, serverTls, crypto, d.from, Random(99), now, b, d.bytes.size)
        } finally {
            b.close()
        }
        // an Initial the server cannot accept (version) is dropped, as an endpoint would
        if (server == null) toServer.removeFirst() else onServerCreated(server!!)
    }

    /**
     * One round: timers fire when due, datagrams queued by the previous round are delivered (one tick of one-way delay,
     * so the RTT is two ticks), then both cores are polled into the queues for the next round.
     */
    fun step() {
        client.nextTimeout()?.let { if (it <= now) client.onTimeout(now) }
        server?.nextTimeout()?.let { if (it <= now) server!!.onTimeout(now) }
        server?.let {
            deliver(it, toServer)
            drainEvents(it, serverEvents)
        }
        deliver(client, toClient)
        drainEvents(client, clientEvents)
        poll(client, toServer, CoreFixtures.clientAddr, toServer = true)
        if (server == null) serverFromFirstInitial()
        server?.let {
            poll(it, toClient, CoreFixtures.serverAddr, toServer = false)
            drainEvents(it, serverEvents)
        }
        drainEvents(client, clientEvents)
    }

    fun advance(d: Duration) {
        now += d
    }

    /** Steps with time passing until [done] or [limit] of virtual time elapsed. */
    fun runUntil(
        limit: Duration = 15_000.milliseconds,
        tick: Duration = 5.milliseconds,
        done: () -> Boolean,
    ): Boolean {
        val end = now + limit
        while (now < end) {
            step()
            if (done()) return true
            advance(tick)
        }
        step()
        return done()
    }

    fun handshake(): Boolean =
        runUntil {
            clientEvents.any { it is ConnectionEvent.HandshakeCompleted } &&
                serverEvents.any { it is ConnectionEvent.HandshakeCompleted }
        }

    fun closedReason(events: List<ConnectionEvent>): QuicException.ConnectionLost? =
        events.filterIsInstance<ConnectionEvent.Closed>().firstOrNull()?.reason

    fun close() {
        batch.close()
    }
}

internal val ksl: QuicCrypto get() = KslQuicCrypto
