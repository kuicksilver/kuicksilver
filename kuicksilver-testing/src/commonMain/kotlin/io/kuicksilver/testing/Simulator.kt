// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.testing

import io.ktor.network.sockets.InetSocketAddress
import io.kuicksilver.annotations.DelicateKuicksilverApi
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.native.PacketBuffer
import io.kuicksilver.native.toByteArray
import io.kuicksilver.quic.ConnectionCore
import io.kuicksilver.quic.ConnectionEvent
import io.kuicksilver.quic.Ecn
import io.kuicksilver.quic.EndpointCore
import io.kuicksilver.quic.NullCryptoProvider
import io.kuicksilver.quic.PacketBatch
import io.kuicksilver.quic.QuicClientConfig
import io.kuicksilver.quic.QuicConfig
import io.kuicksilver.quic.QuicEndpointConfig
import io.kuicksilver.quic.QuicException
import io.kuicksilver.quic.QuicServerConfig
import io.kuicksilver.quic.TimeMark
import io.kuicksilver.tls.QuicCrypto
import io.kuicksilver.tls.TlsConfig
import kotlinx.coroutines.runBlocking
import kotlin.random.Random
import kotlin.time.Duration
import kotlin.time.Duration.Companion.milliseconds

/** Outcome of a simulator run. */
public class SimResult(
    public val finished: Boolean,
    public val elapsed: Duration,
    public val traceHash: Long,
    public val violations: List<String>,
)

/** The two cores of a simulated connection and what the scenario observed about them. */
@OptIn(ExperimentalKuicksilverApi::class)
public class SimConnection internal constructor(
    public val client: ConnectionCore,
) {
    public var server: ConnectionCore? = null
        internal set
    public val clientEvents: MutableList<ConnectionEvent> = ArrayList()
    public val serverEvents: MutableList<ConnectionEvent> = ArrayList()
    public var maxPtoCount: Int = 0
        internal set
    public val handshakeDone: Boolean get() =
        clientEvents.any { it is ConnectionEvent.HandshakeCompleted } &&
            serverEvents.any { it is ConnectionEvent.HandshakeCompleted }

    public fun closed(): QuicException.ConnectionLost? =
        (clientEvents + serverEvents).filterIsInstance<ConnectionEvent.Closed>().firstOrNull()?.reason
}

/**
 * A deterministic network between two cores under virtual time: every random choice comes from [seed],
 * so a run reproduces byte for byte with [NullCryptoProvider] (OpenSSL draws its own randomness for key shares).
 */
@OptIn(ExperimentalKuicksilverApi::class, DelicateKuicksilverApi::class, io.kuicksilver.annotations.InternalKuicksilverApi::class)
public class Simulator(
    public val seed: Long,
    clientToServer: LinkParams,
    serverToClient: LinkParams = clientToServer,
    private val crypto: QuicCrypto = NullCryptoProvider,
    private val pathCapabilities: io.kuicksilver.quic.IoCapabilities = io.kuicksilver.quic.IoCapabilities.Portable,
) {
    public var now: TimeMark = TimeMark(1_000_000_000L)
        private set
    private val random = Random(seed)
    private val c2s = SimLink(clientToServer, Random(seed * 31 + 1), "c2s")
    private val s2c = SimLink(serverToClient, Random(seed * 31 + 2), "s2c")

    /** The client's current source address as the server sees it; [rebindClient] changes it (NAT rebind). */
    public var clientAddress: InetSocketAddress = InetSocketAddress("10.0.0.1", 40000)
        internal set
    private val serverAddr = InetSocketAddress("10.0.0.2", 443)

    /** Extra client paths (migration tests drive them): each has its own local address and link pair; index 0 is the first path. */
    private class ClientPath(
        val local: InetSocketAddress,
        val c2s: SimLink,
        val s2c: SimLink,
    )

    private val extraPaths = ArrayList<ClientPath>()

    /** Test hook: the source address of the last client datagram the server endpoint received. */
    public var lastClientSourceSeenByServer: InetSocketAddress? = null
        private set
    private val batch = PacketBatch(32)
    private var conn: SimConnection? = null
    private val clientEndpoint =
        EndpointCore(
            QuicEndpointConfig.Builder().apply { this.crypto = this@Simulator.crypto }.build(),
            Random(seed + 3),
        )
    private var serverEndpoint: EndpointCore? = null
    private val invariants = SimInvariants()
    private var traceHash = 1469598103934665603L
    private val start = now

    /** Scenario hook: drop the next client datagram (tail-loss tests). */
    public var dropNextClientToServer: Boolean
        get() = c2s.dropNext
        set(v) {
            c2s.dropNext = v
        }

    /** Scenario hook: a value that must keep changing while the link is alive (bytes delivered to the application). */
    public var progress: Long = 0

    /** Changes the MTU of either direction mid-run (null — unlimited): datagrams already on the wire still arrive. */
    public fun setMtu(
        clientToServer: Int?,
        serverToClient: Int?,
    ) {
        c2s.mtu = clientToServer
        s2c.mtu = serverToClient
    }

    /** NAT rebind: from now on the server sees the client's datagrams from a new port and/or host. */
    public fun rebindClient(
        port: Int? = null,
        host: String? = null,
    ) {
        clientAddress =
            InetSocketAddress(host ?: clientAddress.hostname, port ?: clientAddress.port)
    }

    /** Adds a client path with its own local address and link impairments; returns its index (the first path is 0). Traffic moves there only when the core switches paths. */
    public fun addClientPath(
        local: InetSocketAddress,
        params: LinkParams,
    ): Int {
        val k = extraPaths.size + 1
        extraPaths +=
            ClientPath(
                local,
                SimLink(params, Random(seed * 31 + 100 + 2 * k), "c2s#$k"),
                SimLink(params, Random(seed * 31 + 101 + 2 * k), "s2c#$k"),
            )
        return k
    }

    /** Datagrams delivered on path [index] so far (both directions). */
    public fun pathDelivered(index: Int): Long =
        if (index ==
            0
        ) {
            c2s.delivered + s2c.delivered
        } else {
            extraPaths[index - 1].let { it.c2s.delivered + it.s2c.delivered }
        }

    public fun connect(
        client: QuicConfig = QuicConfig.Default,
        server: QuicConfig = QuicConfig.Default,
        tlsClient: TlsConfig,
        tlsServer: TlsConfig,
    ): SimConnection {
        serverEndpoint =
            EndpointCore(
                QuicEndpointConfig
                    .Builder()
                    .apply {
                        this.server =
                            QuicServerConfig.Builder(tlsServer).apply { quic = server }.build()
                        ; this.crypto = this@Simulator.crypto
                    }.build(),
                Random(seed + 5),
            )
        val c = SimConnection(clientEndpoint.connect(QuicClientConfig.Builder(tlsClient).apply { quic = client }.build(), serverAddr, now))
        c.client.setPathCapabilities(io.kuicksilver.quic.PathId.Initial, pathCapabilities)
        conn =
            c
        return c
    }

    private fun hash(
        b: ByteArray,
        dir: Int,
        ecn: Ecn,
        from: InetSocketAddress,
    ) {
        var h = traceHash
        h =
            (h xor dir.toLong()) * 1099511628211L
        h = (h xor b.size.toLong()) * 1099511628211L
        h = (h xor now.nanos) * 1099511628211L
        h =
            (h xor ecn.ordinal.toLong()) * 1099511628211L
        h = (h xor from.port.toLong()) * 1099511628211L
        traceHash = h
    }

    private fun poll(
        core: ConnectionCore,
        link: SimLink,
    ) {
        batch.clear()
        val n = core.poll(batch, now)
        for (i in 0 until n) {
            val bytes = batch.buffer(i).toByteArray(batch.length(i))
            link.send(bytes, batch.ecn(i), now)
        }
    }

    private fun deliver(
        ep: EndpointCore,
        link: SimLink,
        from: InetSocketAddress,
        dir: Int,
    ): ConnectionCore? {
        var last: ConnectionCore? = null
        for (d in link.due(now)) {
            hash(d.bytes, dir, d.ecn, from)
            if (dir ==
                1
            ) {
                lastClientSourceSeenByServer = from
            }
            val b = PacketBuffer.allocate(d.bytes.size)
            try {
                b.copyFrom(d.bytes, 0, 0, d.bytes.size)
                ep.handleDatagram(b, d.bytes.size, from, d.ecn, now)?.let {
                    last =
                        it
                }
            } finally {
                b.close()
            }
        }
        val before = ep.connectionCount
        if (ep.processPending(now) > 0 &&
            last == null
        ) {
            last = ep.connections().last().takeIf { ep.connectionCount > before }
        }
        return last
    }

    private fun pollEndpoint(
        ep: EndpointCore,
        link: SimLink,
    ) {
        for (core in ep.connections()) poll(core, link)
        batch.clear()
        val n = ep.pollStateless(batch)
        for (i in 0 until
            n) {
            link.send(batch.buffer(i).toByteArray(batch.length(i)), batch.ecn(i), now)
        }
    }

    /** Server datagrams travel on the link of the client address they are sent to; one addressed to a port the client no longer has (after a rebind) is lost, as in the real network. */
    private fun pollServer(ep: EndpointCore) {
        for (core in ep.connections()) {
            batch.clear()
            val n = core.poll(batch, now)
            for (i in 0 until n) routeToClient(batch.buffer(i).toByteArray(batch.length(i)), batch.ecn(i), batch.address(i)!!)
        }
        batch.clear()
        val n = ep.pollStateless(batch)
        for (i in 0 until n) routeToClient(batch.buffer(i).toByteArray(batch.length(i)), batch.ecn(i), batch.address(i)!!)
    }

    private fun routeToClient(
        bytes: ByteArray,
        ecn: Ecn,
        to: InetSocketAddress,
    ) {
        if (to == clientAddress) {
            s2c.send(bytes, ecn, now)
            return
        }
        for (p in extraPaths) {
            if (p.local == to) {
                p.s2c.send(bytes, ecn, now)
                return
            }
        }
        misrouted++
    }

    /** Server datagrams addressed to no current client address (dropped). */
    public var misrouted: Long = 0
        private set

    private fun drain(
        core: ConnectionCore,
        into: MutableList<ConnectionEvent>,
    ) {
        while (true) {
            val e =
                core.nextEvent() ?: break
            into += e
            if (e is ConnectionEvent.VerifyRequested) core.resumeVerify(runBlocking { e.session.verifyPeer(e.chain) })
        }
    }

    /** One virtual step: fire due timers, deliver due datagrams, poll both cores, check invariants. */
    private fun step() {
        val c = conn ?: return
        c.client.nextTimeout()?.let { if (it <= now) c.client.onTimeout(now) }
        c.server?.nextTimeout()?.let { if (it <= now) c.server!!.onTimeout(now) }
        val sep = serverEndpoint!!
        deliver(sep, c2s, clientAddress, 1)?.let {
            if (c.server ==
                null
            ) {
                c.server = it
                it.setPathCapabilities(io.kuicksilver.quic.PathId.Initial, pathCapabilities)
            }
        }
        for (p in extraPaths) deliver(sep, p.c2s, p.local, 1)?.let { if (c.server == null) c.server = it }
        c.server?.let { drain(it, c.serverEvents) }
        deliver(clientEndpoint, s2c, serverAddr, 2)
        for (p in extraPaths) deliver(clientEndpoint, p.s2c, serverAddr, 2)
        drain(c.client, c.clientEvents)
        pollEndpoint(clientEndpoint, c2s)
        pollServer(sep)
        c.server?.let { drain(it, c.serverEvents) }
        drain(c.client, c.clientEvents)
        c.maxPtoCount = maxOf(c.maxPtoCount, c.client.stats.ptoCount, c.server?.stats?.ptoCount ?: 0)
        val alive = c.closed() == null
        invariants.check(c.client, now, progress, alive, c.handshakeDone)
        c.server?.let { invariants.check(it, now, progress, alive, c.handshakeDone) }
    }

    /** Runs until [done] or until [limit] of virtual time passed; time jumps to the next timer or arrival. */
    public fun runUntil(
        limit: Duration,
        done: () -> Boolean,
    ): SimResult {
        val end = now + limit
        while (now < end) {
            step()
            if (done()) return SimResult(true, now - start, traceHash, invariants.violations.toList())
            val c = conn!!
            var next: TimeMark? = null

            fun consider(t: TimeMark?) {
                if (t != null && t > now && (next == null || t < next!!)) next = t
            }
            consider(c.client.nextTimeout())
            consider(c.server?.nextTimeout())
            consider(c2s.nextArrival())
            consider(s2c.nextArrival())
            for (p in extraPaths) {
                consider(p.c2s.nextArrival())
                consider(p.s2c.nextArrival())
            }
            val n = next
            // idle gaps advance in bounded steps so scenarios can inject work
            now = if (n == null || n > now + 50.milliseconds) now + 50.milliseconds else n
            if (c.closed() != null && c2s.pending == 0 && s2c.pending == 0 &&
                !done()
            ) {
                return SimResult(false, now - start, traceHash, invariants.violations + listOf("connection closed: ${c.closed()}"))
            }
        }
        step()
        return SimResult(done(), now - start, traceHash, invariants.violations.toList())
    }
}
