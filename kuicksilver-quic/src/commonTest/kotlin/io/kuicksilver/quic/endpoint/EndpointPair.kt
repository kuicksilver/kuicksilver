// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
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
import io.kuicksilver.quic.PathId
import io.kuicksilver.quic.QuicClientConfig
import io.kuicksilver.quic.QuicConfig
import io.kuicksilver.quic.QuicEndpointConfig
import io.kuicksilver.quic.QuicException
import io.kuicksilver.quic.QuicServerConfig
import io.kuicksilver.quic.TimeMark
import io.kuicksilver.tls.QuicCrypto
import kotlinx.coroutines.runBlocking
import kotlin.random.Random
import kotlin.time.Duration
import kotlin.time.Duration.Companion.hours
import kotlin.time.Duration.Companion.milliseconds

/** Two endpoint cores joined in memory under virtual time (10 ms per step, one-step one-way delay); datagram hooks for tests. */
@OptIn(ExperimentalKuicksilverApi::class, DelicateKuicksilverApi::class)
internal class EndpointPair(
    crypto: QuicCrypto = NullCryptoProvider,
    serverSeed: Long = 5,
    loopIndex: Int = 0,
    serverQuic: QuicConfig = QuicConfig.Default,
    serverRandom: Random = Random(serverSeed),
    clientRandom: Random = Random(6),
    serverEarlyData: Boolean = false,
    newTokenLifetime: Duration? = 24.hours,
    sharedTokens: AddressTokens? = null,
    /** The server's `preferred_address`: datagrams to it reach the server on [io.kuicksilver.quic.PREFERRED_SOCKET], its answers come from it. */
    val serverPreferred: io.kuicksilver.quic.PreferredAddress? = null,
    /** The server's address (a public one for the tests of what a public server may point a client at). */
    val serverAddr: InetSocketAddress = InetSocketAddress("10.0.0.2", 443),
    configure: QuicEndpointConfig.Builder.() -> Unit = {},
) {
    val clientAddr: InetSocketAddress = InetSocketAddress("10.0.0.1", 40000)

    /** Datagrams to the preferred address are lost (it does not answer). */
    var dropToPreferred: Boolean = false
    var now: TimeMark = TimeMark(1_000_000_000L)
    val server: EndpointCore =
        EndpointCore(
            QuicEndpointConfig
                .Builder()
                .apply {
                    this.server =
                        QuicServerConfig
                            .Builder(CoreFixtures.server())
                            .apply {
                                quic = serverQuic
                                earlyData = serverEarlyData
                                this.newTokenLifetime = newTokenLifetime
                                preferredAddress = serverPreferred
                            }.build()
                    ; this.crypto = crypto
                    configure()
                }.build(),
            serverRandom,
            loopIndex,
            sharedTokens,
        )
    val client: EndpointCore = EndpointCore(QuicEndpointConfig.Builder().apply { this.crypto = crypto }.build(), clientRandom)
    val events: HashMap<ConnectionCore, MutableList<ConnectionEvent>> = HashMap()
    val batch: PacketBatch = PacketBatch(16)

    /** Return false to drop; index counts datagrams per direction. */
    var filterToServer: (index: Int, bytes: ByteArray) -> Boolean = { _, _ -> true }
    var filterToClient: (index: Int, bytes: ByteArray) -> Boolean = { _, _ -> true }
    var sentToServer: Int = 0
    var sentToClient: Int = 0

    /** What the network does to the ECN codepoint in each direction (identity by default; Bleach = `{ Ecn.NotEct }`). */
    var ecnToServer: (Ecn) -> Ecn = { it }
    var ecnToClient: (Ecn) -> Ecn = { it }

    /** Whether each side's socket can read ECN marks (a portable socket cannot: it delivers NotEct). */
    var serverEcnReceive: Boolean = true
    var clientEcnReceive: Boolean = true

    /** Link MTU per direction: a larger datagram is silently dropped (DPLPMTUD tests). */
    var linkMtuToServer: Int = 1500
    var linkMtuToClient: Int = 1500

    /**
     * A starved server process: while set, the server runs no timers, sends nothing and the datagrams for it wait in its socket
     * (none lost); they are handled in order on the first step after it is cleared.
     */
    var serverStalled: Boolean = false
    private val stalledToServer = ArrayList<Triple<ByteArray, InetSocketAddress, Ecn>>()

    /** Size of every datagram the client sent, in order. */
    val clientDatagramSizes: MutableList<Int> = ArrayList()

    /** The ECN codepoint the client set on every datagram it sent, in order (before the network's transform). */
    val clientEcnSent: MutableList<Ecn> = ArrayList()

    fun clientEcnSentAt(index: Int): Ecn = clientEcnSent.getOrElse(index) { Ecn.NotEct }

    /** The client's source address as the server sees it (NAT rebind tests change it). */
    var clientSource: InetSocketAddress = clientAddr

    /** Addresses the client receives on; a server datagram addressed elsewhere lands in [sentElsewhere] instead. */
    val clientListens: MutableSet<InetSocketAddress> = mutableSetOf(clientAddr)

    /** The client also receives on the address it currently sends from (a real socket does); false models a new address that only transmits. */
    var clientListensOnSource: Boolean = true

    /** Source address of the client's datagrams per socket (path id) other than the first; the server's answers to that address arrive on that socket. */
    val clientSocketSources: HashMap<PathId, InetSocketAddress> = HashMap()
    val sentElsewhere: MutableList<Pair<InetSocketAddress, ByteArray>> = ArrayList()

    /** The socket each client datagram reached the server on, in order (the preferred one for its address). */
    val toServerSockets: MutableList<PathId> = ArrayList()

    /** The source of every server datagram, in the order of [serverSent]. */
    val serverSentFrom: MutableList<InetSocketAddress> = ArrayList()

    /** Every server datagram with its destination, delivered or not. */
    val serverSent: MutableList<Pair<InetSocketAddress, ByteArray>> = ArrayList()

    /** Called once for every connection the server endpoint creates. */
    var onServerCreated: (ConnectionCore) -> Unit = {}
    private val seenServerCores = HashSet<ConnectionCore>()

    fun connect(quic: QuicConfig = QuicConfig.Default): ConnectionCore =
        client.connect(
            QuicClientConfig
                .Builder(CoreFixtures.client())
                .apply {
                    this.quic =
                        quic
                }.build(),
            serverAddr,
            now,
        )

    fun drain(c: ConnectionCore) {
        val l = events.getOrPut(c) { ArrayList() }
        while (true) {
            val e =
                c.nextEvent() ?: break
            l += e
            if (e is ConnectionEvent.VerifyRequested) c.resumeVerify(runBlocking { e.session.verifyPeer(e.chain) })
        }
    }

    private fun move(
        from: EndpointCore,
        to: EndpointCore,
        fromAddr: InetSocketAddress,
        toServer: Boolean,
    ) {
        val pending = ArrayList<Pair<InetSocketAddress, ByteArray>>()
        val sockets = ArrayList<PathId>()
        val ecns = ArrayList<Ecn>()
        for (c in from.connections().toList()) {
            batch.clear()
            val n = c.poll(batch, now)
            for (i in 0 until n) {
                pending +=
                    batch.address(i)!! to batch.buffer(i).toByteArray(batch.length(i))
                sockets += batch.path(i)
                ecns += batch.ecn(i)
            }
        }
        batch.clear()
        val n = from.pollStateless(batch)
        for (i in 0 until n) {
            pending +=
                batch.address(i)!! to batch.buffer(i).toByteArray(batch.length(i))
            sockets += PathId.Initial
            ecns += batch.ecn(i)
        }
        if (toServer) {
            clientEcnSent += ecns
            for ((_, b) in pending) clientDatagramSizes += b.size
        }
        if (toServer && !serverStalled && stalledToServer.isNotEmpty()) {
            for ((bytes, src, ecn) in stalledToServer) deliver(to, bytes, src, ecn, PathId.Initial)
            stalledToServer.clear()
        }
        for (k in pending.indices) {
            val (dest, bytes) = pending[k]
            val keep = if (toServer) filterToServer(sentToServer++, bytes) else filterToClient(sentToClient++, bytes)
            if (!keep) continue
            // the link cannot carry it (DF set: no fragmentation, no ICMP)
            if (bytes.size > (if (toServer) linkMtuToServer else linkMtuToClient)) continue
            var src = fromAddr
            var socket = PathId.Initial
            if (toServer) {
                val sk = sockets[k]
                if (sk != PathId.Initial) src = clientSocketSources[sk] ?: clientSource
                if (dest == serverPreferred?.ipv4 || dest == serverPreferred?.ipv6) {
                    if (dropToPreferred) continue
                    socket = io.kuicksilver.quic.PREFERRED_SOCKET
                }
                toServerSockets += socket
            } else {
                if (sockets[k] == io.kuicksilver.quic.PREFERRED_SOCKET) {
                    src = serverPreferred?.ipv4 ?: serverPreferred!!.ipv6!!
                }
                serverSentFrom += src
                serverSent += dest to bytes
                socket = clientSocketSources.entries.firstOrNull { it.value == dest }?.key ?: PathId.Initial
                if (socket ==
                    PathId.Initial &&
                    dest !in clientListens &&
                    !(clientListensOnSource && dest == clientSource)
                ) {
                    sentElsewhere += dest to bytes
                    continue
                }
            }
            val ecn =
                if (toServer) {
                    (
                        if (serverEcnReceive) {
                            ecnToServer(
                                ecns[k],
                            )
                        } else {
                            Ecn.NotEct
                        }
                    )
                } else {
                    (if (clientEcnReceive) ecnToClient(ecns[k]) else Ecn.NotEct)
                }
            if (toServer && serverStalled) {
                stalledToServer += Triple(bytes, src, ecn)
                continue
            }
            deliver(to, bytes, src, ecn, socket)
        }
        if (toServer && serverStalled) return
        to.processPending(now)
        if (toServer) for (c in to.connections()) if (seenServerCores.add(c)) onServerCreated(c)
    }

    private fun deliver(
        to: EndpointCore,
        bytes: ByteArray,
        src: InetSocketAddress,
        ecn: Ecn,
        socket: PathId,
    ) {
        val b = PacketBuffer.of(bytes)
        try {
            to.handleDatagram(b, bytes.size, src, ecn, now, socket)
        } finally {
            b.close()
        }
    }

    fun step() {
        now += 10.milliseconds
        val running = if (serverStalled) client.connections().toList() else client.connections().toList() + server.connections().toList()
        for (c in running) if (c.nextTimeoutOrNever() <= now) c.onTimeout(now)
        move(client, server, clientSource, toServer = true)
        for (c in server.connections()) drain(c)
        if (!serverStalled) move(server, client, serverAddr, toServer = false)
        for (c in client.connections()) drain(c)
        for (c in server.connections()) drain(c)
    }

    fun runUntil(
        limit: Duration = 10_000.milliseconds,
        done: () -> Boolean,
    ): Boolean {
        val end =
            now + limit
        while (now < end) {
            step()
            if (done()) return true
        }
        return done()
    }

    fun confirmed(c: ConnectionCore): Boolean =
        runUntil {
            c.state == ConnectionState.Confirmed &&
                server.connections().any { it.state == ConnectionState.Confirmed }
        }

    fun closed(c: ConnectionCore): QuicException.ConnectionLost? =
        events[c]?.filterIsInstance<ConnectionEvent.Closed>()?.firstOrNull()?.reason

    /** Routes one datagram carrying the ECN codepoint [ecn]. */
    fun feedEcn(
        ep: EndpointCore,
        bytes: ByteArray,
        from: InetSocketAddress,
        ecn: Ecn,
    ): ConnectionCore? {
        val b = PacketBuffer.of(bytes)
        try {
            return ep.handleDatagram(b, bytes.size, from, ecn, now)
        } finally {
            b.close()
        }
    }

    /** Routes one datagram without admitting queued Initials (what one `handleDatagram` call does). */
    fun feedNoAdmit(
        ep: EndpointCore,
        bytes: ByteArray,
        from: InetSocketAddress,
    ): ConnectionCore? {
        val b = PacketBuffer.of(bytes)
        try {
            return ep.handleDatagram(b, bytes.size, from, Ecn.NotEct, now)
        } finally {
            b.close()
        }
    }

    /** Routes one datagram and admits what it queued; returns the connection that took it, or the one it created. */
    fun feed(
        ep: EndpointCore,
        bytes: ByteArray,
        from: InetSocketAddress,
    ): ConnectionCore? {
        val before = ep.connectionCount
        feedNoAdmit(ep, bytes, from)?.let { return it }
        ep.processPending(now)
        return if (ep.connectionCount > before) ep.connections().last() else null
    }

    fun stateless(ep: EndpointCore): List<ByteArray> {
        batch.clear()
        val n = ep.pollStateless(batch)
        return List(n) { batch.buffer(it).toByteArray(batch.length(it)) }
    }

    fun close() {
        batch.close()
        client.close()
        server.close()
    }
}
