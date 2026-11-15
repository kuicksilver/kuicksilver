// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.fuzz

import io.ktor.network.sockets.InetSocketAddress
import io.kuicksilver.annotations.DelicateKuicksilverApi
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.native.PacketBuffer
import io.kuicksilver.native.of
import io.kuicksilver.native.toByteArray
import io.kuicksilver.quic.ConnectionAdmission
import io.kuicksilver.quic.ConnectionCore
import io.kuicksilver.quic.ConnectionEvent
import io.kuicksilver.quic.ConnectionState
import io.kuicksilver.quic.CoreFixtures
import io.kuicksilver.quic.Ecn
import io.kuicksilver.quic.EndpointCore
import io.kuicksilver.quic.IoCapabilities
import io.kuicksilver.quic.KuicksilverLogger
import io.kuicksilver.quic.PREFERRED_SOCKET
import io.kuicksilver.quic.PacketBatch
import io.kuicksilver.quic.PathId
import io.kuicksilver.quic.PreferredAddress
import io.kuicksilver.quic.QuicClientConfig
import io.kuicksilver.quic.QuicConfig
import io.kuicksilver.quic.QuicEndpointConfig
import io.kuicksilver.quic.QuicServerConfig
import io.kuicksilver.quic.TimeMark
import io.kuicksilver.quic.core.preferredSocketDown
import io.kuicksilver.quic.core.release
import io.kuicksilver.tls.QuicCrypto
import kotlinx.coroutines.runBlocking
import kotlin.random.Random
import kotlin.time.Duration
import kotlin.time.Duration.Companion.milliseconds

/** A datagram in flight: [from] and [to] as the network carries it, the ECN codepoint it has now. */
internal class Flight(
    val bytes: ByteArray,
    val from: InetSocketAddress,
    val to: InetSocketAddress,
    val ecn: Ecn = Ecn.NotEct,
)

/** What the network does to the ECN field of a direction (RFC 9000 section 13.4.2: faulty elements bleach, remark or drop). */
internal enum class EcnPath {
    Keep,

    /** Every codepoint cleared to Not-ECT (a bleaching element). */
    Bleach,

    /** Every ECT-marked datagram arrives CE (congestion). */
    MarkCe,

    /** ECT(0) remarked to ECT(1). */
    Remark,

    /** ECT-marked datagrams are dropped (an ECN black hole). */
    DropMarked,
}

/**
 * A client and a server [EndpointCore] joined by in-memory queues under virtual time, for the stateful connection fuzzer: both
 * cores are reached through their endpoints, as in the runtime, so Retry, Version Negotiation, Stateless Reset, routing by
 * connection ID, ICMP Packet Too Big and the server's preferred address work as they do there. The server listens on [SERVER]
 * and, with [preferred], on [PREFERRED] (its [PREFERRED_SOCKET]); the client sends from [CLIENT] and from one address per extra
 * socket ([addClientSocket]). Each direction has a link MTU (larger datagrams vanish, or draw a Packet Too Big where [icmp] is
 * on), an [EcnPath], and the sockets' capabilities ([IoCapabilities]) decide whether marks go out and are read.
 *
 * A round ([step]) is CorePair's: due timers fire, the datagrams queued by the last round are delivered (each endpoint's
 * stateless answers to one datagram are collected right after it, so [observer] sees which datagram drew them), events are
 * drained, and every connection is polled into the queues of the next round. Closed connections leave their endpoint, as the
 * runtime removes them.
 */
@OptIn(ExperimentalKuicksilverApi::class, DelicateKuicksilverApi::class)
internal class EndpointNet(
    clientQuic: QuicConfig,
    serverQuic: QuicConfig,
    crypto: QuicCrypto,
    retry: Boolean,
    preferred: Boolean,
    /** What the client's and the server's sockets can do (ECN marking, DF). */
    val caps: Array<IoCapabilities>,
    /** Whether the client's and the server's sockets read the ECN field of what they receive. */
    val ecnRead: BooleanArray,
    val observer: Observer,
) {
    /** Hooks for the invariants: every datagram sent, delivered, dropped by the link, every stateless answer. */
    interface Observer {
        /** [side] (0 client, 1 server) sent [f] on its socket [socket] from connection [c]. */
        fun sent(
            side: Int,
            c: ConnectionCore,
            f: Flight,
            socket: PathId,
        )

        /** [f] is handed to [side]'s endpoint now. */
        fun delivered(
            side: Int,
            f: Flight,
        )

        /** [side]'s endpoint has handled [f] (its stateless answers, if any, follow). */
        fun handled(
            side: Int,
            f: Flight,
        )

        /** [side]'s endpoint answered [trigger] statelessly with [answer] (a Retry, a Version Negotiation, a reset or a close). */
        fun stateless(
            side: Int,
            trigger: Flight,
            answer: ByteArray,
        )
    }

    var now: TimeMark = TimeMark(1_000_000_000L)
        private set
    private val batch = PacketBatch(16)
    val preferredAddress: PreferredAddress? = if (preferred) PreferredAddress(PREFERRED, null) else null

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
                                preferredAddress = this@EndpointNet.preferredAddress
                            }.build()
                    this.crypto = crypto
                    logger = KuicksilverLogger.None
                    if (retry) admission = ConnectionAdmission.AlwaysRetry
                }.build(),
            Random(5),
        )
    val clientEp: EndpointCore =
        EndpointCore(
            QuicEndpointConfig
                .Builder()
                .apply {
                    this.crypto = crypto
                    logger = KuicksilverLogger.None
                }.build(),
            Random(6),
        )
    val client: ConnectionCore =
        clientEp.connect(QuicClientConfig.Builder(CoreFixtures.client()).apply { quic = clientQuic }.build(), SERVER, now).also {
            it.setPathCapabilities(PathId.Initial, caps[0])
        }

    /** The server's connection the program drives: the latest one its endpoint created. */
    var serverCore: ConnectionCore? = null
        private set
    private val serverCores = ArrayList<ConnectionCore>()
    var onServerCreated: (ConnectionCore) -> Unit = {}

    val toServer = ArrayDeque<Flight>()
    val toClient = ArrayDeque<Flight>()
    val clientEvents = ArrayList<ConnectionEvent>()
    val serverEvents = ArrayList<ConnectionEvent>()

    /** Return false to drop a datagram of a direction (the BLOCK operation). */
    var filterToServer: (Flight) -> Boolean = { true }
    var filterToClient: (Flight) -> Boolean = { true }

    /** Link MTU in UDP payload bytes per direction (0: client to server, 1: server to client). */
    val linkMtu = intArrayOf(DEFAULT_MTU, DEFAULT_MTU)

    /** The router of a direction answers a datagram above [linkMtu] with an ICMP Packet Too Big. */
    val icmp = BooleanArray(2)
    val ecnPath = arrayOf(EcnPath.Keep, EcnPath.Keep)

    /** Datagrams to the server's preferred address are lost. */
    var preferredUnreachable = false

    /** The server endpoint forgot its connection (a crash): the client's packets draw Stateless Resets now. */
    var serverLostState = false
        private set

    /** The client's sockets by the address they send from: Initial is [CLIENT]; NAT aliases of the Initial socket map to it too. */
    private val clientSockets = HashMap<InetSocketAddress, PathId>().also { it[CLIENT] = PathId.Initial }
    private val clientSocketAddr = HashMap<PathId, InetSocketAddress>().also { it[PathId.Initial] = CLIENT }

    /** Datagrams addressed to nobody (a client address no socket listens on, a server address the server does not have). */
    var lost = 0
        private set

    /** The latest datagram each side sent, for forged copies (a stranger's, a Packet Too Big quote). */
    val lastSent = arrayOfNulls<Flight>(2)

    /** The latest Retry and Version Negotiation the server's endpoint sent. */
    var lastRetry: ByteArray? = null
        private set
    var lastVn: ByteArray? = null
        private set

    fun core(side: Int): ConnectionCore? = if (side == 0) client else serverCore

    /** What the server's preferred-address socket can do: the main socket's at the start, narrowed by the program. */
    var preferredCaps: IoCapabilities = caps[1]

    /**
     * What the client's extra sockets ([addClientSocket]) can do: what its first socket could when each was opened. A program that
     * narrows the first socket's capabilities ([caps]) leaves them as they are, as the runtime follows each socket on its own.
     */
    private val clientSocketCaps = LinkedHashMap<PathId, IoCapabilities>()

    /** What [side]'s socket [socket] can do. */
    fun capsOf(
        side: Int,
        socket: PathId,
    ): IoCapabilities =
        when {
            side == 1 && socket == PREFERRED_SOCKET -> preferredCaps
            side == 0 -> clientSocketCaps[socket] ?: caps[0]
            else -> caps[side]
        }

    fun endpoint(side: Int): EndpointCore = if (side == 0) clientEp else server

    fun advance(d: Duration) {
        now += d
    }

    /** The socket [side] sent [f] on, from its source address. */
    fun socketOf(
        side: Int,
        f: Flight,
    ): PathId =
        if (side == 0) {
            clientSockets[f.from] ?: PathId.Initial
        } else if (f.from == PREFERRED) {
            PREFERRED_SOCKET
        } else {
            PathId.Initial
        }

    /** The address the client's socket [socket] sends from. */
    fun clientAddress(socket: PathId): InetSocketAddress = clientSocketAddr[socket] ?: CLIENT

    /** A new client socket with its own address, for a migration (`ConnectionCore.addPath`); its capabilities are the client's. */
    fun addClientSocket(socket: PathId) {
        val a = InetSocketAddress("10.0.1.${socket.value % 200 + 1}", 41000 + socket.value)
        clientSockets[a] = socket
        clientSocketAddr[socket] = a
        newestClientSocketAddress = a
        clientSocketCaps[socket] = caps[0]
    }

    /** The client's sockets: the first, then the migration sockets in the order they were opened. */
    fun clientSocketIds(): List<PathId> = listOf(PathId.Initial) + clientSocketCaps.keys

    /** The client's socket [socket] can do only [c] from now on. */
    fun setClientSocketCaps(
        socket: PathId,
        c: IoCapabilities,
    ) {
        if (socket == PathId.Initial) caps[0] = c else clientSocketCaps[socket] = c
    }

    /** The address of the client's latest extra socket ([addClientSocket]), if any. */
    var newestClientSocketAddress: InetSocketAddress? = null
        private set

    /** Client addresses the server's datagrams to are lost (a path that broke for one direction to one address). */
    val droppedClientAddresses = HashSet<InetSocketAddress>()

    /** NAT rebinding: datagrams to [alias] reach the client's first socket. */
    fun aliasClient(alias: InetSocketAddress) {
        if (alias !in clientSockets) clientSockets[alias] = PathId.Initial
    }

    /** The server endpoint forgets its connection without a word (a crash with the endpoint's keys kept, RFC 9000 section 10.3). */
    fun loseServerState() {
        val s = serverCore ?: return
        if (serverLostState) return
        serverLostState = true
        server.remove(s)
    }

    /** The preferred-address socket goes down (the endpoint runtime's `dropPreferred`). */
    fun preferredDown() {
        for (c in server.connections().toList()) c.preferredSocketDown()
        preferredUnreachable = true
    }

    /** Hands [f] to [side]'s endpoint on the socket its destination names (dropped when none listens there). */
    fun deliver(
        side: Int,
        f: Flight,
    ) {
        val socket: PathId
        if (side == 1) {
            socket =
                when (f.to) {
                    SERVER -> {
                        PathId.Initial
                    }

                    PREFERRED -> {
                        if (preferredAddress == null || preferredUnreachable) {
                            lost++
                            return
                        }
                        PREFERRED_SOCKET
                    }

                    else -> {
                        lost++
                        return
                    }
                }
        } else {
            socket =
                clientSockets[f.to] ?: run {
                    lost++
                    return
                }
        }
        val ecn = if (ecnRead[side]) f.ecn else Ecn.NotEct
        val g = if (ecn == f.ecn) f else Flight(f.bytes, f.from, f.to, ecn)
        observer.delivered(side, g)
        val ep = endpoint(side)
        val b = PacketBuffer.of(g.bytes)
        try {
            ep.handleDatagram(b, g.bytes.size, g.from, g.ecn, now, socket, null)
        } finally {
            b.close()
        }
        observer.handled(side, g)
        // stateless answers go back to the datagram's source, from the address it was sent to
        batch.clear()
        val n = ep.pollStateless(batch)
        for (i in 0 until n) {
            val answer = batch.buffer(i).toByteArray(batch.length(i))
            observer.stateless(side, g, answer)
            if (side == 1) {
                val first = answer[0].toInt() and 0xff
                if (first and 0x80 != 0 && answer.size >= 5 && answer[1].toInt() == 0 && answer[2].toInt() == 0 && answer[3].toInt() == 0 &&
                    answer[4].toInt() == 0
                ) {
                    lastVn = answer
                } else if (first and 0x80 != 0 && isRetry(answer)) {
                    lastRetry = answer
                }
            }
            val q = if (side == 1) toClient else toServer
            if (q.size < QUEUE_CAP) q += Flight(answer, g.to, g.from)
        }
    }

    private fun isRetry(b: ByteArray): Boolean {
        val version = Datagrams.version(b)
        val type = (b[0].toInt() ushr 4) and 3
        return (version == 1 && type == 3) || (version == VERSION_2 && type == 0)
    }

    private fun drain(
        c: ConnectionCore,
        into: MutableList<ConnectionEvent>,
    ) {
        while (true) {
            val e = c.nextEvent() ?: break
            into += e
            if (e is ConnectionEvent.VerifyRequested) c.resumeVerify(runBlocking { e.session.verifyPeer(e.chain) })
        }
    }

    /** Polls [c] of [side] into the queue towards the other side through the link (MTU, ICMP, ECN path, the filter). */
    private fun poll(
        side: Int,
        c: ConnectionCore,
    ) {
        batch.clear()
        val n = c.poll(batch, now)
        for (i in 0 until n) {
            val bytes = batch.buffer(i).toByteArray(batch.length(i))
            val socket = batch.path(i)
            val to = batch.address(i) ?: continue
            val from =
                if (side == 0) {
                    clientAddress(socket)
                } else if (socket == PREFERRED_SOCKET) {
                    PREFERRED
                } else {
                    SERVER
                }
            val f = Flight(bytes, from, to, batch.ecn(i))
            observer.sent(side, c, f, socket)
            lastSent[side] = f
            send(side, f, socket)
        }
    }

    /** The network between the sockets: [side]'s datagram [f] towards the other side. */
    private fun send(
        side: Int,
        f: Flight,
        socket: PathId,
    ) {
        if (!(if (side == 0) filterToServer(f) else filterToClient(f))) return
        if (side == 1 && f.to in droppedClientAddresses) return
        if (f.bytes.size > linkMtu[side]) {
            // DF set (or a router that drops): no fragmentation; where the router reports it, a Packet Too Big with the link MTU of
            // the IP packet (IPv4 + UDP headers: 28 bytes) quoting the start of the datagram goes back to the sender's socket
            if (icmp[side]) packetTooBig(side, f, linkMtu[side] + 28, socket)
            return
        }
        val ecn =
            when (ecnPath[side]) {
                EcnPath.Keep -> {
                    f.ecn
                }

                EcnPath.Bleach -> {
                    Ecn.NotEct
                }

                EcnPath.MarkCe -> {
                    if (f.ecn == Ecn.NotEct) Ecn.NotEct else Ecn.Ce
                }

                EcnPath.Remark -> {
                    if (f.ecn == Ecn.Ect0) Ecn.Ect1 else f.ecn
                }

                EcnPath.DropMarked -> {
                    if (f.ecn != Ecn.NotEct) return
                    f.ecn
                }
            }
        val q = if (side == 0) toServer else toClient
        if (q.size < QUEUE_CAP) q += if (ecn == f.ecn) f else Flight(f.bytes, f.from, f.to, ecn)
    }

    /** An ICMP Packet Too Big about [f] (sent by [side] on [socket]) reporting an IP MTU of [mtu], as the socket's error queue hands it over. */
    fun packetTooBig(
        side: Int,
        f: Flight,
        mtu: Int,
        socket: PathId,
        quoteLength: Int = minOf(f.bytes.size, ICMP_QUOTE),
    ) {
        val len = quoteLength.coerceIn(0, f.bytes.size)
        endpoint(side).handlePacketTooBig(f.bytes.copyOf(len), len, f.to, mtu, now, socket)
    }

    /**
     * One round: due timers, then the datagrams of the last round delivered (server first), events drained, every connection
     * polled; closed connections leave their endpoint.
     */
    fun step() {
        for (ep in arrayOf(clientEp, server)) {
            for (c in ep.connections().toList()) if (c.nextTimeoutOrNever() <= now) c.onTimeout(now)
        }
        val forServer = ArrayList(toServer)
        toServer.clear()
        for (f in forServer) deliver(1, f)
        server.processPending(now)
        while (server.nextAccepted() != null) { /* the application accepts every connection */ }
        for (c in server.connections()) {
            if (c !in serverCores) {
                serverCores += c
                c.setPathCapabilities(PathId.Initial, caps[1])
                if (preferredAddress != null) c.setSocketCapabilities(PREFERRED_SOCKET, preferredCaps)
                serverCore = c
                onServerCreated(c)
            }
        }
        serverCore?.let { if (!serverLostState) drain(it, serverEvents) }
        val forClient = ArrayList(toClient)
        toClient.clear()
        for (f in forClient) deliver(0, f)
        drain(client, clientEvents)
        if (client in clientEp.connections()) poll(0, client)
        for (c in server.connections().toList()) poll(1, c)
        serverCore?.let { if (!serverLostState) drain(it, serverEvents) }
        drain(client, clientEvents)
        for (ep in arrayOf(clientEp, server)) {
            for (c in ep.connections().toList()) if (c.state == ConnectionState.Closed) ep.remove(c)
        }
    }

    /** Rounds with [tick] of time between them until [done] or [limit] of virtual time passed. */
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

    /** Frees every core's and both endpoints' native resources. */
    fun close() {
        batch.close()
        val all = LinkedHashSet<ConnectionCore>()
        all += client
        all += serverCores
        for (c in all) c.release()
        clientEp.close()
        server.close()
    }

    companion object {
        val CLIENT = InetSocketAddress("10.0.0.1", 40000)
        val SERVER = InetSocketAddress("10.0.0.2", 443)
        val PREFERRED = InetSocketAddress("10.0.0.3", 4433)

        /** A server address the client never dialled nor was offered. */
        val STRANGER = InetSocketAddress("10.0.0.9", 443)

        /** An Ethernet path: 1500-byte IPv4 packets, 1472 bytes of UDP payload. */
        const val DEFAULT_MTU = 1472

        /** What a router quotes of the datagram (IPv4 ICMP: 576 bytes in all, less the IP and ICMP headers and the quoted IP and UDP headers). */
        const val ICMP_QUOTE = 520
        const val QUEUE_CAP = 256
        const val VERSION_2 = 0x6b3343cf
    }
}

/** Plain parsing of datagrams for the invariants (the long header is cleartext; with NullCryptoProvider everything is). */
internal object Datagrams {
    fun version(b: ByteArray): Int =
        if (b.size < 5 || b[0].toInt() and 0x80 == 0) {
            0
        } else {
            ((b[1].toInt() and 0xff) shl 24) or ((b[2].toInt() and 0xff) shl 16) or ((b[3].toInt() and 0xff) shl 8) or
                (b[4].toInt() and 0xff)
        }
}
