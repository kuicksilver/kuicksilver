// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic

import io.ktor.network.sockets.InetSocketAddress
import io.kuicksilver.annotations.DelicateKuicksilverApi
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.native.PacketBuffer
import io.kuicksilver.native.of
import io.kuicksilver.native.packetBuffersOpenOnThisThread
import io.kuicksilver.native.toByteArray
import io.kuicksilver.quic.VersionProfile
import io.kuicksilver.quic.core.release
import io.kuicksilver.quic.core.serverWithKeys
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

    private val defaultChain: List<ByteArray> by lazy { listOf(TestCerts.server) }

    /**
     * The identity of the default chain and key, made once: a fresh one per fixture is never closed, so its native key
     * stayed allocated (the fuzz targets build a pair per input and ran out of memory over hours).
     */
    private val defaultIdentity: TlsIdentity by lazy { TlsIdentity.fromDer(defaultChain, TestCerts.serverKey.copyOf()) }

    fun server(
        alpn: String = "hq-interop",
        chain: List<ByteArray> = defaultChain,
        key: ByteArray = TestCerts.serverKey,
        block: TlsConfig.Builder.() -> Unit = {
        },
    ): TlsConfig =
        tlsConfig(TlsRole.Server) {
            this.alpn = listOf(alpn)
            identity =
                if (chain === defaultChain && key === TestCerts.serverKey) defaultIdentity else TlsIdentity.fromDer(chain, key.copyOf())
            block()
        }

    val clientAddr = InetSocketAddress("10.0.0.1", 40000)
    val serverAddr = InetSocketAddress("10.0.0.2", 443)
}

/** A datagram in flight between the two cores. */
internal class Dgram(
    val bytes: ByteArray,
    val from: InetSocketAddress,
    /** The ECN codepoint the datagram arrives with (NotEct unless a test marks it). */
    val ecn: Ecn = Ecn.NotEct,
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
    crypto: QuicCrypto = NullCryptoProvider,
    seed: Long = 1,
    clientEarly: io.kuicksilver.tls.EarlyDataState = io.kuicksilver.tls.EarlyDataState.Disabled,
    private val serverEarly: io.kuicksilver.quic.core.ServerEarlyData? = null,
    clientSetup: (ConnectionCore) -> Unit = {},
    /** The endpoints' stateless reset keys (owned by the test, as an endpoint owns its own); null: random tokens. */
    clientResetKey: io.kuicksilver.tls.ResetKey? = null,
    private val serverResetKey: io.kuicksilver.tls.ResetKey? = null,
) : AutoCloseable {
    private val buffers = BufferWatch.opened()
    var now: TimeMark = TimeMark(1_000_000_000L)
    val random = Random(seed)

    /**
     * Counts every native-backed object the cores get from [crypto] ([LeakTrackingCrypto]); [close] fails when one is
     * left open after the cores were released. A test's own [LeakTrackingCrypto] is used as it is.
     */
    val leaks: LeakTrackingCrypto = crypto as? LeakTrackingCrypto ?: LeakTrackingCrypto(crypto)
    private val crypto: QuicCrypto = leaks

    val client: ConnectionCore =
        ConnectionCore
            .client(
                clientQuic,
                clientTls,
                crypto,
                CoreFixtures.serverAddr,
                Random(seed + 1),
                now,
                clientResetKey,
                clientEarly,
            ).also(clientSetup)
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

    /**
     * The client's original DCID and the SCID of a Retry the test made it accept (as a stateless server would, RFC 9000
     * section 17.2.5): the server core is created with them, so its transport parameters carry what the client checks.
     */
    var serverAfterRetry: Pair<io.kuicksilver.quic.wire.ConnectionId, io.kuicksilver.quic.wire.ConnectionId>? = null

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
                core.handleDatagram(b, d.bytes.size, d.from, d.ecn, now)
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
            if (e is ConnectionEvent.SniRequested) core.resumeSni(runBlocking { e.session.selectSni(e.clientHello) })
        }
    }

    private fun serverFromFirstInitial() {
        val d = toServer.firstOrNull() ?: return
        val b = PacketBuffer.of(d.bytes)
        try {
            server =
                ConnectionCore.serverWithKeys(
                    serverQuic,
                    serverTls,
                    crypto,
                    d.from,
                    Random(99),
                    now,
                    b,
                    d.bytes.size,
                    null,
                    serverResetKey,
                    originalDcid = serverAfterRetry?.first,
                    retryScid = serverAfterRetry?.second,
                    early = serverEarly,
                )
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

    /**
     * Frees the cores' native resources (TLS sessions, keys) too: a connection still open at the end would keep them.
     * Then checks that nothing leaked: every object the cores got from the crypto provider is closed (on the JVM and
     * Native alike, also for [NullCryptoProvider], whose objects stand for native ones), and no [PacketBuffer] the
     * test allocated while the pair was open is left open ([BufferWatch]). A second close checks nothing more. Close it
     * with `use { }`, so that a failure of the test is not hidden by the leak it left: a leak found then is added to it
     * as suppressed.
     */
    override fun close() {
        if (closed) return
        closed = true
        batch.close()
        client.release()
        server?.release()
        // the client owns the tickets its events handed out: those a test did not [keep] go with the pair (a consumed or
        // closed one is closed already; closing is idempotent)
        for (e in clientEvents) if (e is ConnectionEvent.SessionTicket && e.ticket !in kept) e.ticket.close()
        val live = leaks.live
        if (live.isNotEmpty()) throw AssertionError("native objects left open after the cores were released: $live")
        BufferWatch.closed("CorePair", buffers)
    }

    private var closed = false

    /** Tickets of [clientEvents] the test takes past [close] (and closes itself). */
    private val kept = HashSet<io.kuicksilver.tls.QuicSessionTicket>()

    /** [ticket] outlives this pair: [close] leaves it open, the test closes it. */
    fun keep(ticket: io.kuicksilver.tls.QuicSessionTicket): io.kuicksilver.tls.QuicSessionTicket = ticket.also { kept += it }
}

/** The thread running the caller (a key compared for identity only). */
internal expect fun fixtureThread(): Any

/**
 * The [PacketBuffer]s a test allocates on a thread while a fixture (CorePair, EndpointPair) is open are all closed when
 * it closes: the thread's count after its close is the count before it was built. Judged for a fixture during whose
 * life no other fixture was built or closed (fixtures left open by earlier tests do not count: they are not used); when
 * two overlap, what each holds at the other's close cannot be told apart, and only their crypto objects are judged
 * ([LeakTrackingCrypto]). The count is per thread ([packetBuffersOpenOnThisThread]): a fixture closed on another thread
 * than the one that built it fails its close, saying so (the counts of two threads cannot be compared).
 */
internal object BufferWatch {
    private var events = 0L
    private var warm = false

    /** What [closed] compares: the fixture's place among the builds and closes, the count, the thread. */
    class Opened(
        val event: Long,
        val buffers: Long,
        val thread: Any,
    )

    /** Called first in a fixture's construction: what [closed] compares. */
    fun opened(): Opened {
        if (!warm) {
            warm = true
            // what a process makes once and keeps (a core's shared scratch buffer) is made before the first count
            ConnectionCore
                .client(
                    QuicConfig.Default,
                    CoreFixtures.client(),
                    NullCryptoProvider,
                    CoreFixtures.serverAddr,
                    Random(1),
                    TimeMark(1),
                    null,
                ).release()
        }
        return Opened(++events, packetBuffersOpenOnThisThread(), fixtureThread())
    }

    /** Called once the fixture freed all it holds: fails when buffers allocated meanwhile are still open. */
    fun closed(
        what: String,
        opened: Opened,
    ) {
        val alone = events == opened.event
        events++
        if (fixtureThread() != opened.thread) {
            throw AssertionError(
                "$what: closed on another thread than the one that built it; its PacketBuffers are counted per thread, " +
                    "so build and close it on one thread",
            )
        }
        if (!alone) return
        val left = packetBuffersOpenOnThisThread() - opened.buffers
        if (left != 0L) throw AssertionError("$what: $left PacketBuffer(s) left open on this thread since the fixture was built")
    }
}

internal val ksl: QuicCrypto get() = KslQuicCrypto
