// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic

import io.ktor.network.sockets.InetSocketAddress
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.native.PacketBuffer
import io.kuicksilver.quic.VersionProfile
import io.kuicksilver.quic.core.AddressClass
import io.kuicksilver.quic.core.CidRegistrar
import io.kuicksilver.quic.core.checkStatelessReset
import io.kuicksilver.quic.core.failInternal
import io.kuicksilver.quic.core.refreshLocalTp
import io.kuicksilver.quic.core.release
import io.kuicksilver.quic.endpoint.AdmissionQueue
import io.kuicksilver.quic.endpoint.ConnectionIdRegistry
import io.kuicksilver.quic.endpoint.RetryTokens
import io.kuicksilver.quic.endpoint.ServerCidFormat
import io.kuicksilver.quic.endpoint.StatelessClose
import io.kuicksilver.quic.endpoint.StatelessRateLimiter
import io.kuicksilver.quic.endpoint.StatelessReset
import io.kuicksilver.quic.endpoint.TokenCheck
import io.kuicksilver.quic.wire.ConnectionId
import io.kuicksilver.quic.wire.PacketHeaderCodec
import io.kuicksilver.quic.wire.PacketHeaderView
import io.kuicksilver.quic.wire.PacketType
import io.kuicksilver.quic.wire.RetryPacket
import io.kuicksilver.quic.wire.VersionNegotiationPacket
import io.kuicksilver.tls.ResetKey
import io.kuicksilver.tls.TlsRole
import kotlin.random.Random

/**
 * The sans-IO endpoint (ADR-0004): routes datagrams to connections by keyed connection ID, queues client Initials for
 * [ConnectionAdmission], creates server connections in [processPending], and answers unknown versions, forged tokens and
 * unknown short-header CIDs statelessly under a rate limit. One endpoint loop drives it; nothing here is thread-safe.
 *
 * A new client Initial takes two steps: [handleDatagram] runs only the cheap checks (1200 bytes, version, DCID length,
 * reflective source port) and copies the datagram into a bounded queue; the runtime then calls [processPending] once per
 * receive batch, which checks the Retry token, the hard limits and the admission policy, and creates the connection.
 *
 * @property config The endpoint's settings; its `server` decides whether client Initials are admitted at all.
 * @property loopIndex This endpoint's loop in a group (0 for a single loop): the routing byte of every server connection ID it issues.
 */
@ExperimentalKuicksilverApi
public class EndpointCore(
    public val config: QuicEndpointConfig,
    internal val random: Random,
    public val loopIndex: Int = 0,
) {
    // [random] must be a CSPRNG in production (the runtime passes a per-loop `RAND_bytes` stream): every connection of this endpoint draws its
    // connection IDs, PATH_CHALLENGE data and skipped packet numbers from it directly; tests pass a seeded Random to stay deterministic
    internal val registry = ConnectionIdRegistry(random.nextLong(), random.nextLong())
    internal val connections = ArrayList<ConnectionCore>()
    internal val accepted = ArrayDeque<ConnectionCore>()
    internal val hv = PacketHeaderView()

    internal class Stateless(
        val bytes: ByteArray,
        val to: InetSocketAddress,
    )

    internal val stateless = ArrayDeque<Stateless>()
    internal val vnBuffer = PacketBuffer.allocate(1500)

    /** One reset key per endpoint (loop), random for the life of the process (RFC 9000 section 10.3; ADR-0003). */
    internal val resetKey: ResetKey = config.crypto.newResetKey()
    internal val limiter = StatelessRateLimiter(config.statelessPerAddressPerSecond, config.statelessTotalPerSecond)
    internal val retryTokens: RetryTokens? = if (config.server != null) RetryTokens(config.crypto, random) else null
    private val queue: AdmissionQueue? = if (config.server != null) AdmissionQueue(config.initialQueueCap) else null

    /** Connections per client IP (ports ignored) for `maxConnectionsPerIp`. */
    internal val perIp = HashMap<Any, Int>()
    internal var statelessResets = 0L
    internal var statelessRateLimited = 0L
    internal var retriesSent = 0L
    internal var invalidTokens = 0L
    internal var initialsDropped = 0L
    internal var versionNegotiations = 0L
    internal var admissionContractViolations = 0L
    internal var connectionsCreated = 0L
    internal var testForgeRetryScidInTp = false

    /** Test hook: connections examined as Stateless Reset candidates by the last unknown short header. */
    internal var resetCandidatesExaminedForTest = 0

    /** Test hook: after a Retry, answer with a fresh SCID instead of reusing the Retry SCID (what ngtcp2 and quinn do), the Retry SCID staying an alias for the client's Initials. */
    internal var testFreshCidAfterRetry = false
    internal val cidLength: Int get() = config.connectionIdLength

    /** Connections that completed their handshake and wait for the application's `accept()`; the loop replaces the default (this core's own queue). */
    public var acceptBacklog: () -> Int = { accepted.size }
    private val registrar =
        object : CidRegistrar {
            override fun add(
                cid: ConnectionId,
                core: ConnectionCore,
            ) = registry.add(cid, core)

            override fun remove(cid: ConnectionId) = registry.remove(cid)
        }

    /** Connections this endpoint holds, in any state, until they are closed and removed. */
    public val connectionCount: Int get() = connections.size

    /** Client Initials copied in by [handleDatagram] and not yet decided by [processPending]. */
    public val pendingInitials: Int get() = queue?.size ?: 0

    /** Counters since the endpoint started. */
    public val stats: EndpointStats get() =
        EndpointStats(
            initialsDropped,
            retriesSent,
            invalidTokens,
            versionNegotiations,
            statelessResets,
            statelessRateLimited,
            admissionContractViolations,
            connectionsCreated,
        )

    /** A new client connection to [remote]; its first [ConnectionCore.poll] produces the Initial datagrams. */
    public fun connect(
        client: QuicClientConfig,
        remote: InetSocketAddress,
        now: TimeMark,
    ): ConnectionCore {
        require(client.quic.connectionIdLength == cidLength) {
            "QuicConfig.connectionIdLength (${client.quic.connectionIdLength}) must equal the endpoint's connectionIdLength ($cidLength)"
        }
        // the endpoint's CSPRNG itself: a child Random(seed) would let an observer recover the 64-bit seed from two cleartext CIDs
        val core = ConnectionCore.client(client.quic, client.tls, config.crypto, remote, random, now, resetKey)
        attach(core)
        return core
    }

    internal fun attach(core: ConnectionCore) {
        core.registrar = registrar
        registry.add(core.localCid, core)
        connections += core
        connectionsCreated++
        markDirty(core)
        // rotated IDs route and reset like the first one
        if (core.role == TlsRole.Server) core.cids.generator = { r -> ServerCidFormat.generate(loopIndex, cidLength, r) }
        byRemote.getOrPut(AddressClass.addrKey(core.remoteAddress)) { ArrayList(1) } += core
        core.onRemoteChanged =
            {
                old,
                new,
                ->
                val oldKey = AddressClass.addrKey(old)
                byRemote[oldKey]?.let { l ->
                    l.remove(core)
                    if (l.isEmpty()) byRemote.remove(oldKey)
                }
                byRemote.getOrPut(AddressClass.addrKey(new)) { ArrayList(1) } +=
                    core
            }
    }

    /** Connections by the remote address of their active path: Stateless Reset candidates for an unknown short header are only those at its source. */
    private val byRemote = HashMap<AddressClass.AddrKey, ArrayList<ConnectionCore>>()

    // ---- dirty connections: the loop polls only connections something happened to since its last flush ----
    private val dirty = ArrayList<ConnectionCore>()

    /** Connections touched since [clearDirty]: a datagram, a timer, an application command or creation; the loop's flush visits only these. */
    public val dirtyConnections: List<ConnectionCore> get() = dirty

    /** Puts [core] on [dirtyConnections] so the next flush polls it; call it after touching a connection from outside [handleDatagram]. */
    public fun markDirty(core: ConnectionCore) {
        if (!core.dirty) {
            core.dirty = true
            dirty += core
        }
    }

    /** Empties [dirtyConnections] once the loop flushed every connection on it. */
    public fun clearDirty() {
        for (i in 0 until dirty.size) dirty[i].dirty = false
        dirty.clear()
    }

    /**
     * The loop that owns the connection a datagram belongs to, read from the routing byte of our server CID format ([ServerCidFormat]),
     * or -1: an Initial (admitted where it lands), Version Negotiation, a client endpoint, or a DCID not in our format. The
     * endpoint runtime forwards a datagram whose owner is another loop (a flow the kernel hashed onto this socket after a rebind).
     */
    public fun ownerLoop(
        data: PacketBuffer,
        length: Int,
    ): Int {
        if (config.server == null || !PacketHeaderCodec.parse(data, 0, length, cidLength, hv)) return -1
        if (hv.isVersionNegotiation || hv.type == PacketType.Initial || hv.type == PacketType.Retry) return -1
        if (hv.dcidLen != cidLength || data[hv.dcidOff].toInt() != ServerCidFormat.FORMAT_VERSION) return -1
        return data[hv.dcidOff + 1].toInt() and 0xff
    }

    /**
     * Routes one datagram; returns the connection that took it, or null when it was dropped, answered statelessly or
     * queued as a new client Initial (those become connections in [processPending]).
     */
    public fun handleDatagram(
        data: PacketBuffer,
        length: Int,
        from: InetSocketAddress,
        ecn: Ecn,
        now: TimeMark,
    ): ConnectionCore? = handleDatagram(data, length, from, ecn, now, PathId.Initial)

    /** [handleDatagram] for a datagram that arrived on the client socket [socket] of a migrating connection (RFC 9000 section 9). */
    public fun handleDatagram(
        data: PacketBuffer,
        length: Int,
        from: InetSocketAddress,
        ecn: Ecn,
        now: TimeMark,
        socket: PathId,
    ): ConnectionCore? {
        if (!PacketHeaderCodec.parse(data, 0, length, cidLength, hv)) return null
        if (hv.isVersionNegotiation && config.server != null) return null // a server never acts on Version Negotiation
        registry.lookup(data, hv.dcidOff, hv.dcidLen)?.let {
            deliver(it, data, length, from, ecn, now, socket)
            return it
        }
        if (hv.isVersionNegotiation) {
            connections.firstOrNull { it.odcid.contentEquals(data, hv.scidOff, hv.scidLen) }?.let {
                deliver(it, data, length, from, ecn, now)
                return it
            }
            return null
        }
        if (hv.type == PacketType.OneRtt) {
            // RFC 9000 section 10.3: an unknown DCID in a short header is either a Stateless Reset for one of our connections to that peer, or a reason to send one
            resetCandidatesExaminedForTest = 0
            byRemote[AddressClass.addrKey(from)]?.let { l ->
                for (i in l.indices) {
                    val c = l[i]
                    resetCandidatesExaminedForTest++
                    if (c.checkStatelessReset(data, length, now)) {
                        markDirty(c)
                        return c
                    }
                }
            }
            if (config.server != null && length > StatelessReset.MIN_SIZE && hv.dcidLen == cidLength &&
                data[hv.dcidOff].toInt() == ServerCidFormat.FORMAT_VERSION &&
                data[hv.dcidOff + 1].toInt() == loopIndex
            ) {
                if (!limiter.allow(from, now)) {
                    statelessRateLimited++
                    return null
                }
                val token = ByteArray(16)
                resetKey.token(data, hv.dcidOff, hv.dcidLen, token, 0)
                val n = StatelessReset.write(vnBuffer, token, length, random)
                if (n >
                    0
                ) {
                    val bytes = ByteArray(n)
                    vnBuffer.copyTo(bytes, 0, 0, n)
                    stateless += Stateless(bytes, from)
                    statelessResets++
                }
            }
            return null
        }
        val server = config.server ?: return null
        // ---- cheap checks before anything is remembered about this datagram (threat-model 3.2) ----
        if (length < 1200) return null
        if (hv.unsupportedVersion || VersionProfile.of(hv.version)?.let { it !in server.quic.versions } != false) {
            if (hv.type == PacketType.Initial || hv.unsupportedVersion) queueVersionNegotiation(data, length, from, server.quic, now)
            return null
        }
        if (hv.type != PacketType.Initial) return null
        if (hv.dcidLen < 8) return null
        if (from.port == 0) {
            initialsDropped++
            return null
        } // no socket answers port 0 and the kernel refuses the reply (EINVAL): a spoofed Initial must not cost a send
        if (config.rejectInitialFromReflectivePorts && AddressClass.isReflectivePort(from.port)) {
            initialsDropped++
            return null
        } // threat-model 3.1: silence to a reflection source
        if (!queue!!.offer(data, length, from, ecn, now)) initialsDropped++ // the queue is bounded; overflow is a drop
        return null
    }

    /**
     * Decides up to [max] queued client Initials: a duplicate of a connection created meanwhile is routed to it;
     * a forged or expired Retry token is refused with INVALID_TOKEN; the hard limits (`maxConnections`, `acceptQueue`,
     * `maxConnectionsPerIp`) drop; then [QuicEndpointConfig.admission] decides. Returns the number of connections created.
     * The runtime calls it after every receive batch; what it leaves waits for the next one.
     */
    public fun processPending(
        now: TimeMark,
        max: Int = 64,
    ): Int {
        val q = queue ?: return 0
        if (q.size == 0) return 0
        // one scan per batch, not per attempt: handshakes in flight and the bytes they hold
        var inflight = 0
        var handshakeBuffer = 0L
        for (i in connections.indices) {
            val c = connections[i]
            if (c.role == TlsRole.Server &&
                (c.state == ConnectionState.Handshaking || c.state == ConnectionState.Established)
            ) {
                inflight++
                handshakeBuffer +=
                    c.handshakeBufferBytes
            }
        }
        var created = 0
        var n = 0
        while (n < max) {
            val e = q.poll() ?: break
            n++
            try {
                if (admitOne(e, now, inflight, handshakeBuffer)) {
                    created++
                    inflight++
                }
            } finally {
                q.recycle(e)
            }
        }
        return created
    }

    /** One connection's failure stays its own: an exception out of the core closes that connection, never the endpoint. */
    internal fun deliver(
        core: ConnectionCore,
        data: PacketBuffer,
        length: Int,
        from: InetSocketAddress,
        ecn: Ecn,
        now: TimeMark,
        socket: PathId = PathId.Initial,
    ) {
        markDirty(core)
        try {
            core.handleDatagram(data, length, from, ecn, now, socket)
        } catch (
            e: Throwable,
        ) {
            if (e is kotlinx.coroutines.CancellationException) throw e
            core.failInternal(e)
        }
    }

    /** Frees the queue, the stateless buffer and every connection's native resources. */
    public fun close() {
        for (c in connections) c.release()
        connections.clear()
        accepted.clear()
        perIp.clear()
        registry.clear()
        vnBuffer.close()
        resetKey.close()
        retryTokens?.close()
        queue?.close()
    }

    /** The next server connection the application has not taken yet. */
    public fun nextAccepted(): ConnectionCore? = accepted.removeFirstOrNull()

    /** True while stateless answers wait in [pollStateless]. */
    public val hasStateless: Boolean get() = stateless.isNotEmpty()

    /** Stateless answers (Version Negotiation, Retry, Stateless Reset, Initial CONNECTION_CLOSE) to send. */
    public fun pollStateless(out: PacketBatch): Int {
        var i = 0
        while (i <
            out.capacity
        ) {
            val s =
                stateless.removeFirstOrNull() ?: break
            out.buffer(i).copyFrom(s.bytes, 0, 0, s.bytes.size)
            out.setLength(i, s.bytes.size)
            out.setAddress(i, s.to)
            i++
        }
        return i
    }

    /** Forgets a closed connection, every ID that routed to it and its per-IP slot. */
    public fun remove(core: ConnectionCore) {
        registry.removeAll(core)
        connections.remove(core)
        accepted.remove(core)
        if (core.dirty) {
            dirty.remove(core)
            core.dirty = false
        }
        val remoteKey = AddressClass.addrKey(core.remoteAddress)
        byRemote[remoteKey]?.let { l ->
            l.remove(core)
            if (l.isEmpty()) byRemote.remove(remoteKey)
        }
        core.onRemoteChanged =
            null
        core.admissionIpKey?.let { k ->
            val n =
                (perIp[k] ?: 1) - 1
            if (n <= 0) perIp.remove(k) else perIp[k] = n
            core.admissionIpKey = null
        }
    }

    /** Connections in creation order (for the loop). */
    public fun connections(): List<ConnectionCore> = connections
}
