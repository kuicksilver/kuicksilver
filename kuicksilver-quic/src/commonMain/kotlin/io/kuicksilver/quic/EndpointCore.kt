// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic

import io.ktor.network.sockets.InetSocketAddress
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.native.PacketBuffer
import io.kuicksilver.native.of
import io.kuicksilver.quic.VersionProfile
import io.kuicksilver.quic.core.AddressClass
import io.kuicksilver.quic.core.CidRegistrar
import io.kuicksilver.quic.core.acceptPacketTooBig
import io.kuicksilver.quic.core.checkStatelessReset
import io.kuicksilver.quic.core.failInternal
import io.kuicksilver.quic.core.refreshLocalTp
import io.kuicksilver.quic.core.release
import io.kuicksilver.quic.core.useTicket
import io.kuicksilver.quic.endpoint.AddressTokens
import io.kuicksilver.quic.endpoint.AdmissionQueue
import io.kuicksilver.quic.endpoint.ByteRoute
import io.kuicksilver.quic.endpoint.CidIssuance
import io.kuicksilver.quic.endpoint.CidRoute
import io.kuicksilver.quic.endpoint.ConnectionIdRegistry
import io.kuicksilver.quic.endpoint.QuicLbRoute
import io.kuicksilver.quic.endpoint.QuicLbState
import io.kuicksilver.quic.endpoint.ResetGate
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
import kotlin.concurrent.Volatile
import kotlin.random.Random
import kotlin.time.Duration
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.seconds

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
 * @property loopIndex This endpoint's loop in a group (0 for a single loop): the routing byte of every server connection ID it issues
 * (with a QUIC-LB configuration, the loop its IDs hash to).
 */
@ExperimentalKuicksilverApi
public class EndpointCore internal constructor(
    public val config: QuicEndpointConfig,
    internal val random: Random,
    public val loopIndex: Int,
    /** The address tokens of a loop group, shared by its loops (this endpoint is one owner); null makes this endpoint's own. */
    sharedTokens: AddressTokens?,
    /** A group's QUIC-LB state, shared by its loops (this endpoint is one owner); null makes this endpoint's own when it has a `loadBalancer`. */
    sharedLb: QuicLbState? = null,
) {
    /** An endpoint with its own Retry, NEW_TOKEN and reset keys; [loopIndex] is its routing byte in a group (0 alone). */
    public constructor(config: QuicEndpointConfig, random: Random, loopIndex: Int = 0) : this(config, random, loopIndex, null)

    // [random] must be a CSPRNG in production (the runtime passes a per-loop `RAND_bytes` stream): every connection of this endpoint draws its
    // connection IDs, PATH_CHALLENGE data and skipped packet numbers from it directly; tests pass a seeded Random to stay deterministic
    internal val registry = ConnectionIdRegistry(random.nextLong(), random.nextLong())
    internal val connections = ArrayList<ConnectionCore>()
    internal val accepted = ArrayDeque<ConnectionCore>()
    internal val hv = PacketHeaderView()

    internal class Stateless(
        val bytes: ByteArray,
        val to: InetSocketAddress,
        /** Our address the answered datagram was sent to: the answer leaves from it (RFC 9000 section 9); null for the socket's choice. */
        val from: InetSocketAddress?,
    )

    /**
     * Our address the datagram being handled was sent to ([handleDatagram]'s `local`, or that of a queued Initial or early datagram
     * being replayed): connections created from it and the stateless answers to it use it as their local end. Loop thread only.
     */
    internal var rxLocal: InetSocketAddress? = null

    internal val stateless = ArrayDeque<Stateless>()
    internal val vnBuffer: PacketBuffer

    /** One reset key per endpoint (loop), random for the life of the process (RFC 9000 section 10.3; ADR-0003). */
    internal val resetKey: ResetKey
    internal val limiter: StatelessRateLimiter

    /** QUIC-LB decryptions of unknown IDs for the Stateless Reset gate, per address and in total, a second (the reset limits). */
    private val decryptLimiter: StatelessRateLimiter

    /** Retry and NEW_TOKEN tokens (RFC 9000 section 8.1): a group's, or this endpoint's own; null without a server. */
    internal val addressTokens: AddressTokens?
    internal val queue: AdmissionQueue?

    /** The server's 0-RTT setup (configuration digest and the replay register shared by every loop), or null without 0-RTT. */
    internal val serverEarly: io.kuicksilver.quic.core.ServerEarlyData?

    /** The QUIC-LB configurations (a group's, or this endpoint's own), or null without `loadBalancer`. */
    internal val lb: QuicLbState?

    /** The layout of our connection IDs: making them, the loop that owns one, the reset gate. */
    internal val route: CidRoute

    /** [lb] is this endpoint's own, not a group's: [updateLoadBalancer] may change it. */
    private val ownsLb: Boolean

    /** Times a QUIC-LB configuration's nonces ran out on this loop (`EndpointStats.loadBalancerNoncesExhausted`). */
    internal var lbNoncesExhausted = 0L

    /** Failed `QuicLbNonceReservation.store` calls on this loop (`EndpointStats.loadBalancerReservationFailures`). */
    internal var lbReservationFailures = 0L

    init {
        // native memory (the buffers, the keys) is freed only by close(): a constructor that fails part-way frees what it made
        var vn: PacketBuffer? = null
        var rk: ResetKey? = null
        var tokens: AddressTokens? = null
        var q: AdmissionQueue? = null
        var ownLb: QuicLbState? = null
        try {
            vn = PacketBuffer.allocate(1500)
            vnBuffer = vn
            rk = config.crypto.newResetKey()
            resetKey = rk
            limiter = StatelessRateLimiter(config.statelessPerAddressPerSecond, config.statelessTotalPerSecond)
            decryptLimiter = StatelessRateLimiter(config.statelessPerAddressPerSecond, config.statelessTotalPerSecond)
            tokens =
                if (config.server == null) {
                    null
                } else {
                    sharedTokens?.also { check(it.retain()) { "the group's address tokens are closed" } }
                        ?: AddressTokens(
                            config.crypto,
                            random,
                            newTokenLifetime = config.server.newTokenLifetime,
                            replayCapacity = config.server.newTokenReplayCapacity,
                        )
                }
            addressTokens = tokens
            q = if (config.server != null) AdmissionQueue(config.initialQueueCap) else null
            queue = q
            serverEarly = config.server?.earlySetup(random)
            // the loops of a group must share one state: one SipHash key names the owner, one view of the configuration
            require(config.loadBalancer == null || config.loops == 1 || sharedLb != null) {
                "a loop group's endpoint cores share one QUIC-LB state: bind the endpoint (QuicEndpoint.bind) rather than building its cores"
            }
            ownLb =
                if (config.loadBalancer == null) {
                    null
                } else {
                    sharedLb?.also { check(it.retain()) { "the group's QUIC-LB state is closed" } }
                        ?: QuicLbState(config.crypto, random, config.loadBalancer, config.loops, config.connectionIdLength)
                }
            lb = ownLb
            ownsLb = sharedLb == null
            route =
                if (ownLb != null) {
                    QuicLbRoute(
                        ownLb,
                        loopIndex,
                        onExhausted = {
                            lbNoncesExhausted++
                            config.logger.emit(LogLevel.Warn) {
                                "QUIC-LB: the nonces of configuration ${lb.routes.current?.config} are spent; " +
                                    "issuing unroutable connection IDs until updateLoadBalancer gives a new configuration"
                            }
                        },
                        onStoreFailed = { e ->
                            lbReservationFailures++
                            config.logger.emit(LogLevel.Warn, e) {
                                "QUIC-LB: the nonce reservation could not be stored; retried after a back-off, and connection IDs " +
                                    "are unroutable once the reserved nonces are used"
                            }
                        },
                    )
                } else {
                    ByteRoute(loopIndex, config.connectionIdLength)
                }
        } catch (e: Throwable) {
            val r = Releaser(e) // what a release throws is suppressed into e
            r.release { ownLb?.close() }
            r.release { q?.close() }
            r.release { tokens?.close() } // this endpoint's own, or its reference to the group's
            r.release { rk?.close() }
            r.release { vn?.close() }
            throw e
        }
    }

    /** 0-RTT datagrams that arrived before the Initial that creates their connection, by DCID (as quic-go: 100 ms, 32 IDs, 31 each). */
    private class EarlyDatagram(
        val bytes: ByteArray,
        val from: InetSocketAddress,
        val local: InetSocketAddress?,
        val ecn: Ecn,
        val at: TimeMark,
    )

    private val earlyPending = LinkedHashMap<String, ArrayList<EarlyDatagram>>()

    private fun dcidKey(
        data: PacketBuffer,
        off: Int,
        len: Int,
    ): String {
        val sb = StringBuilder(len * 2)
        for (i in 0 until len) sb.append((data[off + i].toInt() and 0xff).toString(16).padStart(2, '0'))
        return sb.toString()
    }

    private fun expireEarly(now: TimeMark) {
        val it = earlyPending.entries.iterator()
        while (it.hasNext()) if (now - it.next().value[0].at > EARLY_PENDING_TTL) it.remove()
    }

    private fun bufferEarly(
        data: PacketBuffer,
        length: Int,
        from: InetSocketAddress,
        ecn: Ecn,
        now: TimeMark,
    ) {
        expireEarly(now)
        val key = dcidKey(data, hv.dcidOff, hv.dcidLen)
        val l =
            earlyPending[key]
                ?: if (earlyPending.size >= EARLY_PENDING_IDS) return else ArrayList<EarlyDatagram>().also { earlyPending[key] = it }
        if (l.size >= EARLY_PENDING_PER_ID) return
        l += EarlyDatagram(ByteArray(length).also { data.copyTo(it, 0, 0, length) }, from, rxLocal, ecn, now)
    }

    /** Feeds [core] the 0-RTT datagrams that waited for it under [dcid] (the DCID of the client's first Initial). */
    internal fun replayEarly(
        core: ConnectionCore,
        dcid: ConnectionId,
        now: TimeMark,
    ) {
        if (earlyPending.isEmpty()) return
        val b = dcid.toByteArray()
        val l = earlyPending.remove(b.joinToString("") { (it.toInt() and 0xff).toString(16).padStart(2, '0') }) ?: return
        for (e in l) {
            if (now - e.at > EARLY_PENDING_TTL) continue
            val buf = PacketBuffer.of(e.bytes)
            try {
                deliver(core, buf, e.bytes.size, e.from, e.ecn, now, local = e.local)
            } finally {
                buf.close()
            }
        }
    }

    internal val earlyPendingForTest: Int get() = earlyPending.values.sumOf { it.size }

    /** Connections per client IP (ports ignored) for `maxConnectionsPerIp`. */
    internal val perIp = HashMap<Any, Int>()
    internal var statelessResets = 0L
    internal var statelessRateLimited = 0L
    internal var retriesSent = 0L
    internal var invalidTokens = 0L
    internal var newTokensIssued = 0L
    internal var newTokensAccepted = 0L
    internal var newTokensRejected = 0L
    internal var initialsDropped = 0L

    /** Client Initials answered with CONNECTION_REFUSED because the accept queue was full (RFC 9000 section 5.2.2). */
    @Volatile internal var acceptQueueRefusals = 0L
    internal var versionNegotiations = 0L
    internal var admissionContractViolations = 0L
    internal var connectionsCreated = 0L

    // ---- observability (EndpointStats): plain counters, the loop's thread only ----
    internal var refusedAdmission = 0L
    internal var refusedLimits = 0L
    internal var refusedShutdown = 0L
    internal var droppedQueue = 0L
    internal var droppedUndecryptable = 0L
    internal var droppedStateless = 0L

    /** Set by `QuicEndpoint.shutdown`: every new client Initial is refused with CONNECTION_REFUSED, statelessly (RFC 9000 section 10.2.3). */
    @Volatile internal var shuttingDown = false
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

            override fun remove(cid: ConnectionId) {
                registry.remove(cid)
                route.release(cid)
            }
        }

    /** Connections this endpoint holds, in any state, until they are closed and removed. */
    public val connectionCount: Int get() = connections.size

    /** Client Initials copied in by [handleDatagram] and not yet decided by [processPending]. */
    public val pendingInitials: Int get() = queue?.size ?: 0

    /** Counters since the endpoint started. */
    public val stats: EndpointStats get() =
        EndpointStats(
            initialsDropped = initialsDropped,
            retriesSent = retriesSent,
            invalidTokens = invalidTokens,
            versionNegotiations = versionNegotiations,
            statelessResets = statelessResets,
            statelessRateLimited = statelessRateLimited,
            admissionContractViolations = admissionContractViolations,
            connectionsCreated = connectionsCreated,
            connectionsActive = connections.size.toLong(),
            connectionsRefusedAcceptQueue = acceptQueueRefusals,
            connectionsRefusedAdmission = refusedAdmission,
            connectionsRefusedLimits = refusedLimits,
            connectionsRefusedShutdown = refusedShutdown,
            datagramsDroppedQueue = droppedQueue,
            datagramsDroppedUndecryptable = droppedUndecryptable,
            datagramsDroppedStateless = droppedStateless + droppedPreferredDown,
            newTokensIssued = newTokensIssued,
            newTokensAccepted = newTokensAccepted,
            newTokensRejected = newTokensRejected,
            ptbAccepted = ptbAccepted,
            ptbIgnored = ptbIgnored,
            preferredAddressFailures = preferredAddressFailures,
            loadBalancerNoncesExhausted = lbNoncesExhausted,
            loadBalancerReservationFailures = lbReservationFailures,
            loadBalancerNoncesWasted = (route as? QuicLbRoute)?.wasted ?: 0L,
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
        // RFC 9002 section 6.2.2: a connection to a server this endpoint already measured starts from that RTT, so a lost first flight
        // is probed at about 3 x that RTT instead of 1 s, 2 s, 4 s ... (a peer like quic-go drops a half-open connection after 5 s of silence)
        val quic = rttMemory[AddressClass.addrKey(remote)]?.let { client.quic.withInitialRtt(it) } ?: client.quic
        // the endpoint's CSPRNG itself: a child Random(seed) would let an observer recover the 64-bit seed from two cleartext CIDs
        // in a group the server's answers may land on another loop's socket: the routing byte in our CIDs brings them back
        val scid = if (grouped) route.newCid(random, client = true) else null
        val core = ConnectionCore.client(quic, client.tls, config.crypto, remote, random, now, resetKey, client.earlyData, scid)
        attach(core)
        connectionsCreated++
        return core
    }

    /** [connect] resuming [ticket] (consumed) for 0-RTT when [client] allows early data. */
    internal fun connect(
        client: QuicClientConfig,
        remote: InetSocketAddress,
        now: TimeMark,
        ticket: io.kuicksilver.tls.QuicSessionTicket?,
    ): ConnectionCore {
        val core = connect(client, remote, now)
        if (ticket != null) {
            if (client.earlyData == io.kuicksilver.tls.EarlyDataState.Disabled) ticket.close() else core.useTicket(ticket)
        }
        return core
    }

    /** Test hook: server connections hold their NEW_CONNECTION_ID frames (ConnectionIdManager.holdNewCidsForTest). */
    internal var testHoldNewConnectionIds = false

    internal fun attach(
        core: ConnectionCore,
        issuance: CidIssuance = CidIssuance.Full,
    ) {
        core.registrar = registrar
        if (testHoldNewConnectionIds && core.role == TlsRole.Server) core.cids.holdNewCidsForTest = true
        registry.add(core.localCid, core)
        connections += core
        markDirty(core)
        // rotated IDs route and reset like the first one
        if (core.role == TlsRole.Client && grouped) core.cids.generator = { r -> route.newCid(r, client = true) }
        if (core.role == TlsRole.Server) {
            val cids = core.cids
            // an unroutable ID never goes out in a NEW_CONNECTION_ID (draft-ietf-quic-load-balancers-21 section 3.2: one ID
            // over the life of the connection): once the nonces are spent the connection stops handing out IDs
            // plaintext IDs only one per configuration change (section 9): the change's own NEW_CONNECTION_ID brings it
            // ([reissueSource]), so the replacements of a connection that had the full set stop here
            cids.generator = { r ->
                val i = route.issue(r, client = false)
                when {
                    i.issuance == CidIssuance.SingleNoMigration && cids.localCount > 0 -> {
                        if (!i.temporary) cids.stopIssuing() // spent; a reservation not stored skips this one only
                        null
                    }

                    i.issuance == CidIssuance.Single && cids.localCount > 0 -> {
                        cids.limitToSingle()
                        null
                    }

                    else -> {
                        i.cid
                    }
                }
            }
            // a configuration change: the mode follows the ID it actually makes (section 9: plaintext, one per change)
            cids.reissueSource = { r ->
                val i = route.issue(r, client = false)
                when (i.issuance) {
                    CidIssuance.Full -> {
                        cids.allowMultiple()
                        i.cid
                    }

                    CidIssuance.Single -> {
                        cids.limitToSingle()
                        i.cid
                    }

                    CidIssuance.SingleNoMigration -> {
                        if (i.temporary) {
                            cids.keepReissuePending()
                            reissueRetry += core
                        } else {
                            cids.stopIssuing()
                        }
                        null
                    }
                }
            }
            when (issuance) {
                CidIssuance.Full -> {}

                CidIssuance.Single -> {
                    cids.limitToSingle()
                }

                CidIssuance.SingleNoMigration -> {
                    cids.limitToSingle()
                    core.unroutableCid = true
                }
            }
        }
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
    internal val byRemote = HashMap<AddressClass.AddrKey, ArrayList<ConnectionCore>>()

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

    /** The preferred-address sockets failed ([io.kuicksilver.quic.runtime.EndpointLoop]): new connections no longer get the offer. */
    internal var preferredDown = false
    internal var preferredAddressFailures = 0L

    /** Datagrams that arrived for the preferred address after it went down (forwarded by another loop before it knew): dropped. */
    internal var droppedPreferredDown = 0L

    internal var ptbAccepted = 0L
    internal var ptbIgnored = 0L
    private var ptbWindowStart = TimeMark.NEVER
    private var ptbInWindow = 0

    /**
     * An ICMP Packet Too Big the socket [socket] reported (RFC 8899 section 4.6, RFC 9000 section 14.2.1; threat-model 3.16): [quote]
     * holds the first [len] bytes of the datagram the message says was too large, [to] where it went, [mtu] the IP packet size the
     * message reports. ICMP is spoofable, so it is a hint only: at most [PTB_PER_SECOND] a second are looked at, the UDP payload left
     * by [mtu] must be at least 1200 bytes, and the connection to [to] must recognise the quote as one of its packets on its active
     * path ([acceptPacketTooBig]). Counted in `EndpointStats.ptbAccepted` / `ptbIgnored`.
     */
    internal fun handlePacketTooBig(
        quote: ByteArray,
        len: Int,
        to: InetSocketAddress,
        mtu: Int,
        now: TimeMark,
        socket: PathId,
    ) {
        if (ptbWindowStart == TimeMark.NEVER || now - ptbWindowStart >= 1.seconds) {
            ptbWindowStart = now
            ptbInWindow = 0
        }
        if (++ptbInWindow > PTB_PER_SECOND) {
            ptbIgnored++
            return
        }
        val payload = mtu - if (AddressClass.ipBytes(to).size == 4) 28 else 48 // IPv4 + UDP headers, IPv6 + UDP headers
        if (payload < 1200 || len <= 0 || len > quote.size) { // below QUIC's minimum: "MUST ignore" (RFC 9000 section 14.2.1)
            ptbIgnored++
            return
        }
        val l = byRemote[AddressClass.addrKey(to)]
        if (l != null) {
            for (i in l.indices) {
                val c = l[i]
                if (c.acceptPacketTooBig(quote, len, to, payload, socket)) {
                    ptbAccepted++
                    markDirty(c)
                    return
                }
            }
        }
        ptbIgnored++
    }

    /** The connection to [from] whose peer token ends the datagram (a Stateless Reset, RFC 9000 section 10.3.1), or null. */
    private fun statelessResetFor(
        data: PacketBuffer,
        length: Int,
        from: InetSocketAddress,
        now: TimeMark,
    ): ConnectionCore? {
        resetCandidatesExaminedForTest = 0
        if (length < StatelessReset.MIN_SIZE) return null
        val l =
            byRemote[AddressClass.addrKey(from)] ?: return null
        for (i in l.indices) {
            val c = l[i]
            resetCandidatesExaminedForTest++
            if (c.checkStatelessReset(data, length, now)) {
                markDirty(c)
                return c
            }
        }
        return null
    }

    /**
     * The loop that owns the connection a datagram belongs to, from its DCID in our format ([CidRoute.ownerLoop]: the routing
     * byte, or with a QUIC-LB configuration the loop the ID hashes to), or -1: Version Negotiation, a client endpoint, a DCID
     * not in our format, or a long header naming this loop or no loop of the group (an Initial is then admitted where it lands). The endpoint runtime forwards a datagram whose owner is another
     * loop: a flow the kernel hashed onto this socket after a rebind, or the answer to a group's client connection ([connect]),
     * which the kernel hashes onto any loop's socket from the first Initial on.
     */
    public fun ownerLoop(
        data: PacketBuffer,
        length: Int,
    ): Int {
        if (config.server == null || !PacketHeaderCodec.parse(data, 0, length, cidLength, hv) || hv.isVersionNegotiation) return -1
        val owner = route.ownerLoop(data, hv.dcidOff, hv.dcidLen)
        if (hv.type != PacketType.OneRtt) return if (routedElsewhere(owner)) owner else -1
        return owner
    }

    /** In a group, connection IDs of client connections carry the routing byte too ([connect]), not only those of server connections. */
    private val grouped: Boolean get() = config.loops > 1

    /**
     * The parsed long-header DCID is in our format and names another existing loop of the group: one of its client
     * connections (the server's Initial, Handshake or Retry hashed onto this socket), or a new client whose DCID names it
     * (its retransmits name it too, so it is admitted there consistently). One naming no loop is admitted where it lands.
     */
    private fun routedElsewhere(owner: Int): Boolean = grouped && owner >= 0 && owner != loopIndex && owner < config.loops

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
    ): ConnectionCore? = handleDatagram(data, length, from, ecn, now, socket, null)

    /**
     * [handleDatagram] with [local], the address of ours the datagram was sent to ([PacketBatch.localAddress]; null when the socket
     * cannot tell). A server keeps it as the local end of the path the datagram opens or belongs to (RFC 9000 section 9: a path is
     * the 4-tuple) and sends that path's datagrams, and any stateless answer to this one, from it: on a wildcard bind of a
     * multi-address host, a VIP or behind IPVS-DR the client hears back from the address it sent to.
     */
    @ExperimentalKuicksilverApi
    public fun handleDatagram(
        data: PacketBuffer,
        length: Int,
        from: InetSocketAddress,
        ecn: Ecn,
        now: TimeMark,
        socket: PathId,
        local: InetSocketAddress?,
    ): ConnectionCore? {
        rxLocal = local
        if (!PacketHeaderCodec.parse(data, 0, length, cidLength, hv)) {
            // RFC 9000 section 10.3: a reset may come in another version's long header that v1 cannot parse
            statelessResetFor(data, length, from, now)?.let { return it }
            droppedUndecryptable++
            return null
        }
        if (hv.isVersionNegotiation && config.server != null) {
            droppedStateless++
            return null
        } // a server never acts on Version Negotiation
        registry.lookup(data, hv.dcidOff, hv.dcidLen)?.let {
            deliver(it, data, length, from, ecn, now, socket)
            return it
        }
        // the preferred socket serves connections only: no new connection, no stateless answer (RFC 9000 section 9.6)
        if (socket == PREFERRED_SOCKET) {
            droppedStateless++
            return null
        }
        if (hv.isVersionNegotiation) {
            connections.firstOrNull { it.odcid.contentEquals(data, hv.scidOff, hv.scidLen) }?.let {
                deliver(it, data, length, from, ecn, now)
                return it
            }
            droppedStateless++
            return null
        }
        // RFC 9000 section 10.3: an unknown DCID is either a Stateless Reset for one of our connections to that peer (any header
        // form: "endpoints MUST treat any packet ending in a valid stateless reset token as a Stateless Reset"), or, in a short
        // header, a reason to send one
        statelessResetFor(data, length, from, now)?.let { return it }
        if (hv.type != PacketType.OneRtt && grouped && routedElsewhere(route.ownerLoop(data, hv.dcidOff, hv.dcidLen))) {
            return null
        } // another loop's: the group forwards it (ownerLoop)
        if (hv.type == PacketType.OneRtt) {
            // only for an ID this loop issued (threat-model 3.4); with QUIC-LB also our server ID under the current or previous
            // configuration, which decrypts: only while the reset limit would let the answer out, and within a budget of
            // decryptions of its own (per address and in total, a second)
            if (config.server != null && length > StatelessReset.MIN_SIZE && route.resetCandidate(data, hv.dcidOff, hv.dcidLen)) {
                val gate =
                    if (limiter.wouldAllow(from, now)) {
                        route.mayReset(data, hv.dcidOff, hv.dcidLen) { decryptLimiter.allow(from, now) }
                    } else {
                        ResetGate.RateLimited
                    }
                if (gate == ResetGate.RateLimited || (gate == ResetGate.Yes && !limiter.allow(from, now))) {
                    statelessRateLimited++
                    droppedStateless++
                    return null
                }
                if (gate == ResetGate.Yes) {
                    val token = ByteArray(16)
                    resetKey.token(data, hv.dcidOff, hv.dcidLen, token, 0)
                    val n = StatelessReset.write(vnBuffer, token, length, random)
                    if (n > 0) {
                        val bytes = ByteArray(n)
                        vnBuffer.copyTo(bytes, 0, 0, n)
                        stateless += Stateless(bytes, from, rxLocal)
                        statelessResets++
                        return null
                    }
                }
            }
            if (!foreignCid(data)) droppedStateless++
            return null
        }
        val server =
            config.server ?: run {
                droppedStateless++
                return null
            }
        if (hv.type == PacketType.ZeroRtt && serverEarly != null && !hv.unsupportedVersion) {
            bufferEarly(data, length, from, ecn, now)
            return null
        } // its Initial may still wait in the admission queue, or be reordered behind it (RFC 9000 section 17.2.3)
        // ---- cheap checks before anything is remembered about this datagram (threat-model 3.2) ----
        if (length < 1200) {
            droppedStateless++
            return null
        }
        if (hv.unsupportedVersion || VersionProfile.of(hv.version)?.let { it !in server.quic.versions } != false) {
            if (hv.type == PacketType.Initial ||
                hv.unsupportedVersion
            ) {
                queueVersionNegotiation(data, length, from, server.quic, now)
            } else {
                droppedStateless++
            }
            return null
        }
        if (hv.type != PacketType.Initial || hv.dcidLen < 8) {
            if (!foreignCid(data)) droppedStateless++
            return null
        }
        if (from.port == 0) {
            initialsDropped++
            droppedStateless++
            return null
        } // no socket answers port 0 and the kernel refuses the reply (EINVAL): a spoofed Initial must not cost a send
        if (config.rejectInitialFromReflectivePorts && AddressClass.isReflectivePort(from.port)) {
            initialsDropped++
            droppedStateless++
            return null
        } // threat-model 3.1: silence to a reflection source
        if (!queue!!.offer(data, length, from, ecn, now, rxLocal)) {
            initialsDropped++
            droppedQueue++
        } // the queue is bounded; overflow is a drop
        return null
    }

    /**
     * Decides up to [max] queued client Initials: a duplicate of a connection created meanwhile is routed to it;
     * a forged or expired Retry token is refused with INVALID_TOKEN; a full accept queue is refused with CONNECTION_REFUSED;
     * the hard limits `maxConnections` and `maxConnectionsPerIp` drop; then [QuicEndpointConfig.admission] decides. Returns the number of connections created.
     * The runtime calls it after every receive batch; what it leaves waits for the next one.
     */
    public fun processPending(
        now: TimeMark,
        max: Int = 64,
    ): Int {
        retryPendingReissues()
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
        val saved = rxLocal // the datagram being handled, if any, keeps its own local address after the drain
        try {
            while (n < max) {
                val e = q.poll() ?: break
                n++
                try {
                    rxLocal = e.local
                    if (admitOne(e, now, inflight, handshakeBuffer)) {
                        created++
                        inflight++
                    }
                } finally {
                    q.recycle(e)
                }
            }
        } finally {
            rxLocal = saved
        }
        return created
    }

    /** The parsed DCID is in our server format and owned by another loop: a group forwards it there, it is not dropped. */
    private fun foreignCid(data: PacketBuffer): Boolean =
        config.server != null && route.ownerLoop(data, hv.dcidOff, hv.dcidLen).let { it >= 0 && it != loopIndex }

    /** One connection's failure stays its own: an exception out of the core closes that connection, never the endpoint. */
    internal fun deliver(
        core: ConnectionCore,
        data: PacketBuffer,
        length: Int,
        from: InetSocketAddress,
        ecn: Ecn,
        now: TimeMark,
        socket: PathId = PathId.Initial,
        local: InetSocketAddress? = rxLocal,
    ) {
        markDirty(core)
        try {
            core.handleDatagram(data, length, from, ecn, now, socket, local)
        } catch (
            e: Throwable,
        ) {
            // sans-IO and not suspending: a CancellationException here came out of code the connection calls (a crypto provider)
            core.failInternal(e)
        }
    }

    private companion object {
        val EARLY_PENDING_TTL = kotlin.time.Duration.parse("100ms")
        const val EARLY_PENDING_IDS = 32
        const val EARLY_PENDING_PER_ID = 31

        /** Server addresses whose last RTT a client endpoint remembers. */
        const val RTT_MEMORY = 256

        /** ICMP Packet Too Big messages an endpoint looks at per second; the rest are only counted. */
        const val PTB_PER_SECOND = 64
    }

    private var tokensReleased = false
    private var lbReleased = false

    /** The QUIC-LB configuration change ([QuicLbState.generation]) this loop's connections were last moved to. */
    private var lbGeneration = 0L

    /** Server connections whose QUIC-LB configuration change waits for a nonce reservation that could not be stored. */
    private val reissueRetry = LinkedHashSet<ConnectionCore>()

    /**
     * Once per receive batch: the route's reservation may try a failed store again (at most one a batch), and the waiting
     * configuration changes go out once nonces are reserved; while none are, nothing is drawn for them.
     */
    private fun retryPendingReissues() {
        route.tick() // every loop: the back-off is scaled by the group's size, so a quiet loop 0 cannot stall the retries
        // a change this loop has not moved its connections to (the group's fan-out missed it): now (section 3.1)
        lb?.let { if (it.generation != lbGeneration) reissueForLoadBalancer() }
        if (reissueRetry.isEmpty() || !route.canIssueRoutable()) return
        val it = reissueRetry.iterator()
        while (it.hasNext()) {
            val c = it.next()
            if (!c.cids.retryPendingReissue()) it.remove() else continue
            markDirty(c)
        }
    }

    /**
     * The endpoint's QUIC-LB configuration changed ([QuicLbState.update] already ran): every server connection gets one ID of
     * the new configuration that retires all earlier ones (draft-ietf-quic-load-balancers-21 section 3.1), and hands out
     * replacements under it; plaintext configurations hand out no more than that one (section 9). With no configuration
     * (unroutable IDs) the connections keep the IDs they have and hand out no new ones (section 3.2). Loop thread only.
     */
    internal fun reissueForLoadBalancer() {
        val state = lb ?: return
        // once per committed change on this loop: the fan-out and the batch check may both come
        val generation = state.generation
        if (generation == lbGeneration) return
        lbGeneration = generation
        val current = state.routes.current
        for (i in connections.indices) {
            val c = connections[i]
            if (c.role != TlsRole.Server || c.state == ConnectionState.Closing || c.state == ConnectionState.Draining ||
                c.state == ConnectionState.Closed
            ) {
                continue
            }
            if (current == null) c.cids.stopIssuing() else c.cids.requestReissue()
            markDirty(c)
        }
    }

    /** [QuicLbState.commit] of a configuration prepared off the loop, then the connections move to it. Loop thread only. */
    internal fun commitLoadBalancer(p: QuicLbState.Prepared) {
        val state = lb ?: throw IllegalStateException("updateLoadBalancer needs an endpoint built with a loadBalancer")
        try {
            checkLoadBalancerUpdate(p.config)
        } catch (e: Throwable) {
            state.discard(p)
            throw e
        }
        if (state.commit(p)) reissueForLoadBalancer()
    }

    /** Test hook: runs between the admission's two looks at the nonce reservation (an unroutable Retry SCID). */
    internal var testBetweenRetryChecks: (() -> Unit)? = null

    /**
     * Sans IO, for an endpoint that is not one loop of a group (whose loops change together through
     * [QuicEndpoint.updateLoadBalancer]): new IDs use [config] at once, and every live server connection gets an ID of it that
     * retires the earlier ones ([QuicEndpoint.updateLoadBalancer] has the rules and the exceptions). Call it on the thread
     * that drives this endpoint, then flush ([dirtyConnections]).
     */
    @ExperimentalKuicksilverApi
    public fun updateLoadBalancer(config: QuicLbConfig?) {
        val state = lb ?: throw IllegalStateException("updateLoadBalancer needs an endpoint built with a loadBalancer")
        check(ownsLb) { "a loop group's endpoint cores change together: QuicEndpoint.updateLoadBalancer" }
        checkLoadBalancerUpdate(config)
        if (state.update(config)) reissueForLoadBalancer()
    }

    /** What every loop must agree on before a configuration change: the preferred address needs encrypted IDs (section 9). */
    internal fun checkLoadBalancerUpdate(config: QuicLbConfig?) {
        val state = lb ?: throw IllegalStateException("updateLoadBalancer needs an endpoint built with a loadBalancer")
        require(config == null || config.encrypted || this.config.server?.preferredAddress == null) {
            "a preferredAddress needs an encrypted loadBalancer configuration (draft-ietf-quic-load-balancers-21 section 9)"
        }
        state.validate(config)
    }

    /** Frees the queue, the stateless buffer and every connection's native resources. */
    public fun close() {
        // every release runs even when one before it threw; the first failure is rethrown at the end
        val r = Releaser()
        try {
            for (c in connections) r.release { c.release() }
        } finally {
            // the endpoint's own buffers and keys even when a connection's release failed
            connections.clear()
            accepted.clear()
            byRemote.clear() // with the lists above: nothing keeps a released connection reachable through a closed endpoint
            dirty.clear()
            earlyPending.clear()
            perIp.clear()
            registry.clear()
            r.release { vnBuffer.close() }
            r.release { resetKey.close() }
            r.release {
                val release = !tokensReleased
                tokensReleased = true
                if (release) addressTokens?.close() // one release per owner: a group's other loops may still use the keys
            }
            r.release { queue?.close() }
            r.release {
                val release = !lbReleased
                lbReleased = true
                if (release) lb?.close() // one release per owner, like the address tokens
            }
            r.finish()
        }
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
            out.setLocalAddress(i, s.from)
            i++
        }
        return i
    }

    /**
     * The final smoothed RTT of the last client connection to each server address that ended on this endpoint's socket (RFC 9002
     * section 6.2.2: a connection over the same network MAY start from the previous connection's smoothed RTT), used by [connect] as
     * the next connection's initial RTT; at most [RTT_MEMORY] addresses, the least recently stored dropped first.
     */
    private val rttMemory = LinkedHashMap<AddressClass.AddrKey, Duration>()

    private fun rememberRtt(core: ConnectionCore) {
        if (core.role != TlsRole.Client) return
        val p = core.paths.active
        // a migrated connection measured another network (a socket of its own): its RTT says nothing about this endpoint's path
        if (!p.rtt.hasSample || p.socket != PathId.Initial) return
        val key = AddressClass.addrKey(p.remote)
        rttMemory.remove(key)
        rttMemory[key] = p.rtt.smoothed.coerceIn(1.milliseconds, 10.seconds)
        if (rttMemory.size > RTT_MEMORY) rttMemory.remove(rttMemory.keys.first())
    }

    /** Forgets a closed connection, every ID that routed to it and its per-IP slot. */
    public fun remove(core: ConnectionCore) {
        rememberRtt(core)
        core.cids.forEachLocal { route.release(it) }
        reissueRetry.remove(core)
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
