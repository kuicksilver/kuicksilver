// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(ExperimentalKuicksilverApi::class, ExperimentalAtomicApi::class, InternalKuicksilverApi::class)

package io.kuicksilver.http3.connectudp

import io.ktor.network.sockets.InetSocketAddress
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.annotations.InternalKuicksilverApi
import io.kuicksilver.http3.CapsuleProtocol
import io.kuicksilver.http3.ConnectUdp
import io.kuicksilver.http3.Http3ErrorCode
import io.kuicksilver.http3.Http3Headers
import io.kuicksilver.http3.Http3ServerRequest
import io.kuicksilver.http3.PacketTooBigStatus
import io.kuicksilver.http3.UdpProxyConfig
import io.kuicksilver.http3.UdpProxyStats
import io.kuicksilver.http3.frame.VarInt
import io.kuicksilver.http3.message.DatagramFilter
import io.kuicksilver.http3.message.DatagramVerdict
import io.kuicksilver.http3.message.TemplateMatch
import io.kuicksilver.http3.message.UdpHost
import io.kuicksilver.http3.runtime.CapsuleStreamImpl
import io.kuicksilver.http3.runtime.Http3StreamImpl
import io.kuicksilver.quic.DatagramIo
import io.kuicksilver.quic.DatagramSendResult
import io.kuicksilver.quic.Ecn
import io.kuicksilver.quic.EmsgsizeReports
import io.kuicksilver.quic.IpFamily
import io.kuicksilver.quic.PacketBatch
import io.kuicksilver.quic.PacketTooBigSender
import io.kuicksilver.quic.QuicException
import io.kuicksilver.quic.UnreachableReports
import io.kuicksilver.quic.ipLiteral
import io.kuicksilver.quic.isRefusedAsTooLarge
import io.kuicksilver.quic.sameIpAs
import io.kuicksilver.quic.specificIpOrNull
import io.kuicksilver.quic.withUnmappedIp
import io.kuicksilver.tls.completedWithin
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineExceptionHandler
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.IO
import kotlinx.coroutines.Job
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull
import kotlin.concurrent.atomics.AtomicBoolean
import kotlin.concurrent.atomics.AtomicLong
import kotlin.concurrent.atomics.AtomicReference
import kotlin.concurrent.atomics.ExperimentalAtomicApi
import kotlin.concurrent.atomics.decrementAndFetch
import kotlin.concurrent.atomics.incrementAndFetch
import kotlin.time.Duration
import kotlin.time.Duration.Companion.minutes
import kotlin.time.Duration.Companion.nanoseconds
import kotlin.time.Duration.Companion.seconds
import kotlin.time.TimeSource

/** IPv4 (20) and UDP (8) headers: the largest unfragmented UDP payload on an IPv4 link is its MTU minus 28 (RFC 791, RFC 768). */
private const val IPV4_UDP_OVERHEAD = 28

/** IPv6 (40) and UDP (8) headers (RFC 8200, RFC 768). */
private const val IPV6_UDP_OVERHEAD = 48

/** The `proxy-status` field (RFC 9209). */
private const val PROXY_STATUS = "proxy-status"

/** The longest Context ID varint (RFC 9000 section 16): the capsule limit leaves room for it on top of the payload. */
private const val MAX_CONTEXT_ID = 8

/** Clients without tunnels a proxy keeps state for at most (the oldest go first). */
private const val MAX_IDLE_CLIENTS = 65_536

/** Socket factory calls running at once over a proxy; one more waits for a thread, within its `socketOpenTimeout`. */
private const val MAX_OPENING = 16

/** [UdpProxyImpl.openSocket]'s slot while the call runs, and once the waiter gave up on it. */
private val OPENING = Any()
private val GIVEN_UP = Any()

/** The socket factory did not return within `socketOpenTimeout`: that family failed for the request. */
internal class SocketOpenTimeoutException(
    timeout: Duration,
) : Exception("the socket factory did not return within $timeout")

/** The socket factory threw a CancellationException of its own (its own timeout): that family failed for the request. */
internal class SocketFactoryCancelledException(
    cause: CancellationException,
) : Exception("the socket factory threw a CancellationException of its own", cause)

/** Datagrams taken from a tunnel's socket per receive call. */
private const val RECEIVE_BATCH = 4

/** The proxy behind [io.kuicksilver.http3.UdpProxy]. */
internal class UdpProxyImpl(
    internal val config: UdpProxyConfig,
) {
    /** The clock of the rate limit and the idle timeout; tests take a TestTimeSource. */
    internal var clock: TimeSource = TimeSource.Monotonic

    /** Grows with every counter of [snapshot]: tests wait on it for a datagram to have been judged. */
    internal val changes = MutableStateFlow(0L)

    /** Counts one event in [c] and in [changes]. */
    internal fun count(c: AtomicLong) {
        c.incrementAndFetch()
        changes.update { it + 1 }
    }

    /** Tunnels open or being set up. */
    val active = MutableStateFlow(0)
    private val lock = Mutex()
    private val clients = HashMap<String, ClientState>()

    /** How long a client's state (its rate and its unanswered targets) outlives its last tunnel. */
    internal var clientRetention: Duration = 2.minutes
    private val epoch = TimeSource.Monotonic.markNow()

    private fun nowMs(): Long = epoch.elapsedNow().inWholeMilliseconds

    /** Tests: how often a tunnel looks for an ICMP unreachable its socket reported. */
    internal var unreachablePoll: Duration = 1.seconds

    /** Tests shorten the idle timeout below the two minutes [UdpProxyConfig] allows. */
    internal var idleTimeoutForTest: Duration? = null

    /** Tests: runs once the socket is open, before the request is answered. */
    internal var beforeAnswerForTest: (suspend (Http3ServerRequest) -> Unit)? = null

    /** Tests: runs as soon as the 2xx was handed to the stream, before anything is forwarded. */
    internal var answeredForTest: (() -> Unit)? = null

    /** How long ending a tunnel gracefully (its queued capsules, then FIN) may take before the stream is reset. */
    internal var closeTimeout: Duration = 5.seconds

    private val opened = AtomicLong(0)
    private val refused = AtomicLong(0)
    internal val toTargets = AtomicLong(0)
    internal val fromTargets = AtomicLong(0)
    internal val unknownContext = AtomicLong(0)
    internal val tooLargeForLink = AtomicLong(0)
    internal val refusedAsTooLarge = AtomicLong(0)
    internal val rateLimited = AtomicLong(0)
    internal val unanswered = AtomicLong(0)
    internal val foreignSource = AtomicLong(0)
    internal val tooLargeForClient = AtomicLong(0)
    internal val clientBusy = AtomicLong(0)
    internal val tooLargeFromTarget = AtomicLong(0)
    internal val closedUnreachable = AtomicLong(0)
    internal val ignoredUnreachable = AtomicLong(0)
    internal val packetTooBigSent = AtomicLong(0)
    internal val packetTooBigNoSource = AtomicLong(0)
    internal val packetTooBigFailed = AtomicLong(0)
    internal val socketFactoryUncaught = AtomicLong(0)

    /** RFC 9298 section 6.1: probed once, at the first tunnel (before its 2xx), when the configuration asks for it. */
    private val packetTooBig =
        AtomicReference(if (config.packetTooBig) PacketTooBigStatus.NotProbed else PacketTooBigStatus.Off)

    /** Tests replace the probe (a privileged one cannot be had on every host). */
    internal var probeForTest: (() -> PacketTooBigSender.Probe)? = null

    /** Tests replace the sender of a tunnel (a privileged one cannot be had on every host, and tests send to no one). */
    internal var senderForTest: (() -> PtbSink)? = null

    /** One probe at a time: tunnels set up together wait for the first one's probe instead of each running their own. */
    private val probeLock = Mutex()

    /**
     * Whether tunnels send Packet Too Big; probes once (opening and closing a raw socket) the first time it is asked, which
     * is the first tunnel's setup. Single-flight: a caller that comes while the probe runs waits for it and takes its result.
     */
    internal suspend fun packetTooBigAvailable(): Boolean {
        if (packetTooBig.load() == PacketTooBigStatus.NotProbed) {
            probeLock.withLock {
                if (packetTooBig.load() == PacketTooBigStatus.NotProbed) {
                    val p = (probeForTest ?: PacketTooBigSender::probe)()
                    packetTooBig.store(if (p.available) PacketTooBigStatus.Available else PacketTooBigStatus.Unavailable)
                }
            }
        }
        return packetTooBig.load() == PacketTooBigStatus.Available
    }

    /**
     * One sender for every tunnel (two raw sockets at most, one per family: Linux hands each ICMP message the host receives
     * to every raw ICMP socket, so a socket per tunnel would multiply that work), opened at the first message and closed
     * when the last tunnel ends; [ptbLock] serialises its use. Messages are limited per target address over all tunnels
     * ([PTB_RATE] a second, a burst of [PTB_BURST]; the [MAX_PTB_TARGETS] latest targets kept) and over the proxy
     * ([ptbTotalRate], burst [ptbTotalBurst]), RFC 4443 section 2.4 (f); each answers one dropped payload.
     */
    private val ptbLock = Mutex()
    private var ptbSink: PtbSink? = null
    private val ptbTargets = LinkedHashMap<String, TokenBucket>()

    /** Tests: the proxy-wide limit of Packet Too Big messages (a second, and the burst). */
    internal var ptbTotalRate: Int = PTB_TOTAL_RATE
    internal var ptbTotalBurst: Int = PTB_TOTAL_BURST
    private var ptbAll: TokenBucket? = null

    /** Tests: how many senders were opened. */
    internal val ptbSinksOpened = AtomicLong(0)

    /** What became of a Packet Too Big [sendPacketTooBig] was asked for. */
    internal enum class PtbOutcome { Sent, Unavailable, Limited, Failed }

    /** Sends the Packet Too Big for a payload [target] sent to [local]. */
    internal suspend fun sendPacketTooBig(
        target: InetSocketAddress,
        local: InetSocketAddress,
        payload: ByteArray,
        len: Int,
        mtu: Int,
    ): PtbOutcome {
        if (!packetTooBigAvailable()) return PtbOutcome.Unavailable
        return ptbLock.withLock {
            val key = target.ipLiteral()
            val bucket = ptbTargets.remove(key) ?: TokenBucket(PTB_RATE, PTB_BURST) { clockStart.elapsedNow().inWholeNanoseconds }
            ptbTargets[key] = bucket // the most recent last
            if (ptbTargets.size > MAX_PTB_TARGETS) ptbTargets.remove(ptbTargets.keys.first())
            val all = ptbAll ?: TokenBucket(ptbTotalRate, ptbTotalBurst) { clockStart.elapsedNow().inWholeNanoseconds }.also { ptbAll = it }
            if (!bucket.tryTake()) return@withLock PtbOutcome.Limited
            // the target's token goes back when the proxy's limit refuses: it was not spent on a message
            if (!all.tryTake()) {
                bucket.refund()
                return@withLock PtbOutcome.Limited
            }
            val sink =
                ptbSink ?: (senderForTest?.invoke() ?: RawPtbSink(PacketTooBigSender.create())).also {
                    ptbSink = it
                    ptbSinksOpened.incrementAndFetch()
                }
            // a message the sender refused (a family whose socket did not open, arguments it rules out, the kernel) is
            // counted; its tokens stay spent, so a sender that keeps failing is tried no faster than one that works
            if (sink.send(target, local, payload, len, mtu)) PtbOutcome.Sent else PtbOutcome.Failed
        }
    }

    fun snapshot(): UdpProxyStats =
        UdpProxyStats(
            opened.load(),
            refused.load(),
            toTargets.load(),
            fromTargets.load(),
            unknownContext.load(),
            tooLargeForLink.load(),
            refusedAsTooLarge.load(),
            rateLimited.load(),
            unanswered.load(),
            foreignSource.load(),
            tooLargeForClient.load(),
            clientBusy.load(),
            tooLargeFromTarget.load(),
            closedUnreachable.load(),
            ignoredUnreachable.load(),
            packetTooBig.load(),
            packetTooBigSent.load(),
            packetTooBigNoSource.load(),
            packetTooBigFailed.load(),
            socketFactoryUncaught.load(),
        )

    suspend fun serve(
        request: Http3ServerRequest,
        answered: (Int) -> Unit = {},
    ) {
        // section 3.4: an Extended CONNECT with :protocol connect-udp; anything else is not ours to serve
        if (!ConnectUdp.isConnectUdp(request)) return refuse(request, answered, 400, "http_request_error")
        val target =
            when (val m = config.template.match(request.path.orEmpty())) {
                is TemplateMatch.NoMatch -> return refuse(request, answered, 404, null)
                is TemplateMatch.Invalid -> return refuse(request, answered, 400, "http_request_error")
                is TemplateMatch.Target -> m
            }
        if (config.requireCapsuleProtocolField && !CapsuleProtocol.isEnabled(request.headers)) {
            return refuse(request, answered, 400, "http_request_error")
        }
        val client = clientKey(request.remoteAddress, config.clientIpv6Prefix)
        val state =
            when (val r = reserve(client)) {
                is ClientState -> r
                else -> return refuse(request, answered, r as Int, "connection_limit_reached")
            }
        try {
            open(request, target, answered, state)
        } catch (e: CancellationException) {
            // a request the cancelled call leaves unanswered would hold its stream until the connection ends
            request.reset(Http3ErrorCode.REQUEST_CANCELLED)
            throw e
        } finally {
            withContext(NonCancellable) { release(client) }
        }
    }

    /**
     * The factory's calls, on a `Dispatchers.IO.limitedParallelism(MAX_OPENING)` view of this proxy's own: a call that
     * blocks its thread holds one of its [MAX_OPENING] threads, never a thread of the request's dispatcher. Such a view is
     * not counted against `Dispatchers.IO`'s 64 threads, so each proxy may add up to [MAX_OPENING] threads of its own; a
     * call given up on keeps its thread until it returns. The handler guards a case that should not be reachable:
     * [openSocket] catches the factory's throws and a late socket's `close`, so nothing should escape a call. If something
     * ever does, it is counted in [UdpProxyStats.socketFactoryUncaught] (and kept in [uncaughtInOpening] for tests) rather
     * than handed to the platform's handler, which ends the process on Android and Kotlin/Native.
     */
    @OptIn(ExperimentalCoroutinesApi::class)
    private val opening =
        CoroutineScope(
            SupervisorJob() + Dispatchers.IO.limitedParallelism(MAX_OPENING) +
                CoroutineExceptionHandler { _, e ->
                    uncaughtInOpening.store(e)
                    count(socketFactoryUncaught)
                },
        )

    /** The last throwable that escaped a factory call of [opening] (tests: null when none did). */
    internal val uncaughtInOpening = AtomicReference<Throwable?>(null)

    /** Factory calls of [opening] not finished yet, given up on or not (tests wait for 0). */
    internal val openingCallsForTest: Int get() = opening.coroutineContext[Job]!!.children.count()

    /** Closes a socket no one owns any more; a throwing `close` is no reason to fail anything else. */
    private fun closeUnowned(io: DatagramIo?) {
        if (io != null) runCatching { io.close() }
    }

    /**
     * [UdpProxyConfig.socketFactory]'s socket on [bind], bounded by [UdpProxyConfig.socketOpenTimeout]: the call runs in
     * [opening] and this waits for it at most that long, then throws [SocketOpenTimeoutException] (the family failed).
     * Ownership is decided once in `slot`: the call stores its outcome there unless the waiter gave up first, and then
     * closes the socket itself; a waiter that gives up (the deadline, or its own cancellation) cancels a call still running
     * and closes a socket that came as it gave up. A socket is never both handed over and closed, nor left open.
     */
    private suspend fun openSocket(bind: InetSocketAddress): DatagramIo {
        val slot = AtomicReference(OPENING)
        val call =
            opening.launch {
                // the socket, or what the factory threw
                val outcome: Any =
                    try {
                        config.socketFactory(bind)
                    } catch (e: Throwable) {
                        e
                    }
                if (!slot.compareAndSet(OPENING, outcome)) closeUnowned(outcome as? DatagramIo) // the waiter gave up: no one owns it
            }

        fun giveUp() {
            // the cancellation the waiter rethrows stays the exception: a throwing close does not replace it
            if (slot.compareAndSet(OPENING, GIVEN_UP)) call.cancel() else closeUnowned(slot.load() as? DatagramIo)
        }
        try {
            withTimeoutOrNull(config.socketOpenTimeout) { call.join() } // only waits: the outcome is kept in slot
        } catch (e: CancellationException) {
            giveUp()
            throw e
        }
        if (slot.compareAndSet(OPENING, GIVEN_UP)) {
            call.cancel()
            throw SocketOpenTimeoutException(config.socketOpenTimeout)
        }
        // the outcome, also one stored as the deadline fired: a socket that came in time is the request's
        return when (val outcome = slot.load()) {
            // the factory's own cancellation (its withTimeout, say), not the request's: the call is never cancelled
            // while slot is OPENING, so this is a family that failed to open, not a request to stop serving
            is CancellationException -> throw SocketFactoryCancelledException(outcome)

            is Throwable -> throw outcome

            else -> outcome as DatagramIo
        }
    }

    /** Resolves, filters, opens the socket, answers and relays. */
    private suspend fun open(
        request: Http3ServerRequest,
        target: TemplateMatch.Target,
        answered: (Int) -> Unit,
        client: ClientState,
    ) {
        val candidates =
            when (val h = target.host) {
                is UdpHost.Ipv4 -> {
                    listOf(h.bytes)
                }

                is UdpHost.Ipv6 -> {
                    listOf(h.bytes)
                }

                is UdpHost.Name -> {
                    // section 3.1: "the UDP proxy MUST perform DNS resolution before replying to the HTTP request", and
                    // on an error "MUST reject the request and SHOULD send details using an appropriate Proxy-Status"
                    // completedWithin: an answer that came as the deadline fired is the answer, not a timeout
                    val r =
                        completedWithin(config.resolveTimeout) {
                            try {
                                Result.success(resolve(h.name, client))
                            } catch (e: CancellationException) {
                                throw e
                            } catch (e: Throwable) {
                                Result.failure(e)
                            }
                        } ?: return refuse(request, answered, 504, "dns_timeout")
                    if (r.exceptionOrNull() is ResolverBusyException) return refuse(request, answered, 503, "dns_error")
                    val list = r.getOrNull() ?: return refuse(request, answered, 502, "dns_error")
                    list.filter { it.size == 4 || it.size == 16 }.ifEmpty { return refuse(request, answered, 502, "dns_error") }
                }
            }
        // section 7: "the UDP proxy's own addresses" are refused (the address this request's connection reached, the
        // listener's own), then the filter sees every address; the socket sends to the one it allowed, never a later answer
        val own =
            if (config.refuseOwnAddresses) {
                (request as? io.kuicksilver.http3.runtime.ServerRequestImpl)
                    ?.connectionOwnAddresses
                    ?.mapNotNull { UdpHost.parse(it.ipLiteral().substringBefore('%')) }
                    ?.map { if (it is UdpHost.Ipv4) it.bytes else (it as UdpHost.Ipv6).bytes }
                    ?.map(::canonical)
                    .orEmpty()
            } else {
                emptyList()
            }
        val allowed =
            candidates
                .map(::unmapped)
                .filter { a -> own.none { it.contentEquals(canonical(a)) } && config.targetFilter.allows(target.host.text, a, target.port) }
                .ifEmpty { return refuse(request, answered, 403, "destination_ip_prohibited") }
        // RFC 9298 section 3.1: "UDP proxies MUST NOT introduce fragmentation at the IP layer"; a socket without DF towards
        // the target's family could (after an ICMP message lowered its cached path MTU): no DF, no tunnel. So the candidates
        // of a family with DF come first (in their order), a family found without DF (cached for this proxy) is skipped, and
        // only when no candidate of a family with DF is left is the request refused
        var address: ByteArray? = null
        var io: OnceClosed? = null
        val lacking = LinkedHashSet<IpFamily>() // the families found without DF for this request, for the refusal's details
        val failed = HashSet<IpFamily>() // the families whose socket failed to open for another reason in this request
        var timedOut = false // one of them did not open within socketOpenTimeout (the refusal's details say so)
        for (a in allowed.sortedBy { if (familyOf(it) in noDfFamilies) 1 else 0 }) {
            val family = familyOf(a)
            if (family in noDfFamilies) {
                lacking += family
                continue
            }
            if (family in lacking || family in failed) continue // already tried in this request (not cached: maybe transient)
            val opened =
                try {
                    OnceClosed(openSocket(InetSocketAddress(if (family == IpFamily.V4) "0.0.0.0" else "::", 0)))
                } catch (e: CancellationException) {
                    throw e
                } catch (e: QuicException.DontFragmentUnavailable) {
                    // remembered only when it holds for good (no ksl below JDK 19, both DF modes refused); a refusal that may
                    // pass next time (the accelerated socket could not open, out of descriptors) fails this request only
                    if (e.permanent) learnNoDf(family)
                    lacking += family
                    continue
                } catch (e: Throwable) {
                    // the other family's socket may still open (also after a factory given up on at socketOpenTimeout):
                    // 502 only when no candidate did
                    if (e is SocketOpenTimeoutException) timedOut = true
                    failed += family
                    continue
                }
            // only the family the socket was opened for counts: an AF_INET socket reports IPv6 as without DF because it
            // cannot reach IPv6 at all, which says nothing about an IPv6 socket
            if (opened.io.noDontFragmentFamily == family) {
                learnNoDf(family)
                lacking += family
                opened.close()
                continue
            }
            address = a
            io = opened
            break
        }
        if (address == null || io == null) {
            if (failed.isNotEmpty()) {
                // RFC 9209 section 2.1.6 details: a socket that did not open in time says so (no error type of its own)
                return refuse(request, answered, 502, "proxy_internal_error", if (timedOut) "socket open timed out" else null)
            }
            return refuseNoDf(request, answered, lacking.joinToString(" or ") { it.label })
        }
        val v4 = address.size == 4
        val targetAddress = InetSocketAddress((if (v4) UdpHost.Ipv4(address) else UdpHost.Ipv6(address)).text, target.port)
        try {
            // section 6.2: "it MUST set the ECN bits to Not-ECT on UDP packets it sends to the target"
            io.io.disableEcnMarking()
            val payloadLimit = config.linkMtu - if (v4) IPV4_UDP_OVERHEAD else IPV6_UDP_OVERHEAD
            // section 6.1: the privilege is probed at the first tunnel, before its 2xx, so once a client holds a tunnel
            // UdpProxyStats.packetTooBig says whether Packet Too Big applies (not only after a payload was dropped)
            packetTooBigAvailable()
            beforeAnswerForTest?.invoke(request)
            val stream =
                try {
                    request.acceptConnect(Http3Headers(listOf(CapsuleProtocol.Enabled)))
                } catch (e: CancellationException) {
                    throw e
                } catch (e: Throwable) {
                    count(refused)
                    // a request that rules capsules out was answered 400 (RFC 9297 section 3.2); a stream already gone needs nothing
                    if (e is io.kuicksilver.http3.Http3Exception.MessageError) answered(400)
                    return
                }
            answered(200)
            answeredForTest?.invoke()
            val impl = stream as Http3StreamImpl
            val filter =
                DatagramFilter { ctx, len ->
                    when {
                        ctx != 0L -> DatagramVerdict.Skip.also { count(unknownContext) }

                        // section 5: "An endpoint that receives an HTTP Datagram using Context ID zero whose UDP Proxying
                        // Payload field is longer than 65527 MUST abort the corresponding stream"
                        len > ConnectUdp.MAX_UDP_PAYLOAD -> DatagramVerdict.Abort

                        // section 5: what the link cannot carry is discarded, a DATAGRAM capsule "without buffering"
                        len > payloadLimit -> DatagramVerdict.Skip.also { count(tooLargeForLink) }

                        else -> DatagramVerdict.Deliver
                    }
                }
            val capsules =
                try {
                    impl.useCapsuleProtocol(connectUdpCapsules(payloadLimit + MAX_CONTEXT_ID), filter)
                } catch (e: CancellationException) {
                    throw e
                } catch (_: Throwable) {
                    count(refused)
                    return // the client's message broke RFC 9297 section 3.2: the stream was reset with H3_MESSAGE_ERROR
                }
            count(opened)
            val answer = lock.withLock { client.answerFor(targetAddress) }
            ProxyTunnel(this, impl, capsules, io, targetAddress, config.linkMtu, clock, client, answer)
                .run(idleTimeoutForTest ?: config.idleTimeout)
        } finally {
            io.close()
        }
    }

    /**
     * The address families this proxy's target sockets have no Don't Fragment for, as learned from the sockets it
     * opened (a factory that threw [QuicException.DontFragmentUnavailable], or a socket's
     * [DatagramIo.noDontFragmentFamily]): a host's DF support does not change while it runs, so later requests skip
     * those candidates without opening a socket.
     */
    @kotlin.concurrent.Volatile
    private var noDfFamilies: Set<IpFamily> = emptySet()

    private fun learnNoDf(family: IpFamily) {
        if (family !in noDfFamilies) noDfFamilies = noDfFamilies + family
    }

    /** The family of an address of 4 or 16 bytes (an IPv4-mapped one is already unmapped to its 4). */
    private fun familyOf(a: ByteArray): IpFamily = if (a.size == 4) IpFamily.V4 else IpFamily.V6

    /**
     * The target's address family has no Don't Fragment on this host, so a tunnel could fragment (RFC 9298 section 3.1:
     * "UDP proxies MUST NOT introduce fragmentation at the IP layer"): 500 with `proxy_configuration_error` (RFC 9209
     * section 2.3.24: "The intermediary encountered an error regarding its configuration", recommended status 500) and the
     * reason in `details` (section 2.1.6).
     */
    private suspend fun refuseNoDf(
        request: Http3ServerRequest,
        answered: (Int) -> Unit,
        family: String,
    ) {
        refuse(request, answered, 500, "proxy_configuration_error", "no Don't Fragment for $family targets on this host")
    }

    /**
     * Answers [status] with `proxy-status: <name>; error=<error>` when [error] is given (RFC 9209 section 2), and
     * `; details="<details>"` (a quoted string, section 2.1.6) when [details] is.
     */
    private suspend fun refuse(
        request: Http3ServerRequest,
        answered: (Int) -> Unit,
        status: Int,
        error: String?,
        details: String? = null,
    ) {
        count(refused)
        val fields =
            if (error == null) {
                emptyList()
            } else {
                listOf(PROXY_STATUS to "${config.proxyName}; error=$error" + (details?.let { "; details=\"$it\"" } ?: ""))
            }
        try {
            request.respond(status, Http3Headers(fields)).finish()
            answered(status)
        } catch (e: CancellationException) {
            throw e
        } catch (_: Throwable) {
            request.reset(Http3ErrorCode.REQUEST_CANCELLED) // the stream failed meanwhile: it is over either way
        }
    }

    /**
     * [host]'s addresses from the configured resolver, [SystemResolver.MAX_PER_CLIENT] lookups of one client at once: the
     * system one counts a lookup until its blocking call returns, another resolver until its call does.
     */
    private suspend fun resolve(
        host: String,
        client: ClientState,
    ): List<ByteArray> {
        if (config.resolver === io.kuicksilver.http3.UdpProxyResolver.System) return SystemResolver.resolveFor(host, client.lookups)
        if (client.lookups.incrementAndFetch() > SystemResolver.MAX_PER_CLIENT) {
            client.lookups.decrementAndFetch()
            throw ResolverBusyException()
        }
        try {
            return config.resolver.resolve(host)
        } finally {
            client.lookups.decrementAndFetch()
        }
    }

    /** Takes a slot for [client]: its [ClientState], or the status that refuses the request (an Int). */
    private suspend fun reserve(client: String): Any =
        lock.withLock {
            forgetIdleClients()
            if (active.value >= config.maxTunnels) return@withLock 503
            val st =
                clients.getOrPut(client) {
                    ClientState(
                        SharedTokenBucket(config.clientPacketRate, config.clientPacketBurst) { clockStart.elapsedNow().inWholeNanoseconds },
                    )
                }
            if (st.tunnels >= config.maxTunnelsPerClient) return@withLock 429
            st.tunnels++
            active.value += 1
            st
        }

    private suspend fun release(client: String) {
        lock.withLock {
            clients[client]?.let {
                it.tunnels--
                if (it.tunnels <= 0) it.idleSince = nowMs()
            }
            // the last tunnel closes the Packet Too Big sender (lock order: lock, then ptbLock; a send takes ptbLock only)
            if (active.value == 1) {
                ptbLock.withLock {
                    ptbSink?.close()
                    ptbSink = null
                }
            }
            active.value -= 1
        }
    }

    /** Drops clients without tunnels for [clientRetention], and the oldest idle ones beyond [MAX_IDLE_CLIENTS]; under [lock]. */
    private fun forgetIdleClients() {
        val now = nowMs()
        val keep = clientRetention.inWholeMilliseconds
        val it = clients.entries.iterator()
        var idle = 0
        while (it.hasNext()) {
            val e = it.next().value
            if (e.tunnels > 0) continue
            if (now - e.idleSince >= keep) it.remove() else idle++
        }
        if (idle > MAX_IDLE_CLIENTS) {
            clients.entries
                .filter { it.value.tunnels <= 0 }
                .sortedBy { it.value.idleSince }
                .take(idle - MAX_IDLE_CLIENTS)
                .forEach { clients.remove(it.key) }
        }
    }

    /** Nanoseconds of [clock] since this proxy started, for the client buckets (TestTimeSource in tests). */
    private val clockStart by lazy { clock.markNow() }

    /** The IPv4 address an IPv6 one is delivered to (mapped, NAT64, 6to4: `UdpAddressClass.embeddedV4`), else the address. */
    private fun canonical(a: ByteArray): ByteArray =
        io.kuicksilver.http3.message.UdpAddressClass
            .embeddedV4(a) ?: a

    /** An IPv4-mapped IPv6 address (`::ffff:0:0/96`) as its IPv4 address: it is one, and an IPv4 socket sends to it. */
    private fun unmapped(a: ByteArray): ByteArray {
        if (a.size != 16) return a
        for (i in 0 until 10) if (a[i] != 0.toByte()) return a
        if (a[10] != 0xff.toByte() || a[11] != 0xff.toByte()) return a
        return a.copyOfRange(12, 16)
    }
}

/** Why a tunnel ended. */
private enum class End { ClientFin, ClientGone, SocketFailed, Idle, Unreachable }

/** One open tunnel: client datagrams to the target and back, until [End]. */
private class ProxyTunnel(
    private val proxy: UdpProxyImpl,
    private val impl: Http3StreamImpl,
    private val capsules: CapsuleStreamImpl,
    private val io: OnceClosed,
    private val target: InetSocketAddress,
    private val linkMtu: Int,
    clock: TimeSource,
    private val client: ClientState,
    private val answer: TargetAnswer,
) {
    private val config = proxy.config
    private val start = clock.markNow()
    private val lastActivity = AtomicLong(0)

    // one byte more than the link carries: a datagram that fills the slot was larger, and is dropped, not forwarded cut
    private val receiveSlot = linkMtu + 1
    private val bucket = TokenBucket(config.packetRate, config.packetBurst) { start.elapsedNow().inWholeNanoseconds }

    // what was sent lately, for the check of an ICMP unreachable; only on a socket that reports them
    private val sent: SentPrefixes? = if (io.io is UnreachableReports) SentPrefixes() else null
    private val sendBatch = PacketBatch(1, linkMtu)
    private val receiveBatch = PacketBatch(RECEIVE_BATCH, receiveSlot)

    private fun now(): Long = start.elapsedNow().inWholeNanoseconds

    private fun touch() {
        lastActivity.store(now())
    }

    suspend fun run(idleTimeout: Duration) {
        val end = CompletableDeferred<End>()
        var why: End? = null
        try {
            coroutineScope {
                val jobs =
                    listOf(
                        // the client's side: FIN on a capsule boundary ends the flow, a reset or a lost connection fails it
                        launch {
                            try {
                                capsules.capsules.collect { }
                                end.complete(End.ClientFin)
                            } catch (e: CancellationException) {
                                throw e
                            } catch (_: Throwable) {
                                end.complete(End.ClientGone)
                            }
                        },
                        launch {
                            try {
                                capsules.datagrams.collect { up(it) }
                            } catch (e: CancellationException) {
                                throw e
                            } catch (_: Throwable) {
                                end.complete(End.SocketFailed)
                            }
                        },
                        launch {
                            try {
                                down()
                            } catch (e: CancellationException) {
                                throw e
                            } catch (_: Throwable) {
                                end.complete(End.SocketFailed)
                            }
                        },
                        launch {
                            idle(idleTimeout)
                            end.complete(End.Idle)
                        },
                        launch {
                            if (unreachable()) end.complete(End.Unreachable)
                        },
                    )
                why = end.await()
                // closed first: a receive blocked in the socket returns, so the cancelled readers end promptly
                io.close()
                jobs.forEach { it.cancel() }
            }
        } finally {
            io.close()
            withContext(NonCancellable) { finish(why) }
            // every coroutine that used them has ended with the scope
            sendBatch.close()
            receiveBatch.close()
        }
    }

    /** Ends the request stream (section 3.1: the socket and the stream close together). */
    private suspend fun finish(why: End?) {
        when (why) {
            End.ClientFin, End.Idle -> {
                // completedWithin: a close that finished as the bound fires is not followed by a reset
                val done = completedWithin(proxy.closeTimeout) { runCatching { capsules.close() } }
                if (done == null) impl.reset(Http3ErrorCode.CONNECT_ERROR)
                if (why == End.Idle) impl.stopSending(Http3ErrorCode.NO_ERROR)
            }

            End.ClientGone -> {
                impl.reset(Http3ErrorCode.CONNECT_ERROR)
            }

            // "If a UDP proxy is notified by its operating system that its socket is no longer usable, it MUST close the
            // request stream"; also a cancelled serve()
            End.SocketFailed, End.Unreachable, null -> {
                impl.reset(Http3ErrorCode.CONNECT_ERROR)
                impl.stopSending(Http3ErrorCode.CONNECT_ERROR)
            }
        }
    }

    /**
     * RFC 9298 section 3.1: "If a UDP proxy is notified by its operating system that its socket is no longer usable, it
     * MUST close the request stream", for example on "an ICMP Destination Unreachable message". The accelerated socket on
     * Linux and Android reports port and host unreachable for the datagrams it sent (its error queue). An off-path sender
     * can forge them, guessing only the socket's port, so a report ends the tunnel only when it is a port unreachable for
     * this tunnel's target address and port whose quote carries the start of a payload the tunnel sent lately (RFC 8085
     * section 5.2). A host unreachable (often transient, a route that comes back) and a report quoting the headers only are
     * ignored and counted. Polled every [UdpProxyImpl.unreachablePoll]; true when one ends the tunnel. Other sockets report
     * none: an unconnected socket is told nothing on Apple platforms, Windows and the portable sockets.
     */
    private suspend fun unreachable(): Boolean {
        val reports = io.io as? UnreachableReports ?: return false
        val sent = sent ?: return false
        while (true) {
            delay(proxy.unreachablePoll)
            while (true) {
                val r = reports.takeUnreachable() ?: break
                if (r.destination.sameIpAs(target) && r.destination.port == target.port && r.port && sent.matches(r.quote)) {
                    proxy.count(proxy.closedUnreachable)
                    return true
                }
                proxy.count(proxy.ignoredUnreachable)
            }
        }
    }

    private suspend fun idle(timeout: Duration) {
        val limit = timeout.inWholeNanoseconds
        touch()
        while (true) {
            val left = limit - (now() - lastActivity.load())
            if (left <= 0) return
            delay(left.nanoseconds)
        }
    }

    /** One HTTP datagram the filter let through: Context ID 0 and a payload the link carries. */
    private suspend fun up(d: ByteArray) {
        val n = VarInt.encodedLength(d[0])
        val len = d.size - n
        val c = config
        // the tunnel's own rate, then its client's over all its tunnels (CWE-400)
        if (!bucket.tryTake() || !client.bucket.tryTake()) {
            proxy.count(proxy.rateLimited)
            return
        }
        if (c.unansweredLimit > 0 && !answer.answered.load() && answer.sent.load() >= c.unansweredLimit) {
            proxy.count(proxy.unanswered)
            return
        }
        sendBatch.count = 0
        sendBatch.buffer(0).copyFrom(d, n, 0, len)
        sendBatch.setLength(0, len)
        sendBatch.setAddress(0, target)
        sendBatch.setEcn(0, Ecn.NotEct)
        // the batch holds this one payload, so a refusal is that payload's: it is dropped alone, the next HTTP datagram is a
        // send of its own. Section 5 carries "the unmodified payload": one the path or link cannot carry whole is dropped, not
        // fragmented, and the socket stays usable; any other failure ends the tunnel (section 3.1). A refusal is neither
        // activity (nothing went out: the idle timer is not touched) nor a payload the target left unanswered.
        val accepted =
            try {
                io.io.send(sendBatch)
            } catch (e: CancellationException) {
                throw e
            } catch (e: Throwable) {
                if (!isRefusedAsTooLarge(e)) throw e
                proxy.count(proxy.refusedAsTooLarge)
                return
            }
        // the accelerated socket skips a refused slot without throwing, and counts it as sent
        if (accepted > 0 && (io.io as? EmsgsizeReports)?.takeEmsgsize()?.let { it > 0 } == true) {
            proxy.count(proxy.refusedAsTooLarge)
            return
        }
        if (accepted == 1) {
            sent?.record(d, n, len)
            proxy.count(proxy.toTargets)
        }
        answer.sent.incrementAndFetch()
        touch()
    }

    /**
     * RFC 9298 section 6.1: "the UDP proxy SHOULD drop the UDP payload and send an ICMP Packet Too Big message to the
     * target". [d] is the HTTP datagram that did not fit (Context ID 0, then the payload); [maxDatagram] the largest that
     * does, from which the MTU to report follows (the UDP and IP headers on top of the largest payload). Needs the privilege,
     * a token of the target's and of the proxy's limits ([UdpProxyImpl.sendPacketTooBig]) and the address the target sent
     * to: [local], the datagram's destination, which the accelerated socket reports on a wildcard bind (IP_PKTINFO /
     * IPV6_PKTINFO), else the socket's own address when it is bound to one ([sourceOf]). A wildcard socket that does not
     * report it (the portable socket) has none: the message is not sent and counted in [UdpProxyImpl.packetTooBigNoSource].
     */
    private suspend fun packetTooBig(
        local: InetSocketAddress?,
        d: ByteArray,
        maxDatagram: Int,
    ) {
        val from = sourceOf(local, io.io.localAddress)
        if (from == null) {
            if (proxy.packetTooBigAvailable()) proxy.count(proxy.packetTooBigNoSource)
            return
        }
        // an IPv4-mapped target (Kotlin/Native keeps the dual-stack spelling) is IPv4 on the wire: its headers and its socket
        val to = target.withUnmappedIp()
        // the largest UDP payload that fits (the datagram less its one-byte Context ID) and the headers it would travel in
        val mtu = (maxDatagram - 1).coerceAtLeast(0) + if (':' in to.ipLiteral()) IPV6_UDP_OVERHEAD else IPV4_UDP_OVERHEAD
        when (proxy.sendPacketTooBig(to, from, d.copyOfRange(1, d.size), d.size - 1, mtu)) {
            UdpProxyImpl.PtbOutcome.Sent -> proxy.count(proxy.packetTooBigSent)
            UdpProxyImpl.PtbOutcome.Failed -> proxy.count(proxy.packetTooBigFailed)
            UdpProxyImpl.PtbOutcome.Unavailable, UdpProxyImpl.PtbOutcome.Limited -> Unit // dropped and counted only
        }
    }

    /** Datagrams from the socket: only the target's (section 3.1), each one an HTTP datagram with Context ID 0. */
    private suspend fun down() {
        val batch = receiveBatch
        while (true) {
            batch.count = 0
            io.io.receive(batch)
            for (i in 0 until batch.count) {
                val from = batch.address(i)
                // "it MUST validate the IP source address and UDP source port on received packets"
                if (from == null || !from.sameIpAs(target)) {
                    proxy.count(proxy.foreignSource)
                    continue
                }
                answer.answered.store(true)
                touch()
                val len = batch.length(i)
                // a datagram above the link's MTU arrived reassembled, or was cut by a socket whose buffer it did not fit:
                // RFC 9298 section 5 carries "the unmodified payload", so it is dropped whole
                if (len > linkMtu) {
                    proxy.count(proxy.tooLargeFromTarget)
                    continue
                }
                val d = ByteArray(len + 1)
                batch.buffer(i).copyTo(d, 0, 1, len)
                // section 6.1: one too large for a QUIC DATAGRAM frame is dropped, never sent as a capsule
                when (val r = capsules.trySendDatagram(d)) {
                    is DatagramSendResult.Sent -> {
                        proxy.count(proxy.fromTargets)
                    }

                    is DatagramSendResult.TooLarge -> {
                        proxy.count(proxy.tooLargeForClient)
                        packetTooBig(batch.localAddress(i), d, r.max)
                    }

                    is DatagramSendResult.Closed -> {
                        return
                    }

                    else -> {
                        proxy.count(proxy.clientBusy)
                    }
                }
            }
        }
    }
}

/**
 * The address a target's datagram was sent to, the source of the Packet Too Big that answers it: [local], the destination
 * the socket reported for the datagram, else [bound], the socket's own address, when it names one address and port (a
 * socket bound to one address takes only datagrams sent to it). Null for a wildcard socket that reported none: all its
 * address bytes zero, in any spelling ([specificIpOrNull]). An IPv4-mapped address (a dual-stack socket on Kotlin/Native)
 * is its IPv4 address, the family of the raw socket that sends to an IPv4 target.
 *
 * A socket bound to one address can still be handed datagrams sent to another: TPROXY (`IP_TRANSPARENT`) or a BPF
 * `sk_lookup` program steer traffic for other addresses to it. Its Packet Too Big then leaves from the bound address, not
 * the one the target sent to; the target's kernel matches the message to a socket by the quoted addresses and ports, finds
 * none, and drops it. Harmless, and such deployments use a wildcard bind with each datagram's destination reported.
 */
internal fun sourceOf(
    local: InetSocketAddress?,
    bound: InetSocketAddress,
): InetSocketAddress? = local?.withUnmappedIp() ?: bound.specificIpOrNull()

/** Packet Too Big messages per second and per target address (RFC 4443 section 2.4 (f)), and the burst before the rate applies. */
private const val PTB_RATE = 10
private const val PTB_BURST = 5

/** Packet Too Big messages per second over the whole proxy, and the burst. */
private const val PTB_TOTAL_RATE = 100
private const val PTB_TOTAL_BURST = 50

/** Target addresses whose Packet Too Big limit a proxy keeps (the least recently used go first). */
private const val MAX_PTB_TARGETS = 4096

/** Where a proxy's Packet Too Big messages go: the raw socket, or a test's recorder; used under the proxy's lock. */
internal interface PtbSink {
    /** Sends the message for `payload[0, len)` from [target] to [local] that does not fit [mtu]; true when it went out. */
    fun send(
        target: InetSocketAddress,
        local: InetSocketAddress,
        payload: ByteArray,
        len: Int,
        mtu: Int,
    ): Boolean

    fun close()
}

/** The raw-socket [PtbSink] (`ksl_icmp_*`). */
private class RawPtbSink(
    private val s: PacketTooBigSender,
) : PtbSink {
    override fun send(
        target: InetSocketAddress,
        local: InetSocketAddress,
        payload: ByteArray,
        len: Int,
        mtu: Int,
    ): Boolean = s.send(target, local, payload, len, mtu)

    override fun close() = s.close()
}

/** A tunnel's socket, closed at most once whoever ends the tunnel first. */
internal class OnceClosed(
    val io: DatagramIo,
) {
    private val closed = AtomicBoolean(false)

    fun close() {
        if (closed.compareAndSet(expectedValue = false, newValue = true)) io.close()
    }
}

/** A token bucket of [burst] tokens refilled at [rate] per second, on [now] (nanoseconds); used by one coroutine. */
internal class TokenBucket(
    private val rate: Int,
    private val burst: Int,
    private val now: () -> Long,
) {
    private var tokens = burst.toDouble()
    private var last = now()

    fun tryTake(): Boolean {
        val t = now()
        tokens = minOf(burst.toDouble(), tokens + (t - last) * rate / 1e9)
        last = t
        if (tokens < 1.0) return false
        tokens -= 1.0
        return true
    }

    /** Gives back a token [tryTake] took for nothing. */
    fun refund() {
        tokens = minOf(burst.toDouble(), tokens + 1.0)
    }
}
