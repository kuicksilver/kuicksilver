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
import io.kuicksilver.quic.PacketBatch
import io.kuicksilver.quic.ipLiteral
import io.kuicksilver.quic.sameIpAs
import io.kuicksilver.tls.completedWithin
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.IO
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import kotlin.concurrent.atomics.AtomicBoolean
import kotlin.concurrent.atomics.AtomicLong
import kotlin.concurrent.atomics.ExperimentalAtomicApi
import kotlin.concurrent.atomics.incrementAndFetch
import kotlin.time.Duration
import kotlin.time.Duration.Companion.nanoseconds
import kotlin.time.Duration.Companion.seconds
import kotlin.time.TimeSource

/** The platform resolver of [io.kuicksilver.http3.UdpProxyResolver.System]: one address, looked up off the caller's thread. */
internal suspend fun systemResolve(host: String): List<ByteArray> =
    withContext(Dispatchers.IO) { listOfNotNull(InetSocketAddress(host, 0).resolveAddress()) }

/** IPv4 (20) and UDP (8) headers: the largest unfragmented UDP payload on an IPv4 link is its MTU minus 28 (RFC 791, RFC 768). */
private const val IPV4_UDP_OVERHEAD = 28

/** IPv6 (40) and UDP (8) headers (RFC 8200, RFC 768). */
private const val IPV6_UDP_OVERHEAD = 48

/** The `proxy-status` field (RFC 9209). */
private const val PROXY_STATUS = "proxy-status"

/** The longest Context ID varint (RFC 9000 section 16): the capsule limit leaves room for it on top of the payload. */
private const val MAX_CONTEXT_ID = 8

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
    private val perClient = HashMap<String, Int>()

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
    internal val rateLimited = AtomicLong(0)
    internal val unanswered = AtomicLong(0)
    internal val foreignSource = AtomicLong(0)
    internal val tooLargeForClient = AtomicLong(0)
    internal val clientBusy = AtomicLong(0)

    fun snapshot(): UdpProxyStats =
        UdpProxyStats(
            opened.load(),
            refused.load(),
            toTargets.load(),
            fromTargets.load(),
            unknownContext.load(),
            tooLargeForLink.load(),
            rateLimited.load(),
            unanswered.load(),
            foreignSource.load(),
            tooLargeForClient.load(),
            clientBusy.load(),
        )

    suspend fun serve(request: Http3ServerRequest) {
        // section 3.4: an Extended CONNECT with :protocol connect-udp; anything else is not ours to serve
        if (!ConnectUdp.isConnectUdp(request)) return refuse(request, 400, "http_request_error")
        val target =
            when (val m = config.template.match(request.path.orEmpty())) {
                is TemplateMatch.NoMatch -> return refuse(request, 404, null)
                is TemplateMatch.Invalid -> return refuse(request, 400, "http_request_error")
                is TemplateMatch.Target -> m
            }
        if (config.requireCapsuleProtocolField && !CapsuleProtocol.isEnabled(request.headers)) {
            return refuse(request, 400, "http_request_error")
        }
        val client = request.remoteAddress.ipLiteral()
        reserve(client)?.let { status -> return refuse(request, status, "connection_limit_reached") }
        try {
            open(request, target)
        } catch (e: CancellationException) {
            // a request the cancelled call leaves unanswered would hold its stream until the connection ends
            request.reset(Http3ErrorCode.REQUEST_CANCELLED)
            throw e
        } finally {
            withContext(NonCancellable) { release(client) }
        }
    }

    /** Resolves, filters, opens the socket, answers and relays. */
    private suspend fun open(
        request: Http3ServerRequest,
        target: TemplateMatch.Target,
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
                                Result.success(config.resolver.resolve(h.name))
                            } catch (e: CancellationException) {
                                throw e
                            } catch (e: Throwable) {
                                Result.failure(e)
                            }
                        } ?: return refuse(request, 504, "dns_timeout")
                    val list = r.getOrNull() ?: return refuse(request, 502, "dns_error")
                    list.filter { it.size == 4 || it.size == 16 }.ifEmpty { return refuse(request, 502, "dns_error") }
                }
            }
        // section 7: the filter sees every address; the socket sends to the one it allowed, never to a later answer
        val address =
            candidates.map(::unmapped).firstOrNull { config.targetFilter.allows(target.host.text, it, target.port) }
                ?: return refuse(request, 403, "destination_ip_prohibited")
        val v4 = address.size == 4
        val targetAddress = InetSocketAddress((if (v4) UdpHost.Ipv4(address) else UdpHost.Ipv6(address)).text, target.port)
        val io =
            try {
                OnceClosed(config.socketFactory(InetSocketAddress(if (v4) "0.0.0.0" else "::", 0)))
            } catch (e: CancellationException) {
                throw e
            } catch (_: Throwable) {
                return refuse(request, 502, "proxy_internal_error")
            }
        try {
            // section 6.2: "it MUST set the ECN bits to Not-ECT on UDP packets it sends to the target"
            io.io.disableEcnMarking()
            val payloadLimit = config.linkMtu - if (v4) IPV4_UDP_OVERHEAD else IPV6_UDP_OVERHEAD
            beforeAnswerForTest?.invoke(request)
            val stream =
                try {
                    request.acceptConnect(Http3Headers(listOf(CapsuleProtocol.Enabled)))
                } catch (e: CancellationException) {
                    throw e
                } catch (_: Throwable) {
                    count(refused)
                    return // a request that rules capsules out was answered 400; a stream already gone needs nothing
                }
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
            ProxyTunnel(this, impl, capsules, io, targetAddress, config.linkMtu, clock).run(idleTimeoutForTest ?: config.idleTimeout)
        } finally {
            io.close()
        }
    }

    /** Answers [status] with `proxy-status: <name>; error=<error>` when [error] is given (RFC 9209 section 2). */
    private suspend fun refuse(
        request: Http3ServerRequest,
        status: Int,
        error: String?,
    ) {
        count(refused)
        val fields = if (error == null) emptyList() else listOf(PROXY_STATUS to "${config.proxyName}; error=$error")
        try {
            request.respond(status, Http3Headers(fields)).finish()
        } catch (e: CancellationException) {
            throw e
        } catch (_: Throwable) {
            request.reset(Http3ErrorCode.REQUEST_CANCELLED) // the stream failed meanwhile: it is over either way
        }
    }

    /** Takes a slot for [client]; null, or the status that refuses the request. */
    private suspend fun reserve(client: String): Int? =
        lock.withLock {
            if (active.value >= config.maxTunnels) return@withLock 503
            val n = perClient[client] ?: 0
            if (n >= config.maxTunnelsPerClient) return@withLock 429
            perClient[client] = n + 1
            active.value += 1
            null
        }

    private suspend fun release(client: String) {
        lock.withLock {
            val n = (perClient[client] ?: 1) - 1
            if (n <= 0) perClient.remove(client) else perClient[client] = n
            active.value -= 1
        }
    }

    /** An IPv4-mapped IPv6 address (`::ffff:0:0/96`) as its IPv4 address: it is one, and an IPv4 socket sends to it. */
    private fun unmapped(a: ByteArray): ByteArray {
        if (a.size != 16) return a
        for (i in 0 until 10) if (a[i] != 0.toByte()) return a
        if (a[10] != 0xff.toByte() || a[11] != 0xff.toByte()) return a
        return a.copyOfRange(12, 16)
    }
}

/** Why a tunnel ended. */
private enum class End { ClientFin, ClientGone, SocketFailed, Idle }

/** One open tunnel: client datagrams to the target and back, until [End]. */
private class ProxyTunnel(
    private val proxy: UdpProxyImpl,
    private val impl: Http3StreamImpl,
    private val capsules: CapsuleStreamImpl,
    private val io: OnceClosed,
    private val target: InetSocketAddress,
    linkMtu: Int,
    clock: TimeSource,
) {
    private val config = proxy.config
    private val start = clock.markNow()
    private val lastActivity = AtomicLong(0)
    private val answered = AtomicBoolean(false)
    private val sentUnanswered = AtomicLong(0)
    private val receiveSlot = linkMtu
    private val bucket = TokenBucket(config.packetRate, config.packetBurst) { start.elapsedNow().inWholeNanoseconds }
    private val sendBatch = PacketBatch(1, receiveSlot)
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
            End.SocketFailed, null -> {
                impl.reset(Http3ErrorCode.CONNECT_ERROR)
                impl.stopSending(Http3ErrorCode.CONNECT_ERROR)
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
        if (!bucket.tryTake()) {
            proxy.count(proxy.rateLimited)
            return
        }
        if (c.unansweredLimit > 0 && !answered.load() && sentUnanswered.load() >= c.unansweredLimit) {
            proxy.count(proxy.unanswered)
            return
        }
        sendBatch.count = 0
        sendBatch.buffer(0).copyFrom(d, n, 0, len)
        sendBatch.setLength(0, len)
        sendBatch.setAddress(0, target)
        sendBatch.setEcn(0, Ecn.NotEct)
        if (io.io.send(sendBatch) == 1) proxy.count(proxy.toTargets)
        sentUnanswered.incrementAndFetch()
        touch()
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
                answered.store(true)
                touch()
                val len = batch.length(i)
                val d = ByteArray(len + 1)
                batch.buffer(i).copyTo(d, 0, 1, len)
                // section 6.1: one too large for a QUIC DATAGRAM frame is dropped, never sent as a capsule
                when (capsules.trySendDatagram(d)) {
                    is DatagramSendResult.Sent -> proxy.count(proxy.fromTargets)
                    is DatagramSendResult.TooLarge -> proxy.count(proxy.tooLargeForClient)
                    is DatagramSendResult.Closed -> return
                    else -> proxy.count(proxy.clientBusy)
                }
            }
        }
    }
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
}
