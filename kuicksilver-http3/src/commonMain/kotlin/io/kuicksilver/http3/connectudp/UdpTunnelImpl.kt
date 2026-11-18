// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(ExperimentalKuicksilverApi::class, ExperimentalAtomicApi::class, io.kuicksilver.annotations.InternalKuicksilverApi::class)

package io.kuicksilver.http3.connectudp

import io.ktor.network.sockets.InetSocketAddress
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.http3.CapsuleConfig
import io.kuicksilver.http3.CapsuleProtocol
import io.kuicksilver.http3.CapsuleStream
import io.kuicksilver.http3.ConnectUdp
import io.kuicksilver.http3.Http3Connection
import io.kuicksilver.http3.Http3ErrorCode
import io.kuicksilver.http3.Http3Headers
import io.kuicksilver.http3.UdpProxyTemplate
import io.kuicksilver.http3.UdpTunnel
import io.kuicksilver.http3.http3Request
import io.kuicksilver.http3.message.DatagramFilter
import io.kuicksilver.http3.message.DatagramVerdict
import io.kuicksilver.http3.message.UdpHost
import io.kuicksilver.http3.runtime.Http3StreamImpl
import io.kuicksilver.quic.DatagramIo
import io.kuicksilver.quic.DatagramSendResult
import io.kuicksilver.quic.Ecn
import io.kuicksilver.quic.IoCapabilities
import io.kuicksilver.quic.PacketBatch
import io.kuicksilver.tls.completedWithin
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.channels.BufferOverflow
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.receiveAsFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import kotlinx.io.IOException
import kotlin.concurrent.atomics.AtomicBoolean
import kotlin.concurrent.atomics.AtomicLong
import kotlin.concurrent.atomics.ExperimentalAtomicApi
import kotlin.concurrent.atomics.incrementAndFetch
import kotlin.time.Duration

/** The Context ID of UDP payloads (RFC 9298 section 5), one byte as a QUIC varint. */
private const val UDP_CONTEXT: Byte = 0

/** The longest Context ID varint (RFC 9000 section 16): a full UDP payload may follow one of 8 bytes. */
private const val MAX_CONTEXT_ID_LENGTH = 8

/** Payloads from the target kept for a collector that lags (the newest win, as on a socket's receive buffer). */
private const val RECEIVE_QUEUE = 64

/** An HTTP datagram with Context ID 0 and [payload]. */
internal fun udpDatagram(payload: ByteArray): ByteArray = ByteArray(payload.size + 1).also { payload.copyInto(it, 1) }

/** The capsule configuration of a CONNECT-UDP stream: no capsule types of its own, datagrams up to [maxDatagram]. */
internal fun connectUdpCapsules(maxDatagram: Int): CapsuleConfig = CapsuleConfig(maxDatagramLength = maxDatagram)

internal suspend fun connectUdpTunnel(
    connection: Http3Connection,
    template: UdpProxyTemplate,
    targetHost: String,
    targetPort: Int,
    headers: Http3Headers,
    closeTimeout: Duration,
): UdpTunnel {
    require(closeTimeout.isPositive()) { "closeTimeout must be positive" }
    // section 2 and 3: the target is checked before a stream is opened
    val target = template.parsed.expand(targetHost, targetPort)
    val host = UdpHost.parse(targetHost.removeSurrounding("[", "]"))!!
    val fields = headers.fields.filter { !it.first.equals(CapsuleProtocol.FIELD, ignoreCase = true) } + CapsuleProtocol.Enabled
    val request =
        http3Request("CONNECT", target.authority, target.pathAndQuery) {
            scheme = target.scheme
            this.headers = Http3Headers(fields)
        }
    val stream = connection.connect(request, ConnectUdp.PROTOCOL)
    val impl =
        stream as? Http3StreamImpl ?: run {
            stream.reset(Http3ErrorCode.REQUEST_CANCELLED)
            throw IllegalStateException("connectUdp needs a stream of this library's Http3Connection")
        }
    val dropped = AtomicLong(0)
    // section 5: Context ID 0 carries UDP payloads, longer than 65527 bytes "MUST abort the corresponding stream"; the
    // client registers no other Context ID, so every other one is unknown and dropped (section 4)
    val filter =
        DatagramFilter { ctx, len ->
            when {
                ctx != 0L -> DatagramVerdict.Skip.also { dropped.incrementAndFetch() }
                len > ConnectUdp.MAX_UDP_PAYLOAD -> DatagramVerdict.Abort
                else -> DatagramVerdict.Deliver
            }
        }
    val capsules =
        try {
            impl.useCapsuleProtocol(connectUdpCapsules(ConnectUdp.MAX_UDP_PAYLOAD + MAX_CONTEXT_ID_LENGTH), filter)
        } catch (e: Throwable) {
            if (e !is CancellationException) impl.reset(Http3ErrorCode.REQUEST_CANCELLED)
            throw e
        }
    return UdpTunnelImpl(capsules, impl, host, targetPort, dropped, closeTimeout).also { it.start() }
}

internal class UdpTunnelImpl(
    override val stream: CapsuleStream,
    private val impl: Http3StreamImpl,
    host: UdpHost,
    override val targetPort: Int,
    private val dropped: AtomicLong,
    private val closeTimeout: Duration,
) : UdpTunnel {
    override val targetHost: String = host.text

    /** The target is an IPv6 literal: the socket of [asDatagramIo] says it is bound to `::`. */
    internal val ipv6: Boolean = host is UdpHost.Ipv6
    private val incoming = Channel<ByteArray>(RECEIVE_QUEUE, BufferOverflow.DROP_OLDEST)
    private val closed = AtomicBoolean(false)
    private val ioTaken = AtomicBoolean(false)

    override val remoteAddress: InetSocketAddress =
        when (host) {
            is UdpHost.Name -> InetSocketAddress(PLACEHOLDER, targetPort)
            else -> InetSocketAddress(host.text, targetPort)
        }

    override val payloads: Flow<ByteArray> = incoming.receiveAsFlow()
    override val droppedDatagrams: Long get() = dropped.load()

    fun start() {
        // the filter let only Context ID 0 through: strip its varint (one byte, or up to eight when not minimal)
        impl.scope
            .launch {
                stream.datagrams.collect { d ->
                    val n =
                        io.kuicksilver.http3.frame.VarInt
                            .encodedLength(d[0])
                    incoming.trySend(d.copyOfRange(n, d.size))
                }
            }.invokeOnCompletion { incoming.close(it?.takeIf { e -> e !is CancellationException }) }
    }

    override fun trySend(payload: ByteArray): DatagramSendResult {
        require(payload.size <= ConnectUdp.MAX_UDP_PAYLOAD) { "a UDP payload is at most 65527 bytes (RFC 9298 section 5)" }
        return when (val r = stream.trySendDatagram(udpDatagram(payload))) {
            is DatagramSendResult.TooLarge -> DatagramSendResult.TooLarge((r.max - 1).coerceAtLeast(0))
            else -> r
        }
    }

    override suspend fun send(payload: ByteArray) {
        require(payload.size <= ConnectUdp.MAX_UDP_PAYLOAD) { "a UDP payload is at most 65527 bytes (RFC 9298 section 5)" }
        stream.sendDatagram(udpDatagram(payload))
    }

    override suspend fun close() {
        if (!closed.compareAndSet(expectedValue = false, newValue = true)) return
        withContext(NonCancellable) {
            // completedWithin: a close that finished as the bound fires is not followed by a reset
            val done = completedWithin(closeTimeout) { runCatching { stream.close() } }
            if (done == null) impl.reset(Http3ErrorCode.CONNECT_ERROR)
        }
    }

    override fun asDatagramIo(): DatagramIo {
        check(ioTaken.compareAndSet(expectedValue = false, newValue = true)) { "asDatagramIo() was already called on this tunnel" }
        return TunnelDatagramIo(this)
    }

    /** Takes the next payload from the target; throws once the tunnel ended. */
    internal suspend fun receivePayload(): ByteArray =
        incoming.receiveCatching().getOrNull() ?: throw IOException("the UDP tunnel to $targetHost:$targetPort ended")

    /** Closes the tunnel from a socket's non-suspending close(). */
    internal fun closeInBackground() {
        impl.scope.launch { close() }
    }

    private companion object {
        /** TEST-NET-1 (RFC 5737): never routed, so a QUIC connection that names it can only mean the tunnel's target. */
        const val PLACEHOLDER = "192.0.2.1"
    }
}

/**
 * A [UdpTunnelImpl] as the UDP socket of a QUIC endpoint (proxied QUIC): sends go to the tunnel's target whatever their
 * address, receives come from [UdpTunnel.remoteAddress]. No ECN (RFC 9298 section 6.2: the proxy sends Not-ECT), no GSO,
 * no Don't Fragment, so the QUIC connection inside keeps to 1200-byte datagrams.
 */
@OptIn(ExperimentalKuicksilverApi::class)
internal class TunnelDatagramIo(
    private val tunnel: UdpTunnelImpl,
) : DatagramIo {
    override val localAddress: InetSocketAddress =
        if (tunnel.ipv6) InetSocketAddress("::", 0) else InetSocketAddress("0.0.0.0", 0)
    override val capabilities: StateFlow<IoCapabilities> = MutableStateFlow(IoCapabilities.Portable)
    private val closed = AtomicBoolean(false)

    /** Datagrams the tunnel refused (too large or a full queue), lost as on a path. */
    internal val refused = AtomicLong(0)

    override suspend fun receive(into: PacketBatch): Int {
        if (into.count >= into.capacity) return 0
        while (true) {
            if (closed.load()) throw IOException("the socket is closed")
            val p = tunnel.receivePayload()
            if (p.size > into.segmentSize) continue // as a socket drops what does not fit its slot
            val i = into.count
            into.buffer(i).copyFrom(p, 0, 0, p.size)
            into.setLength(i, p.size)
            into.setAddress(i, tunnel.remoteAddress)
            into.setEcn(i, Ecn.NotEct)
            return 1
        }
    }

    override suspend fun send(batch: PacketBatch): Int = trySend(batch)

    override fun trySend(batch: PacketBatch): Int {
        if (closed.load()) return 0
        for (i in 0 until batch.count) {
            val bytes = ByteArray(batch.length(i))
            batch.buffer(i).copyTo(bytes, 0, 0, bytes.size)
            when (tunnel.trySend(bytes)) {
                is DatagramSendResult.Sent -> {}

                is DatagramSendResult.QueueFull -> {
                    return i
                }

                // the rest is refused, as a full send buffer would
                else -> {
                    refused.incrementAndFetch()
                } // too large, unsupported or closed: lost on the path
            }
        }
        return batch.count
    }

    override fun close() {
        if (closed.compareAndSet(expectedValue = false, newValue = true)) tunnel.closeInBackground()
    }
}
