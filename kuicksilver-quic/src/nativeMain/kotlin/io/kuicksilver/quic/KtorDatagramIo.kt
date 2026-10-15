// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic

import io.ktor.network.selector.SelectorManager
import io.ktor.network.sockets.BoundDatagramSocket
import io.ktor.network.sockets.Datagram
import io.ktor.network.sockets.InetSocketAddress
import io.ktor.network.sockets.aSocket
import io.ktor.utils.io.errors.PosixException
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.native.toByteArray
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.io.Buffer
import kotlinx.io.IOException
import kotlinx.io.readByteArray

/**
 * Portable Native transport over ktor-network's datagram socket (ADR-0006), client use in K2: an empty incoming
 * datagram stops ktor's receive loop for good (known ktor behaviour, not worked around here), and the server side
 * waits for the accelerated `DatagramIo` of K3.
 *
 * ktor-network 3.6.0 puts `::` into every IPv6 sockaddr on Native (docs/upstream/ktor-native-ipv6.md): a bind of `::1` would
 * listen on every interface, and a datagram to any IPv6 address would go to `::`, the local host. This socket fails closed
 * instead: [open] refuses a specific IPv6 address (UnsupportedOperationException; `::` itself is what ktor binds) and a send to
 * an IPv6 address throws an IOException. The accelerated socket (`ksl`, every Native platform) carries the full address.
 */
@OptIn(ExperimentalKuicksilverApi::class)
internal class KtorDatagramIo private constructor(
    private val selector: SelectorManager,
    private val socket: BoundDatagramSocket,
) : DatagramIo {
    override val localAddress: InetSocketAddress = socket.localAddress as InetSocketAddress
    override val capabilities: StateFlow<IoCapabilities> = MutableStateFlow(IoCapabilities.Portable)
    private var lastAddress: InetSocketAddress? = null

    override suspend fun receive(into: PacketBatch): Int {
        if (into.count >= into.capacity) return 0
        val d = defunctAware { socket.receive() }
        val i = into.count
        val bytes = d.packet.readByteArray()
        val n = minOf(bytes.size, into.segmentSize)
        into.buffer(i).copyFrom(bytes, 0, 0, n)
        into.setLength(i, n)
        val a = d.address as InetSocketAddress
        val cached = lastAddress
        into.setAddress(
            i,
            if (cached != null && cached.hostname == a.hostname &&
                cached.port == a.port
            ) {
                cached
            } else {
                a.also { lastAddress = it }
            },
        )
        into.setEcn(i, Ecn.NotEct)
        return 1
    }

    override suspend fun send(batch: PacketBatch): Int {
        refuseIpv6Destinations(batch)
        var sent = 0
        for (i in 0 until batch.count) {
            val a =
                batch.address(i) ?: continue
            defunctAware { socket.send(Datagram(Buffer().also { it.write(batch.buffer(i).toByteArray(batch.length(i))) }, a)) }
            sent++
        }
        return sent
    }

    override fun trySend(batch: PacketBatch): Int {
        refuseIpv6Destinations(batch)
        var sent = 0
        for (i in 0 until batch.count) {
            val a =
                batch.address(i) ?: continue
            if (socket.outgoing
                    .trySend(
                        Datagram(
                            Buffer().also {
                                it.write(batch.buffer(i).toByteArray(batch.length(i)))
                            },
                            a,
                        ),
                    ).isSuccess
            ) {
                sent++
            } else {
                break
            }
        }
        return sent
    }

    /** A ktor failure whose errno says the socket is gone (see [SocketDefunctException]) is reported as such; others pass unchanged. */
    private inline fun <R> defunctAware(call: () -> R): R =
        try {
            call()
        } catch (e: Exception) {
            throw defunctOrNull(e) ?: e
        }

    override fun close() {
        socket.close()
        selector.close()
    }

    private fun refuseIpv6Destinations(batch: PacketBatch) {
        for (i in 0 until batch.count) {
            val a = batch.address(i) ?: continue
            if (a.ipBytes()?.size == 16) throw IOException(misdirected(a))
        }
    }

    companion object {
        private fun misdirected(a: InetSocketAddress): String =
            "the portable Kotlin/Native UDP socket cannot use the IPv6 address ${a.hostname}: ktor-network 3.6.0 would use :: " +
                "instead (docs/upstream/ktor-native-ipv6.md); use the accelerated socket (IoPreference.Accelerated)"

        /** The address bytes ktor-network would resolve [this] to (literals without DNS); null when it does not resolve. */
        private fun InetSocketAddress.ipBytes(): ByteArray? = ipBytesNoDns() ?: runCatching { resolveAddress() }.getOrNull()

        /** The [SocketDefunctException] for [e] when a [PosixException] in its cause chain carries a defunct errno, else null. */
        internal fun defunctOrNull(e: Throwable): SocketDefunctException? {
            var c: Throwable? = e
            while (c != null) {
                if (c is PosixException &&
                    isDefunctErrno(c.errno)
                ) {
                    return SocketDefunctException("socket defunct: ${c.message}", c.errno, e)
                }
                c = c.cause?.takeIf { it !== c }
            }
            return null
        }

        suspend fun open(local: InetSocketAddress): KtorDatagramIo {
            val ip = local.ipBytes()
            if (ip != null && ip.size == 16 && ip.any { it.toInt() != 0 }) throw UnsupportedOperationException(misdirected(local))
            val selector = SelectorManager()
            val s =
                try {
                    aSocket(selector).udp().bind(local)
                } catch (e: Throwable) {
                    selector.close() // a refused bind (port taken) must not keep its selection thread and pipe
                    throw e
                }
            return KtorDatagramIo(selector, s)
        }
    }
}
