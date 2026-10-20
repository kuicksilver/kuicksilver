// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(ExperimentalKuicksilverApi::class, InternalKuicksilverApi::class)

package io.kuicksilver.quic

import io.ktor.network.sockets.InetSocketAddress
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.annotations.InternalKuicksilverApi
import io.kuicksilver.native.PacketBuffer
import io.kuicksilver.tls.KslUdpSocket
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.IO
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.withContext

/**
 * The accelerated transport (ADR-0006): one [KslUdpSocket] of `ksl` on Linux, Android, Apple and Windows. Batches go to C as the
 * slots' own [PacketBuffer]s (no copy in Kotlin); GSO runs, GRO splitting, per-datagram ECN and DF probe mode happen there.
 *
 * `receive` first takes what the socket already holds on the caller's thread (a non-blocking poll, no dispatch); only when nothing
 * is queued does it block a `Dispatchers.IO` thread in 100 ms slices, returning it between slices, until a datagram arrives or the
 * socket is closed. Peers' addresses
 * come back as the same [InetSocketAddress] instance for the same 20 address bytes (a 64-entry cache), so the core's path lookup
 * compares by reference. [capabilities] follow the kernel: GSO or ECN the kernel refused mid-way (EIO/EINVAL, handled in C
 * without loss) drop out of the reported capabilities on the next refresh (every [REFRESH] sends or a short send).
 */
internal class KslDatagramIo private constructor(
    private val socket: KslUdpSocket,
) : DatagramIo {
    override val localAddress: InetSocketAddress = inetOf(socket.localAddress, 0)
    private val caps = MutableStateFlow(capsOf())
    override val capabilities: StateFlow<IoCapabilities> get() = caps

    private fun capsOf(): IoCapabilities {
        val f = socket.grantedFlags
        val gso = socket.gsoMaxSegments
        return IoCapabilities(
            ecnSend = f and KslUdpSocket.ECN != 0,
            ecnReceive = f and KslUdpSocket.ECN != 0,
            gsoMaxSegments =
                if (gso >
                    1
                ) {
                    gso
                } else {
                    1
                },
            gro = f and KslUdpSocket.GRO != 0,
            df = f and KslUdpSocket.DF != 0,
            batch = socket.batch,
        )
    }

    private fun refreshCaps() {
        val c = capsOf()
        val old = caps.value
        if (c.ecnSend != old.ecnSend ||
            c.gsoMaxSegments != old.gsoMaxSegments ||
            c.gro != old.gro
        ) {
            caps.value = c
        }
    }

    /** The arrays one [PacketBatch] hands to C, built once per batch (and per start slot) and reused. */
    private class Slots(
        val batch: PacketBatch,
        val from: Int,
    ) {
        val n = batch.capacity - from
        val bufs: Array<PacketBuffer> = Array(n) { batch.buffer(from + it) }
        val lens = IntArray(n)
        val addrs = ByteArray(n * KslUdpSocket.ADDR_LEN)
        val ecn = ByteArray(n)
    }

    private var rx: Slots? = null
    private var tx: Slots? = null

    private fun rxSlots(b: PacketBatch): Slots {
        val s = rx
        if (s != null && s.batch === b &&
            s.from == b.count
        ) {
            return s
        }
        return Slots(b, b.count).also { rx = it }
    }

    private fun txSlots(b: PacketBatch): Slots {
        val s = tx
        if (s != null && s.batch === b &&
            s.from == 0
        ) {
            return s
        }
        return Slots(b, 0).also { tx = it }
    }

    // peers seen on receive: 64 entries of 20 bytes, round-robin replacement; the same bytes answer the same instance
    private val peerKeys = ByteArray(PEERS * KslUdpSocket.ADDR_LEN)
    private val peers = arrayOfNulls<InetSocketAddress>(PEERS)
    private var peerNext = 0

    private fun peerOf(
        addrs: ByteArray,
        off: Int,
    ): InetSocketAddress {
        for (k in 0 until PEERS) {
            val p = peers[k] ?: break
            if (same(peerKeys, k * KslUdpSocket.ADDR_LEN, addrs, off)) return p
        }
        val slot = peerNext
        peerNext = (peerNext + 1) % PEERS
        addrs.copyInto(peerKeys, slot * KslUdpSocket.ADDR_LEN, off, off + KslUdpSocket.ADDR_LEN)
        return inetOf(addrs, off).also { peers[slot] = it }
    }

    // destinations on send: the last 4 instances by identity
    private val destKeys = arrayOfNulls<InetSocketAddress>(4)
    private val destBytes = ByteArray(4 * KslUdpSocket.ADDR_LEN)
    private var destNext = 0

    private fun encodeInto(
        a: InetSocketAddress,
        out: ByteArray,
        off: Int,
    ) {
        for (k in 0 until 4) {
            if (destKeys[k] ===
                a
            ) {
                destBytes.copyInto(out, off, k * KslUdpSocket.ADDR_LEN, (k + 1) * KslUdpSocket.ADDR_LEN)
                return
            }
        }
        val ip = a.ipBytesNoDns() ?: throw IllegalArgumentException("not an IP address: ${a.hostname}") // connect resolved the name once
        val enc = KslUdpSocket.encodeAddress(ip, a.port)
        val slot = destNext
        destNext = (destNext + 1) % 4
        enc.copyInto(destBytes, slot * KslUdpSocket.ADDR_LEN)
        destKeys[slot] = a
        enc.copyInto(out, off)
    }

    override suspend fun receive(into: PacketBatch): Int {
        if (into.count >= into.capacity) return 0
        val s = rxSlots(into)
        // what is already queued is taken on the caller's thread (a non-blocking poll): under load the next datagram is there, and the
        // two dispatches of a blocking slice (to Dispatchers.IO and back to the loop) cost more than the receive itself, most on
        // Kotlin/Native, whose IO dispatcher is a separate pool (docs/benchmarks.md)
        val ready = if (socket.isClosed) 0 else defunctAware { socket.receive(s.bufs, s.lens, s.addrs, s.ecn, s.n, 0) }
        val n =
            if (ready > 0) {
                ready
            } else {
                receiveInSlices(
                    Dispatchers.IO,
                    { socket.isClosed },
                ) { defunctAware { socket.receive(s.bufs, s.lens, s.addrs, s.ecn, s.n, 100) } }
            }
        val from = s.from
        for (i in 0 until n) {
            into.setLength(from + i, s.lens[i])
            into.setAddress(from + i, peerOf(s.addrs, i * KslUdpSocket.ADDR_LEN))
            into.setEcn(from + i, ecnOf(s.ecn[i].toInt()))
        }
        return n
    }

    override suspend fun send(batch: PacketBatch): Int = trySend(batch)

    private var sends = 0

    override fun trySend(batch: PacketBatch): Int {
        val n = batch.count
        if (n == 0) return 0
        val s = txSlots(batch)
        for (i in 0 until n) {
            s.lens[i] = batch.length(i)
            encodeInto(batch.address(i) ?: throw IllegalArgumentException("slot $i has no address"), s.addrs, i * KslUdpSocket.ADDR_LEN)
            s.ecn[i] =
                batch.ecn(i).ordinalCode().toByte()
        }
        val sent = defunctAware { socket.send(s.bufs, s.lens, s.addrs, s.ecn, n) }
        if (++sends and (REFRESH - 1) == 0 || sent < n) refreshCaps()
        return sent
    }

    /**
     * Runs a socket call; a failure whose errno means the socket is gone (iOS takes the sockets of a suspended app, an interface
     * went down) becomes [SocketDefunctException], so the loop reports a lost path instead of failing the endpoint or retrying
     * a dead socket. Other failures pass unchanged.
     */
    private inline fun <R> defunctAware(call: () -> R): R =
        try {
            call()
        } catch (e: Exception) {
            val errno = KslUdpSocket.errnoOf(e)
            if (errno != null && !socket.isClosed &&
                isDefunctErrno(errno)
            ) {
                throw SocketDefunctException("socket defunct: ${e.message}", errno, e)
            }
            throw e
        }

    /** Marks are per datagram: the core stops marking the failed path itself, so one peer that bleaches ECN does not turn it off for every connection on this socket. */
    override fun disableEcnMarking() {}

    override fun close() {
        socket.close()
    }

    internal fun statsForTest(): KslUdpSocket.Stats = socket.stats

    /** The kernel descriptor (tests: socket options, fault injection). */
    internal val fdForTest: Int get() = socket.fd

    /** True when the kernel granted SO_REUSEPORT with flow hashing (Linux, Android; never Apple or Windows): several loops may share the port. */
    internal val reusePortGranted: Boolean get() = socket.grantedFlags and KslUdpSocket.REUSEPORT != 0

    companion object {
        private const val PEERS = 64
        private const val REFRESH = 256

        /**
         * Opens the accelerated socket on [local]; null where `ksl_udp` cannot open its socket or the address cannot be resolved.
         * A single socket (no [reusePort]) the kernel refuses (a sandbox, limits), or a process whose loopback probe failed
         * ([KslUdpSocket.unsupportedReason]), also answers null: the caller takes the portable socket, said once per process to
         * [logger] at [LogLevel.Warn]. [configure] sees the bound socket's descriptor before any datagram (Android binds it
         * to a network); if it throws, the socket is closed.
         */
        fun open(
            local: InetSocketAddress,
            reusePort: Boolean = false,
            logger: KuicksilverLogger = KuicksilverLogger.Stderr,
            configure: (fd: Int) -> Unit = {},
        ): KslDatagramIo? {
            val unsupported = unsupportedReason()
            if (unsupported != null) {
                // the loopback probe failed (a sandbox refusing every bind): the portable socket, said once like a refused bind
                if (!reusePort) warnFallback(logger) { "accelerated UDP socket unavailable ($unsupported); using the portable socket" }
                return null
            }
            val ip = local.resolveAddress() ?: return null
            val flags =
                KslUdpSocket.ECN or KslUdpSocket.GSO or KslUdpSocket.GRO or KslUdpSocket.DF or
                    (if (reusePort) KslUdpSocket.REUSEPORT else 0)
            val addr = KslUdpSocket.encodeAddress(ip, local.port)
            val socket =
                if (reusePort) {
                    // loops > 1 must see why the shared port failed
                    KslUdpSocket.open(addr, flags)
                } else {
                    socketOpener(addr, flags) { e ->
                        warnFallback(logger) { "accelerated UDP socket refused on $local (${e.message}); using the portable socket" }
                    } ?: return null
                }
            try {
                configure(socket.fd)
            } catch (e: Throwable) {
                socket.close()
                throw e
            }
            return KslDatagramIo(socket)
        }

        @OptIn(kotlin.concurrent.atomics.ExperimentalAtomicApi::class)
        private val fallbackWarned = kotlin.concurrent.atomics.AtomicBoolean(false)

        /** The fallback to the portable socket, said once per process at [LogLevel.Warn]. */
        @OptIn(kotlin.concurrent.atomics.ExperimentalAtomicApi::class)
        private inline fun warnFallback(
            logger: KuicksilverLogger,
            line: () -> String,
        ) {
            if (fallbackWarned.compareAndSet(false, true)) logger.emit(LogLevel.Warn, message = line)
        }

        /** Lets a test see the once-per-process warning again. */
        @OptIn(kotlin.concurrent.atomics.ExperimentalAtomicApi::class)
        internal fun resetFallbackWarningForTest() {
            fallbackWarned.store(false)
        }

        /** Why the accelerated socket cannot work in this process ([KslUdpSocket.unsupportedReason]); a test replaces it. */
        internal var unsupportedReason: () -> String? = { KslUdpSocket.unsupportedReason }

        /** Opens the `ksl` socket or answers null with the reason; a test replaces it to inject a refusal. */
        internal var socketOpener: (
            ByteArray,
            Int,
            (Throwable) -> Unit,
        ) -> KslUdpSocket? = { a, f, failed -> KslUdpSocket.openOrNull(a, f, failed) }

        /**
         * Runs blocking [slice]s (each waits at most ~100 ms and answers 0 when nothing arrived) on [blocking] until one returns
         * a count. Each slice is its own dispatch, so an idle socket hands its thread back between slices instead of pinning one
         * `Dispatchers.IO` thread for its lifetime (past ~64 endpoints new receivers never ran).
         */
        internal suspend fun receiveInSlices(
            blocking: kotlinx.coroutines.CoroutineDispatcher,
            closed: () -> Boolean,
            slice: () -> Int,
        ): Int {
            while (true) {
                if (closed()) throw IllegalStateException("datagram io closed")
                val r = withContext(blocking) { slice() }
                if (r != 0) return r
            }
        }

        private fun same(
            a: ByteArray,
            ao: Int,
            b: ByteArray,
            bo: Int,
        ): Boolean {
            for (i in 0 until KslUdpSocket.ADDR_LEN) {
                if (a[ao + i] !=
                    b[bo + i]
                ) {
                    return false
                }
            }
            return true
        }

        private fun ecnOf(code: Int): Ecn =
            when (code and 3) {
                1 -> Ecn.Ect1
                2 -> Ecn.Ect0
                3 -> Ecn.Ce
                else -> Ecn.NotEct
            }

        private fun Ecn.ordinalCode(): Int =
            when (this) {
                Ecn.NotEct -> 0
                Ecn.Ect1 -> 1
                Ecn.Ect0 -> 2
                Ecn.Ce -> 3
            }

        /** The ktor address of an encoded one: numeric host text and the port. */
        internal fun inetOf(
            a: ByteArray,
            off: Int,
        ): InetSocketAddress {
            val port = ((a[off + 1].toInt() and 0xff) shl 8) or (a[off + 2].toInt() and 0xff)
            return InetSocketAddress(if (a[off].toInt() == 4) ipv4Text(a, off + 3) else ipv6Text(a, off + 3), port)
        }

        private fun ipv4Text(
            a: ByteArray,
            off: Int,
        ): String =
            "${a[off].toInt() and 0xff}.${a[off + 1].toInt() and 0xff}.${a[off + 2].toInt() and 0xff}.${a[off + 3].toInt() and 0xff}"

        /** RFC 5952 text: lower-case hex groups, the longest run of two or more zero groups collapsed to `::`. */
        internal fun ipv6Text(
            a: ByteArray,
            off: Int,
        ): String {
            val g = IntArray(8) { ((a[off + 2 * it].toInt() and 0xff) shl 8) or (a[off + 2 * it + 1].toInt() and 0xff) }
            var bestStart = -1
            var bestLen = 0
            var i = 0
            while (i <
                8
            ) {
                if (g[i] ==
                    0
                ) {
                    var j = i
                    while (j < 8 &&
                        g[j] == 0
                    ) {
                        j++
                    }
                    if (j - i > bestLen && j - i >= 2) {
                        bestStart = i
                        bestLen = j - i
                    }
                    i = j
                } else {
                    i++
                }
            }
            val sb = StringBuilder()
            i = 0
            while (i < 8) {
                if (i == bestStart) {
                    sb.append("::")
                    i += bestLen
                    continue
                }
                if (sb.isNotEmpty() && !sb.endsWith(':')) sb.append(':')
                sb.append(g[i].toString(16))
                i++
            }
            return sb.toString()
        }
    }
}
