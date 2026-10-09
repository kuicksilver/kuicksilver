// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(InternalKuicksilverApi::class, ExperimentalAtomicApi::class)

package io.kuicksilver.tls

import io.kuicksilver.annotations.InternalKuicksilverApi
import io.kuicksilver.native.Ksl
import io.kuicksilver.native.KslConst
import io.kuicksilver.native.KslException
import io.kuicksilver.native.KslLoader
import io.kuicksilver.native.PacketBuffer
import kotlin.concurrent.atomics.AtomicInt
import kotlin.concurrent.atomics.ExperimentalAtomicApi

/**
 * The accelerated UDP socket of `ksl` (ADR-0006): one Linux socket with batched send and receive, UDP GSO and GRO
 * done inside C, ECN marks per datagram, DF in probe mode (never the kernel's path MTU cache: quic-go CVE-2024-53259) and
 * SO_REUSEPORT. Slots are [PacketBuffer]s read and written in place; GRO segments are split into consecutive slots by C, so the
 * caller never sees offsets (threat-model 3.12: segments of different senders never share a slot run).
 *
 * Thread safety: one thread sends and one receives; [shutdown] and [close] may be called from any thread. A receive blocked in
 * [receive] is woken by [shutdown] (and so by [close]) and answers 0; the native object is freed only once no receiver is inside.
 * Where `ksl_udp` is not available (Apple, Windows) [supported] is false and [open] throws [KslException.Internal] with
 * [KslConst.E_NOT_SUPPORTED]: the portable io is used there.
 */
@InternalKuicksilverApi
public class KslUdpSocket private constructor(
    internal val handle: Long,
) : AutoCloseable {
    /** `ADDR_LEN` bytes: family (4|6), port BE, 16 address bytes (IPv4 in the first 4), one pad byte. */
    public val localAddress: ByteArray = Ksl.udpGet(handle, KslConst.UDP_GET_LOCAL)

    /** The kernel's file descriptor (for a poller). */
    public val fd: Int = Ksl.udpGet(handle, KslConst.UDP_GET_FD).let { be32(it, 0) }
    private var lastCaps: ByteArray = Ksl.udpGet(handle, KslConst.UDP_GET_CAPS)

    /** The capability bytes, re-read while the socket is open; the last reading after [shutdown] (the native object may be gone). */
    private fun caps(): ByteArray {
        if (!enter()) return lastCaps
        try {
            lastCaps = Ksl.udpGet(handle, KslConst.UDP_GET_CAPS)
            return lastCaps
        } finally {
            leave()
        }
    }

    /** Flags in effect now ([ECN], [GSO], [GRO], [DF], [REUSEPORT]); GSO and ECN can drop out after a send the kernel refused (EIO/EINVAL), so re-read after a short send. */
    public val grantedFlags: Int get() = be32(caps(), 0)

    /** Segments one GSO send may carry (0 when GSO is off). */
    public val gsoMaxSegments: Int get() = caps().let { ((it[4].toInt() and 0xff) shl 8) or (it[5].toInt() and 0xff) }

    /** Slots the C layer batches per syscall. */
    public val batch: Int get() = caps().let { ((it[6].toInt() and 0xff) shl 8) or (it[7].toInt() and 0xff) }

    /** Counters of the socket (diagnostics, allocates): send syscalls, receive syscalls, times GSO was switched off after a kernel refusal. */
    public class Stats(
        public val sendSyscalls: Long,
        public val receiveSyscalls: Long,
        public val gsoFallbacks: Long,
    )

    private var lastStats: Stats = Stats(0, 0, 0)
    public val stats: Stats get() {
        if (!enter()) return lastStats
        try {
            lastStats =
                Ksl.udpGet(handle, KslConst.UDP_GET_STATS).let {
                    Stats(
                        be32(it, 0).toLong() and 0xffffffffL,
                        be32(it, 4).toLong() and 0xffffffffL,
                        be32(it, 8).toLong() and 0xffffffffL,
                    )
                }
            return lastStats
        } finally {
            leave()
        }
    }

    // bit 30 = shut down, bits 0..29 = receivers inside the native call
    private val state = AtomicInt(0)
    public val isClosed: Boolean get() = state.load() and SHUT != 0

    /**
     * Sends `n` datagrams: `bufs[i][0, lens[i])` to `addrs[i * ADDR_LEN, +ADDR_LEN)` with mark `ecn[i]` (0 not-ECT, 1 ECT(1), 2 ECT(0), 3 CE).
     * Consecutive slots to one address with one mark and equal length (the last may be shorter) leave as one GSO send. Returns the
     * datagrams handed to the kernel; a datagram the path refuses as too large (EMSGSIZE) is skipped and counted, the caller's PMTUD
     * learns from its loss; so is one the destination makes unsendable (port 0, a link-local IPv6 address: the address format has no
     * scope id, and datagrams from link-local peers are dropped on receive). 0 after [shutdown]. Throws [KslException.Internal] on a socket error.
     */
    public fun send(
        bufs: Array<PacketBuffer>,
        lens: IntArray,
        addrs: ByteArray,
        ecn: ByteArray,
        n: Int,
    ): Int {
        if (!enter()) return 0
        try {
            return Ksl.udpSend(handle, bufs, lens, addrs, ecn, n)
        } catch (
            e: KslException.Internal,
        ) {
            if (isClosed) return 0 else throw e
        } finally {
            leave()
        }
    }

    /**
     * Receives up to `n` datagrams into the first slots, waiting at most [timeoutMs] (0 polls, negative waits without limit) for the
     * first one; `lens`, `addrs` and `ecn` describe the filled slots. Returns 0 on timeout and after [shutdown] (check [isClosed]).
     * A datagram larger than its slot, or than the receive scratch, is dropped whole, never truncated. Throws [KslException.Internal]
     * (errno in [KslException.Internal.alert]) when `poll`/`recvmsg` fails on a socket that was not shut down: a broken socket is
     * never reported as an endless run of timeouts.
     */
    public fun receive(
        bufs: Array<PacketBuffer>,
        lens: IntArray,
        addrs: ByteArray,
        ecn: ByteArray,
        n: Int,
        timeoutMs: Int,
    ): Int {
        if (!enter()) return 0
        try {
            val r = Ksl.udpRecv(handle, bufs, lens, addrs, ecn, n, timeoutMs)
            if (r >= 0 || isClosed) return r.coerceAtLeast(0)
            val e = Ksl.udpGet(handle, KslConst.UDP_GET_ERROR)
            throw KslException.Internal(KslConst.E_BAD_ARG, be32(e, 0), if (e.size > 4) e.decodeToString(4) else "ksl_udp_recv failed")
        } finally {
            leave()
        }
    }

    /** Wakes a blocked [receive] and closes the socket; every later [send]/[receive] answers 0. Idempotent. */
    public fun shutdown() {
        while (true) {
            val s = state.load()
            if (s and SHUT != 0) return
            if (state.compareAndSet(s, s or SHUT)) break
        }
        Ksl.udpShutdown(handle)
    }

    /** [shutdown], then frees the native object once the receiver (if any) has left it. Idempotent. */
    override fun close() {
        shutdown()
        while (true) {
            val s = state.load()
            if (s and CLOSED !=
                0
            ) {
                return
            }
            if (s and COUNT != 0) continue
            if (state.compareAndSet(s, s or CLOSED)) break
        }
        Ksl.udpClose(handle)
    }

    private fun enter(): Boolean {
        while (true) {
            val s = state.load()
            if (s and SHUT !=
                0
            ) {
                return false
            }
            if (state.compareAndSet(s, s + 1)) return true
        }
    }

    private fun leave() {
        state.addAndFetch(-1)
    }

    public companion object {
        public const val ECN: Int = KslConst.UDP_ECN
        public const val GSO: Int = KslConst.UDP_GSO
        public const val GRO: Int = KslConst.UDP_GRO
        public const val DF: Int = KslConst.UDP_DF
        public const val REUSEPORT: Int = KslConst.UDP_REUSEPORT
        public const val ADDR_LEN: Int = KslConst.UDP_ADDR_LEN
        public const val MAX_BATCH: Int = KslConst.UDP_MAX_BATCH
        private const val SHUT = 1 shl 30
        private const val CLOSED = 1 shl 29
        private const val COUNT = CLOSED - 1

        /** True where `ksl_udp` works (Linux, Android): learned once by opening a loopback socket. */
        public val supported: Boolean by lazy {
            KslLoader.ensureLoaded()
            try {
                Ksl.udpClose(Ksl.udpOpen(encodeAddress(byteArrayOf(127, 0, 0, 1), 0), 0))
                true
            } catch (
                e: KslException.Internal,
            ) {
                if (e.packed ==
                    KslConst.E_NOT_SUPPORTED
                ) {
                    false
                } else {
                    throw e
                }
            }
        }

        /** Opens and binds to [addr] (see [encodeAddress]) with the wanted [flags]; what the kernel granted is in [grantedFlags]. */
        public fun open(
            addr: ByteArray,
            flags: Int,
        ): KslUdpSocket {
            KslLoader.ensureLoaded()
            return KslUdpSocket(Ksl.udpOpen(addr, flags))
        }

        /** Encodes an IPv4 (4 bytes) or IPv6 (16 bytes) address and port into the `ADDR_LEN`-byte wire form. */
        public fun encodeAddress(
            ip: ByteArray,
            port: Int,
        ): ByteArray {
            require(ip.size == 4 || ip.size == 16) { "4 or 16 address bytes" }
            require(port in 0..65535)
            val a = ByteArray(ADDR_LEN)
            a[0] =
                if (ip.size ==
                    4
                ) {
                    4
                } else {
                    6
                }
            ; a[1] = (port ushr 8).toByte()
            a[2] = port.toByte()
            ip.copyInto(a, 3)
            return a
        }

        public fun portOf(addr: ByteArray): Int = ((addr[1].toInt() and 0xff) shl 8) or (addr[2].toInt() and 0xff)

        /** The 4 or 16 address bytes of an encoded address. */
        public fun ipOf(addr: ByteArray): ByteArray = addr.copyOfRange(3, if (addr[0].toInt() == 4) 7 else 19)

        private fun be32(
            b: ByteArray,
            off: Int,
        ): Int =
            ((b[off].toInt() and 0xff) shl 24) or ((b[off + 1].toInt() and 0xff) shl 16) or ((b[off + 2].toInt() and 0xff) shl 8) or
                (b[off + 3].toInt() and 0xff)
    }
}
