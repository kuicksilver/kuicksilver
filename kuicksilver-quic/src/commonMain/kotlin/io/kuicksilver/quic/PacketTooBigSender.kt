// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic

import io.ktor.network.sockets.InetSocketAddress
import io.kuicksilver.annotations.InternalKuicksilverApi
import io.kuicksilver.tls.KslIcmp

/**
 * ICMP Packet Too Big through a send-only raw socket (`ksl_icmp_*`), for a CONNECT-UDP proxy (RFC 9298 section 6.1): IPv4
 * type 3 code 4 with the Next-Hop MTU, ICMPv6 type 2 with the MTU, quoting the datagram the target sent. Only where the
 * process holds the privilege (Linux and Android with CAP_NET_RAW): [open] answers null elsewhere. One socket per family,
 * opened at the first send of that family; [close] closes them. Not thread-safe: one tunnel's reader uses it.
 */
@InternalKuicksilverApi
public class PacketTooBigSender private constructor() : AutoCloseable {
    private var v4 = -1
    private var v6 = -1
    private var closed = false
    private val out = ByteArray(KslIcmp.PTB_MAX)
    private val err = IntArray(1)

    /**
     * Sends the Packet Too Big for the UDP datagram of `payload[0, len)` that came from [target] to [local] (the proxy's
     * address it arrived on, also the message's source) and does not fit [mtu]; false when it was not sent (the
     * arguments ruled it out, the family's socket could not be opened, or the kernel refused it).
     */
    public fun send(
        target: InetSocketAddress,
        local: InetSocketAddress,
        payload: ByteArray,
        len: Int,
        mtu: Int,
    ): Boolean {
        if (closed) return false
        val t = encode(target) ?: return false
        val l = encode(local) ?: return false
        if (t[0] != l[0]) return false
        val v6Family = t[0].toInt() == 6
        val fd = if (v6Family) v6.takeIf { it >= 0 } ?: open(6).also { v6 = it } else v4.takeIf { it >= 0 } ?: open(4).also { v4 = it }
        if (fd < 0) return false
        val n = KslIcmp.ptbBuild(out, t, l, payload, len, mtu)
        return n > 0 && KslIcmp.send(fd, out, n, t, l)
    }

    private fun open(family: Int): Int = KslIcmp.open(family, err)

    override fun close() {
        closed = true
        if (v4 >= 0) KslIcmp.close(v4)
        if (v6 >= 0) KslIcmp.close(v6)
        v4 = -1
        v6 = -1
    }

    /** Opening a sender: one that can send, or why none can. */
    public companion object {
        /**
         * Probes for the privilege once per call (opens and closes a raw IPv4 ICMP socket, then IPv6): a sender when either
         * family opens, else null and [Probe.reason] (no native library, not Linux or Android, no CAP_NET_RAW).
         */
        public fun probe(): Probe {
            try {
                KslIcmp.ensureLoaded()
            } catch (e: Throwable) {
                return Probe(false, "no native library: ${e.message}")
            }
            val e = IntArray(1)
            for (family in intArrayOf(4, 6)) {
                val fd = KslIcmp.open(family, e)
                if (fd >= 0) {
                    KslIcmp.close(fd)
                    return Probe(true, "raw ICMP sockets open")
                }
            }
            return if (e[0] == KslIcmp.E_NOT_SUPPORTED) {
                Probe(false, "not supported on this platform")
            } else {
                Probe(false, "no privilege to open a raw ICMP socket (errno ${e[0]}; Linux needs CAP_NET_RAW)")
            }
        }

        /** A sender; call only after [probe] said one can be opened. */
        public fun create(): PacketTooBigSender = PacketTooBigSender()

        /** A `ksl` address (family, port, 16 address bytes, pad) from an IP literal; null for a name. */
        private fun encode(a: InetSocketAddress): ByteArray? {
            val b = a.ipBytesNoDns() ?: return null
            val out = ByteArray(KslIcmp.ADDR_LEN)
            out[0] = if (b.size == 4) 4 else 6
            out[1] = (a.port shr 8).toByte()
            out[2] = a.port.toByte()
            b.copyInto(out, 3)
            return out
        }
    }

    /** The result of [probe]: whether a raw ICMP socket opened, and why not. */
    public class Probe(
        public val available: Boolean,
        public val reason: String,
    )
}
