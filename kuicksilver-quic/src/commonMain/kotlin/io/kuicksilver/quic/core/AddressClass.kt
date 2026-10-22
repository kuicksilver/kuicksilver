// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.core

import io.ktor.network.sockets.InetSocketAddress
import io.kuicksilver.quic.ipBytesNoDns

/** Address classification for admission and path decisions (threat-model 3.1). */
internal object AddressClass {
    /** Source ports of UDP services commonly abused for reflection (DNS, NTP, SSDP, mDNS, memcached); an Initial "from" one of them is answered with silence. */
    private val reflectivePorts = intArrayOf(53, 123, 1900, 5353, 11211)

    /** The raw IPv4 (4) or IPv6 (16) address bytes; the hostname's bytes for a host name (never a resolver call: see [ipBytesNoDns]). */
    fun ipBytes(a: InetSocketAddress): ByteArray = a.ipBytesNoDns() ?: a.hostname.encodeToByteArray()

    fun isLoopback(a: InetSocketAddress): Boolean {
        val b = ipBytes(a)
        return when (b.size) {
            4 -> {
                b[0].toInt() == 127
            }

            16 -> {
                (isV4Mapped(b) && b[12].toInt() == 127) ||
                    (b.copyOf(15).all { it.toInt() == 0 } && b[15].toInt() == 1)
            }

            else -> {
                false
            }
        }
    }

    fun isLinkLocal(a: InetSocketAddress): Boolean {
        val b = ipBytes(a)
        return when (b.size) {
            4 -> {
                b[0].toInt() and 0xff == 169 &&
                    b[1].toInt() and 0xff == 254
            }

            16 -> {
                if (isV4Mapped(b)) {
                    b[12].toInt() and 0xff == 169 && b[13].toInt() and 0xff == 254
                } else {
                    b[0].toInt() and
                        0xff ==
                        0xfe &&
                        b[1].toInt() and 0xc0 == 0x80
                }
            }

            else -> {
                false
            }
        }
    }

    /** The address of raw IPv4 (4 bytes) or IPv6 (16) [ip] and [port], as an IP literal (no resolver). */
    fun addressOf(
        ip: ByteArray,
        port: Int,
    ): InetSocketAddress =
        InetSocketAddress(
            if (ip.size ==
                4
            ) {
                ip.joinToString(".") { (it.toInt() and 0xff).toString() }
            } else {
                io.kuicksilver.quic.KslDatagramIo
                    .ipv6Text(ip, 0)
            },
            port,
        )

    /**
     * Where a client must never be sent by a public server (threat-model 3.14, as `AltSvcDestination` rules): loopback, link-local,
     * private (RFC 1918, RFC 6598, `fc00::/7`), unspecified, multicast or broadcast. [localOnly] with an origin on such an
     * address: only the always-refused classes (unspecified, multicast, broadcast) count.
     */
    fun isUnsafeDestination(
        a: InetSocketAddress,
        originLocal: Boolean,
    ): Boolean {
        val raw = ipBytes(a)
        val b = if (raw.size == 16 && isV4Mapped(raw)) raw.copyOfRange(12, 16) else raw
        val always =
            when (b.size) {
                4 -> b.all { it.toInt() == 0 } || (b[0].toInt() and 0xf0) == 0xe0 || b.all { it.toInt() and 0xff == 0xff }
                16 -> b.all { it.toInt() == 0 } || (b[0].toInt() and 0xff) == 0xff
                else -> true // a host name: never a preferred address
            }
        if (always) return true
        if (originLocal) return false
        return isLoopback(a) || isLinkLocal(a) || isPrivate(b)
    }

    /** RFC 1918, RFC 6598 (100.64/10) and unique local IPv6 (`fc00::/7`). */
    private fun isPrivate(b: ByteArray): Boolean =
        when (b.size) {
            4 -> {
                val a0 = b[0].toInt() and 0xff
                val a1 = b[1].toInt() and 0xff
                a0 == 10 || (a0 == 172 && a1 in 16..31) || (a0 == 192 && a1 == 168) || (a0 == 100 && a1 in 64..127)
            }

            16 -> {
                (b[0].toInt() and 0xfe) == 0xfc
            }

            else -> {
                false
            }
        }

    /** Whether [a] is in one of the local classes ([isUnsafeDestination] without the always-refused ones): loopback, link-local, private. */
    fun isLocalNetwork(a: InetSocketAddress): Boolean {
        val raw = ipBytes(a)
        val b = if (raw.size == 16 && isV4Mapped(raw)) raw.copyOfRange(12, 16) else raw
        return isLoopback(a) || isLinkLocal(a) || isPrivate(b)
    }

    fun isReflectivePort(port: Int): Boolean {
        for (p in reflectivePorts) if (p == port) return true
        return false
    }

    private fun isV4Mapped(b: ByteArray): Boolean {
        for (i in 0 until 10) {
            if (b[i].toInt() !=
                0
            ) {
                return false
            }
        }
        return b[10].toInt() == -1 && b[11].toInt() == -1
    }

    /** A hash key over the IP address alone (port ignored), for per-address counting. */
    class IpKey(
        private val bytes: ByteArray,
    ) {
        override fun equals(other: Any?): Boolean = other is IpKey && other.bytes.contentEquals(bytes)

        override fun hashCode(): Int = bytes.contentHashCode()
    }

    fun ipKey(a: InetSocketAddress): IpKey = IpKey(ipBytes(a))

    /** A hash key over the IP address bytes and the port: one peer however its address is spelled (Kotlin/Native's InetSocketAddress compares the text). */
    class AddrKey(
        private val bytes: ByteArray,
        private val port: Int,
    ) {
        override fun equals(other: Any?): Boolean = other is AddrKey && other.port == port && other.bytes.contentEquals(bytes)

        override fun hashCode(): Int = bytes.contentHashCode() * 31 + port
    }

    fun addrKey(a: InetSocketAddress): AddrKey = AddrKey(ipBytes(a), a.port)
}
