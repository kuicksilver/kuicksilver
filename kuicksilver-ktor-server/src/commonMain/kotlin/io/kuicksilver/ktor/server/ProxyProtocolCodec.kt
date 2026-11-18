// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(io.kuicksilver.annotations.InternalKuicksilverApi::class)

package io.kuicksilver.ktor.server

import io.ktor.utils.io.ByteReadChannel
import io.ktor.utils.io.ClosedByteChannelException
import io.ktor.utils.io.readByte
import io.ktor.utils.io.readFully
import io.kuicksilver.quic.ipLiteralOf
import kotlinx.io.EOFException
import kotlinx.io.IOException

/** A PROXY protocol header that is malformed, too long, cut or late: the connection is closed. */
internal class ProxyProtocolException(
    message: String,
) : IOException(message)

/**
 * The PROXY protocol header ("The PROXY protocol", HAProxy, versions 1 and 2; quoted below as "the spec"), sans-IO: [frame]
 * tells from the first bytes how long the header is, or that it cannot be one, and [decode] reads a complete header. Every
 * shape the spec does not define is refused ([ProxyProtocolException]): "any sequence which does not exactly match the
 * protocol must be discarded and cause the receiver to abort the connection".
 */
internal object ProxyProtocolCodec {
    /** Version 1: "a 108-byte buffer is always enough to store all the line and a trailing zero", the line at most 107 bytes. */
    const val V1_MAX = 107

    /** Version 2: the signature, the version and command byte, the family byte and the 16-bit length. */
    const val V2_FIXED = 16

    /** Version 2: the fixed part and the largest length field. */
    const val V2_MAX = V2_FIXED + 0xffff

    private val V1_PREFIX = "PROXY ".encodeToByteArray()
    private val V2_SIGNATURE = byteArrayOf(0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A)

    /**
     * From the first [n] bytes of the connection in [buf]: the header's length once it is known (version 1: its LF has
     * arrived; version 2: its 16 fixed bytes have), else -1 (one more byte is needed). Throws as soon as the bytes cannot
     * begin a header: a first byte that starts neither version, a version 1 line with no CRLF within [V1_MAX] bytes, a
     * version 2 header with another signature, version, command or family, or one longer than [maxSize] (before its
     * body is read). Each call looks only at what the previous one had not seen, so the bytes may be offered one at a time.
     */
    fun frame(
        buf: ByteArray,
        n: Int,
        maxSize: Int,
    ): Int {
        if (n == 0) return -1
        return when (buf[0]) {
            V1_PREFIX[0] -> frameV1(buf, n)
            V2_SIGNATURE[0] -> frameV2(buf, n, maxSize)
            else -> throw ProxyProtocolException("the connection does not start with a PROXY protocol header")
        }
    }

    private fun frameV1(
        buf: ByteArray,
        n: Int,
    ): Int {
        val i = n - 1
        val b = buf[i]
        if (i < V1_PREFIX.size && b != V1_PREFIX[i]) throw ProxyProtocolException("not a PROXY protocol version 1 line")
        // the line ends at its first LF, which must follow a CR ("the CRLF sequence"); a CR elsewhere is no valid field byte
        // of a TCP4 or TCP6 line (decode refuses it there) and is ignored after UNKNOWN, as anything is
        if (b == LF) {
            if (i == 0 || buf[i - 1] != CR) throw ProxyProtocolException("the PROXY line ends with LF instead of CRLF")
            return n
        }
        // "If the receiver doesn't find the CRLF sequence within the first 107 characters, it must declare the line invalid"
        if (n >= V1_MAX) throw ProxyProtocolException("no CRLF within the first $V1_MAX bytes of the PROXY line")
        return -1
    }

    private fun frameV2(
        buf: ByteArray,
        n: Int,
        maxSize: Int,
    ): Int {
        val i = n - 1
        if (i < V2_SIGNATURE.size) {
            if (buf[i] != V2_SIGNATURE[i]) throw ProxyProtocolException("not the PROXY protocol version 2 signature")
            return -1
        }
        if (i == 12) {
            val v = buf[12].toInt() and 0xff
            // "\x2 : this is version 2 of the protocol. Only this value is valid" and "Receivers must only accept this value"
            if (v ushr 4 != 2) throw ProxyProtocolException("PROXY protocol version ${v ushr 4} in a version 2 header")
            // commands other than LOCAL and PROXY "MUST NOT be emitted by senders. Receivers MUST drop connections presenting
            // unexpected values here"
            if (v and 0xf > 1) throw ProxyProtocolException("PROXY protocol version 2 command ${v and 0xf} is unassigned")
            return -1
        }
        if (i == 13) {
            // "Other values are unspecified and must not be emitted in version 2 of this protocol and must be rejected as
            // invalid by receivers"
            val f = buf[13].toInt() and 0xff
            if (f !in FAMILIES) throw ProxyProtocolException("PROXY protocol version 2 family and transport 0x${f.toString(16)}")
            return -1
        }
        if (n < V2_FIXED) return -1
        val total = V2_FIXED + u16(buf, 14)
        if (total > maxSize) throw ProxyProtocolException("a PROXY protocol version 2 header of $total bytes, over the limit of $maxSize")
        return total
    }

    /**
     * A complete header, decoded as the spec defines it. It checks the whole header again, whatever [frame] saw (which looks
     * at each byte once, as it arrives): the same bytes framed and decoded in one piece are judged alike.
     */
    fun decode(header: ByteArray): ProxyHeader {
        if (header.isEmpty()) throw ProxyProtocolException("an empty PROXY protocol header")
        val maxSize = if (header[0] == V1_PREFIX[0]) V1_MAX else V2_MAX
        if (header.size > maxSize) throw ProxyProtocolException("a PROXY protocol header of ${header.size} bytes")
        var total = -1
        for (n in 1..header.size) {
            total = frame(header, n, maxSize)
            if (total >= 0) break
        }
        if (total != header.size) throw ProxyProtocolException("a PROXY protocol header of ${header.size} bytes framed as $total")
        return if (header[0] == V1_PREFIX[0]) decodeV1(header) else decodeV2(header)
    }

    private fun decodeV1(h: ByteArray): ProxyHeader {
        val line = CharArray(h.size - V1_PREFIX.size - 2) { (h[V1_PREFIX.size + it].toInt() and 0xff).toChar() }.concatToString()
        if (line.startsWith("UNKNOWN") && (line.length == 7 || line[7] == ' ')) {
            // "the receiver must ignore anything presented before the CRLF is found" and use the real connection's addresses
            return ProxyHeader(
                1,
                ProxyCommand.Proxy,
                ProxyFamily.Unspecified,
                ProxyTransport.Unspecified,
                null,
                null,
                null,
                null,
                emptyList(),
            )
        }
        val v6 =
            when {
                line.startsWith("TCP4 ") -> false
                line.startsWith("TCP6 ") -> true
                else -> throw ProxyProtocolException("PROXY line protocol is not TCP4, TCP6 or UNKNOWN")
            }
        // exactly one space between the fields: "a single space", nothing before the CRLF
        val fields = line.substring(5).split(' ')
        if (fields.size != 4) throw ProxyProtocolException("PROXY line has ${fields.size} fields after the protocol, not 4")
        val src = if (v6) v1Ipv6(fields[0]) else v1Ipv4(fields[0])
        val dst = if (v6) v1Ipv6(fields[1]) else v1Ipv4(fields[1])
        return ProxyHeader(
            1,
            ProxyCommand.Proxy,
            if (v6) ProxyFamily.Inet6 else ProxyFamily.Inet,
            ProxyTransport.Stream,
            ipLiteralOf(src),
            v1Port(fields[2]),
            ipLiteralOf(dst),
            v1Port(fields[3]),
            emptyList(),
            src,
        )
    }

    /** A dotted quad of four decimal numbers 0..255 without leading zeros (which some parsers read as octal). */
    private fun v1Ipv4(s: String): ByteArray {
        val parts = s.split('.')
        if (parts.size != 4) throw ProxyProtocolException("not an IPv4 address in the PROXY line")
        return ByteArray(4) { i ->
            val p = parts[i]
            if (p.isEmpty() || p.length > 3 || !p.all { it in '0'..'9' } || (p.length > 1 && p[0] == '0') || p.toInt() > 255) {
                throw ProxyProtocolException("not an IPv4 address in the PROXY line")
            }
            p.toInt().toByte()
        }
    }

    /** An IPv6 address in RFC 4291 section 2.2 text: no brackets, no zone ID. */
    private fun v1Ipv6(s: String): ByteArray {
        if (':' !in s ||
            s.any { it == '[' || it == ']' || it == '%' }
        ) {
            throw ProxyProtocolException("not an IPv6 address in the PROXY line")
        }
        val b = parseIpLiteral(s)
        if (b == null || b.size != 16) throw ProxyProtocolException("not an IPv6 address in the PROXY line")
        return b
    }

    /** A decimal port 0..65535 without leading zeros (as nghttpx's `parse_proxy_line_port`). */
    private fun v1Port(s: String): Int {
        if (s.isEmpty() || s.length > 5 || !s.all { it in '0'..'9' } || (s.length > 1 && s[0] == '0') || s.toInt() > 0xffff) {
            throw ProxyProtocolException("not a port in the PROXY line")
        }
        return s.toInt()
    }

    private fun decodeV2(h: ByteArray): ProxyHeader {
        val local = h[12].toInt() and 0xf == 0
        val fam = h[13].toInt() and 0xff
        val family =
            when (fam ushr 4) {
                1 -> ProxyFamily.Inet
                2 -> ProxyFamily.Inet6
                3 -> ProxyFamily.Unix
                else -> ProxyFamily.Unspecified
            }
        val transport =
            when (fam and 0xf) {
                1 -> ProxyTransport.Stream
                2 -> ProxyTransport.Dgram
                else -> ProxyTransport.Unspecified
            }
        val addressBytes =
            when (family) {
                ProxyFamily.Inet -> 12
                ProxyFamily.Inet6 -> 36
                ProxyFamily.Unix -> 216
                ProxyFamily.Unspecified -> 0
            }
        // the length "must be at least" the size of the family's addresses: a shorter block is invalid whatever the command
        if (h.size - V2_FIXED < addressBytes) {
            throw ProxyProtocolException(
                "a PROXY protocol version 2 block of ${h.size - V2_FIXED} bytes for $family addresses of $addressBytes",
            )
        }
        // LOCAL: "the receiver must accept this connection as valid and must use the real connection endpoints and discard
        // the protocol block including the family which is ignored"; AF_UNSPEC: "the receiver ... must ignore the address
        // information" (HAProxy reads TLVs only after INET and INET6 addresses, from memory of its source)
        if (local || family == ProxyFamily.Unspecified) {
            return ProxyHeader(
                2,
                if (local) ProxyCommand.Local else ProxyCommand.Proxy,
                family,
                transport,
                null,
                null,
                null,
                null,
                emptyList(),
            )
        }
        val tlvs = tlvs(h, V2_FIXED + addressBytes, h.size, outer = true)
        return when (family) {
            ProxyFamily.Inet, ProxyFamily.Inet6 -> {
                val len = if (family == ProxyFamily.Inet) 4 else 16
                val src = h.copyOfRange(V2_FIXED, V2_FIXED + len)
                val dst = h.copyOfRange(V2_FIXED + len, V2_FIXED + 2 * len)
                ProxyHeader(
                    2,
                    ProxyCommand.Proxy,
                    family,
                    transport,
                    ipLiteralOf(src),
                    u16(h, V2_FIXED + 2 * len),
                    ipLiteralOf(dst),
                    u16(h, V2_FIXED + 2 * len + 2),
                    tlvs,
                    src,
                )
            }

            else -> {
                ProxyHeader(2, ProxyCommand.Proxy, family, transport, unixPath(h, V2_FIXED), null, unixPath(h, V2_FIXED + 108), null, tlvs)
            }
        }
    }

    /** A 108-byte `sun_path`: up to its first NUL; an abstract one (a NUL first) as `@` and its name up to the next NUL. */
    private fun unixPath(
        h: ByteArray,
        at: Int,
    ): String {
        val abstract = h[at].toInt() == 0
        val from = if (abstract) at + 1 else at
        var end = from
        while (end < at + 108 && h[end].toInt() != 0) end++
        val path = h.decodeToString(from, end)
        return if (abstract) "@$path" else path
    }

    /**
     * The TLVs in [from] until [to] of [h]; each must fit there whole ("TLVs ... must not exceed the header length"), else
     * the header is refused. In the [outer] list: PP2_TYPE_CRC32C must be 4 bytes and match (at most one), PP2_TYPE_UNIQUE_ID
     * at most 128 bytes, PP2_TYPE_SSL a valid structure; PP2_TYPE_NOOP is left out. Unknown types are kept as they are.
     */
    private fun tlvs(
        h: ByteArray,
        from: Int,
        to: Int,
        outer: Boolean,
    ): List<ProxyTlv> {
        val out = ArrayList<ProxyTlv>()
        var crcAt = -1
        var p = from
        while (p < to) {
            if (to - p < 3) throw ProxyProtocolException("a PROXY protocol TLV cut by the end of its block")
            val type = h[p].toInt() and 0xff
            val len = u16(h, p + 1)
            if (len > to - p - 3) throw ProxyProtocolException("a PROXY protocol TLV of $len bytes past the end of its block")
            val value = h.copyOfRange(p + 3, p + 3 + len)
            if (outer) {
                when (type) {
                    ProxyHeader.PP2_TYPE_CRC32C -> {
                        // "the value ... is a 32-bit number": another length cannot be checked; a second one would leave which
                        // field was zeroed while summing undefined
                        if (len != 4) throw ProxyProtocolException("a PROXY protocol CRC32c TLV of $len bytes")
                        if (crcAt >= 0) throw ProxyProtocolException("two PROXY protocol CRC32c TLVs")
                        crcAt = p + 3
                    }

                    ProxyHeader.PP2_TYPE_UNIQUE_ID -> {
                        // "The value of the type PP2_TYPE_UNIQUE_ID is an opaque byte sequence of up to 128 bytes"
                        if (len > 128) throw ProxyProtocolException("a PROXY protocol unique ID of $len bytes")
                    }

                    ProxyHeader.PP2_TYPE_SSL -> {
                        ssl(value)
                    }
                }
            }
            if (!outer || type != ProxyHeader.PP2_TYPE_NOOP) out += ProxyTlv(type, value)
            p += 3 + len
        }
        if (crcAt >= 0) checkCrc(h, crcAt)
        return out
    }

    /**
     * "the receiver MUST: Store the received CRC32c checksum value aside. Replace the 32 bits of the checksum field in the
     * received PROXY header with all '0's and calculate a CRC32c checksum value of the whole PROXY header. Verify that the
     * calculated CRC32c checksum is the same as the received CRC32c checksum. If it is not, the receiver MUST treat the TCP
     * connection providing the header as invalid." The value is in network byte order.
     */
    private fun checkCrc(
        h: ByteArray,
        at: Int,
    ) {
        val received = (u16(h, at) shl 16) or u16(h, at + 2)
        val zeroed = h.copyOf()
        for (i in 0 until 4) zeroed[at + i] = 0
        if (crc32c(zeroed) != received) throw ProxyProtocolException("the PROXY protocol header's CRC32c does not match")
    }

    /** A `PP2_TYPE_SSL` value: `client` (1 byte), `verify` (4 bytes), then sub-TLVs that fill the rest exactly. */
    fun ssl(value: ByteArray): ProxySsl {
        if (value.size < 5) throw ProxyProtocolException("a PROXY protocol SSL TLV of ${value.size} bytes")
        val verify = ((u16(value, 1).toLong() shl 16) or u16(value, 3).toLong())
        return ProxySsl(value[0].toInt() and 0xff, verify, tlvs(value, 5, value.size, outer = false))
    }

    /** CRC32c (Castagnoli, the polynomial 0x1EDC6F41 reflected as 0x82F63B78; RFC 3720 appendix B.4) of [len] bytes at [off]. */
    fun crc32c(
        b: ByteArray,
        off: Int = 0,
        len: Int = b.size - off,
    ): Int {
        var c = -1
        for (i in off until off + len) c = CRC_TABLE[(c xor b[i].toInt()) and 0xff] xor (c ushr 8)
        return c.inv()
    }

    private val CRC_TABLE =
        IntArray(256) { n ->
            var c = n
            repeat(8) { c = if (c and 1 != 0) (c ushr 1) xor 0x82F63B78.toInt() else c ushr 1 }
            c
        }

    /** The family and transport bytes the spec defines: UNSPEC, then STREAM and DGRAM of INET, INET6 and UNIX. */
    private val FAMILIES = setOf(0x00, 0x11, 0x12, 0x21, 0x22, 0x31, 0x32)

    private const val CR: Byte = 0x0D
    private const val LF: Byte = 0x0A

    private fun u16(
        b: ByteArray,
        at: Int,
    ): Int = ((b[at].toInt() and 0xff) shl 8) or (b[at + 1].toInt() and 0xff)
}

/**
 * Reads one PROXY protocol header from the start of this connection's input, and not a byte more: what follows it (the
 * request, the ClientHello), sent in the same segment or later, stays in the channel. The receiver "may be tolerant to
 * partial headers": a header split over any number of reads is taken. Throws [ProxyProtocolException] for a malformed
 * header, one over [maxSize] bytes (known from the fixed part of version 2, before the rest is read; version 1 is never
 * over 107 bytes), and a connection that ends inside it. Bounding the time is the caller's.
 */
internal suspend fun ByteReadChannel.readProxyHeader(maxSize: Int): ProxyHeader {
    var buf = ByteArray(ProxyProtocolCodec.V1_MAX)
    var n = 0
    try {
        while (true) {
            val total = ProxyProtocolCodec.frame(buf, n, maxSize)
            if (total in 1..n) return ProxyProtocolCodec.decode(buf.copyOf(total))
            if (total > n) {
                if (buf.size < total) buf = buf.copyOf(total)
                readFully(buf, n, total)
                n = total
                continue
            }
            buf[n] = readByte()
            n++
        }
    } catch (e: EOFException) {
        throw ProxyProtocolException("the connection ended inside the PROXY protocol header after $n bytes")
    } catch (e: ClosedByteChannelException) {
        throw ProxyProtocolException("the connection failed inside the PROXY protocol header after $n bytes: ${e.cause ?: e}")
    }
}
