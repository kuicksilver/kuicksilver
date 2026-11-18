// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.server

import io.ktor.utils.io.ByteChannel
import io.ktor.utils.io.readByte
import io.ktor.utils.io.writeFully
import kotlinx.coroutines.async
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.yield
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** Test helpers: version 2 headers built byte by byte, as a proxy sends them. */
internal object ProxyV2 {
    val SIG = byteArrayOf(0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A)

    fun u16(v: Int) = byteArrayOf((v ushr 8).toByte(), v.toByte())

    fun tlv(
        type: Int,
        value: ByteArray,
    ) = byteArrayOf(type.toByte()) + u16(value.size) + value

    fun header(
        verCmd: Int = 0x21,
        fam: Int = 0x11,
        body: ByteArray,
        len: Int = body.size,
    ) = SIG + byteArrayOf(verCmd.toByte(), fam.toByte()) + u16(len) + body

    /** AF_INET 192.0.2.1:56324 -> 198.51.100.2:443, then [tlvs]. */
    fun inet(tlvs: ByteArray = ByteArray(0)) = byteArrayOf(192.toByte(), 0, 2, 1, 198.toByte(), 51, 100, 2) + u16(56324) + u16(443) + tlvs

    /** [header] with a CRC32c TLV over the whole header, computed as a proxy does (the field zero while summing). */
    fun withCrc(
        body: ByteArray,
        fam: Int = 0x11,
    ): ByteArray {
        val h = header(fam = fam, body = body + tlv(0x03, ByteArray(4)))
        val crc = ProxyProtocolCodec.crc32c(h)
        val at = h.size - 4
        for (i in 0 until 4) h[at + i] = (crc ushr (24 - 8 * i)).toByte()
        return h
    }
}

/**
 * The PROXY protocol header codec ("The PROXY protocol", HAProxy, versions 1 and 2): framing from the first bytes, decoding,
 * the TLVs and the CRC32c TLV, and the reader on a channel. Every malformed shape closes the connection, which the
 * codec reports as [ProxyProtocolException].
 */
class ProxyProtocolCodecTest {
    private fun ascii(s: String) = s.encodeToByteArray()

    private fun decode(b: ByteArray): ProxyHeader {
        assertEquals(b.size, ProxyProtocolCodec.frame(b, b.size, ProxyProtocolConfig.DEFAULT_MAX_HEADER_SIZE), "framed whole")
        return ProxyProtocolCodec.decode(b)
    }

    private fun refused(
        b: ByteArray,
        max: Int = ProxyProtocolConfig.DEFAULT_MAX_HEADER_SIZE,
        what: String? = null,
    ): ProxyProtocolException =
        assertFailsWith<ProxyProtocolException>(what) {
            // framed as a reader frames it, byte after byte, then decoded once complete
            var total = -1
            var n = 0
            while (n < b.size) {
                n++
                total = ProxyProtocolCodec.frame(b, n, max)
                if (total in 1..n) break
            }
            if (total in 1..b.size) ProxyProtocolCodec.decode(b.copyOf(total)) else error("not refused: framing wants $total of ${b.size}")
        }

    @Test fun v1Tcp4() {
        val h = decode(ascii("PROXY TCP4 192.0.2.1 198.51.100.2 56324 443\r\n"))
        assertEquals(1, h.version)
        assertEquals(ProxyCommand.Proxy, h.command)
        assertEquals(ProxyFamily.Inet, h.family)
        assertEquals(ProxyTransport.Stream, h.transport)
        assertEquals("192.0.2.1", h.sourceAddress)
        assertEquals(56324, h.sourcePort)
        assertEquals("198.51.100.2", h.destinationAddress)
        assertEquals(443, h.destinationPort)
        assertTrue(h.namesClient)
    }

    @Test fun v1Tcp6IsReportedInCanonicalText() {
        val h = decode(ascii("PROXY TCP6 2001:0DB8:85a3:0000:0000:8a2e:0370:7334 ::1 0 65535\r\n"))
        assertEquals(ProxyFamily.Inet6, h.family)
        assertEquals("2001:db8:85a3::8a2e:370:7334", h.sourceAddress)
        assertEquals("::1", h.destinationAddress)
        assertEquals(0, h.sourcePort)
        assertEquals(65535, h.destinationPort)
        assertEquals("::ffff:192.0.2.9", decode(ascii("PROXY TCP6 ::ffff:192.0.2.9 ::1 1 2\r\n")).sourceAddress)
    }

    @Test fun v1UnknownIgnoresWhatFollows() {
        for (line in listOf("PROXY UNKNOWN\r\n", "PROXY UNKNOWN anything\u0000at all 1 2\r\n", "PROXY UNKNOWN a lone \r here\r\n")) {
            val h = decode(ascii(line))
            assertEquals(ProxyFamily.Unspecified, h.family)
            assertNull(h.sourceAddress)
            assertFalse(h.namesClient)
        }
    }

    @Test fun v1LongestLineIsTaken() {
        val line = "PROXY UNKNOWN " + "x".repeat(107 - 16) + "\r\n"
        assertEquals(107, line.length)
        decode(ascii(line))
    }

    @Test fun negative_v1WithoutCrlfWithin107BytesIsRefused() {
        val e = refused(ascii("PROXY UNKNOWN " + "x".repeat(200)))
        assertTrue("107" in e.message!!, e.message)
        refused(ascii("PROXY UNKNOWN " + "x".repeat(107 - 15) + "\r\n")) // 108 bytes with its CRLF
    }

    @Test fun negative_v1LineEndsOtherThanCrlfAreRefused() {
        refused(ascii("PROXY TCP4 192.0.2.1 198.51.100.2 1 2\n"))
        refused(ascii("PROXY TCP4 192.0.2.1 198.51.100.2 1 2\r \n"))
        refused(ascii("PROXY TCP4 192.0.2.1\r198.51.100.2 1 2\r\n"))
    }

    @Test fun negative_v1MalformedFieldsAreRefused() {
        val bad =
            listOf(
                "proxy TCP4 192.0.2.1 198.51.100.2 1 2\r\n",
                "PROXY  TCP4 192.0.2.1 198.51.100.2 1 2\r\n",
                "PROXY TCP5 192.0.2.1 198.51.100.2 1 2\r\n",
                "PROXY UNKNOWNX\r\n",
                "PROXY TCP4 192.0.2.1 198.51.100.2 1\r\n",
                "PROXY TCP4 192.0.2.1 198.51.100.2 1 2 3\r\n",
                "PROXY TCP4 192.0.2.1  198.51.100.2 1 2\r\n",
                "PROXY TCP4 192.0.2.1 198.51.100.2 1 2 \r\n",
                "PROXY TCP4 ::1 198.51.100.2 1 2\r\n",
                "PROXY TCP6 192.0.2.1 ::1 1 2\r\n",
                "PROXY TCP6 ::ffff:192.0.2.1%eth0 ::1 1 2\r\n",
                "PROXY TCP6 [::1] ::1 1 2\r\n",
                "PROXY TCP4 192.0.2.01 198.51.100.2 1 2\r\n",
                "PROXY TCP4 192.0.2.256 198.51.100.2 1 2\r\n",
                "PROXY TCP4 192.0.2 198.51.100.2 1 2\r\n",
                "PROXY TCP4 host.test 198.51.100.2 1 2\r\n",
                "PROXY TCP4 192.0.2.1 198.51.100.2 01 2\r\n",
                "PROXY TCP4 192.0.2.1 198.51.100.2 65536 2\r\n",
                "PROXY TCP4 192.0.2.1 198.51.100.2 -1 2\r\n",
                "PROXY TCP4 192.0.2.1 198.51.100.2 +1 2\r\n",
                "PROXY TCP4 192.0.2.1 198.51.100.2 1 2\u0000\r\n",
                "PROXY\r\n",
                "GET / HTTP/1.1\r\n",
            )
        for (line in bad) refused(ascii(line), what = line)
    }

    @Test fun v2ProxyInet() {
        val h = decode(ProxyV2.header(body = ProxyV2.inet()))
        assertEquals(2, h.version)
        assertEquals(ProxyCommand.Proxy, h.command)
        assertEquals(ProxyFamily.Inet, h.family)
        assertEquals(ProxyTransport.Stream, h.transport)
        assertEquals("192.0.2.1", h.sourceAddress)
        assertEquals(56324, h.sourcePort)
        assertEquals("198.51.100.2", h.destinationAddress)
        assertEquals(443, h.destinationPort)
        assertTrue(h.tlvs.isEmpty())
    }

    @Test fun v2ProxyInet6AndDgram() {
        val src =
            ByteArray(16).also {
                it[0] = 0x20
                it[1] = 0x01
                it[2] = 0x0d
                it[3] = 0xb8.toByte()
                it[15] = 1
            }
        val dst = ByteArray(16).also { it[15] = 1 }
        val h = decode(ProxyV2.header(fam = 0x22, body = src + dst + ProxyV2.u16(1) + ProxyV2.u16(2)))
        assertEquals(ProxyFamily.Inet6, h.family)
        assertEquals(ProxyTransport.Dgram, h.transport)
        assertEquals("2001:db8::1", h.sourceAddress)
        assertEquals("::1", h.destinationAddress)
    }

    @Test fun v2ProxyUnixPaths() {
        val src = ByteArray(108).also { "/run/haproxy.sock".encodeToByteArray().copyInto(it) }
        val dst = ByteArray(108).also { "\u0000abstract".encodeToByteArray().copyInto(it) }
        val h = decode(ProxyV2.header(fam = 0x31, body = src + dst))
        assertEquals(ProxyFamily.Unix, h.family)
        assertEquals("/run/haproxy.sock", h.sourceAddress)
        assertEquals("@abstract", h.destinationAddress)
        assertNull(h.sourcePort)
        assertFalse(h.namesClient, "a path is no client IP address: the origin stays the TCP peer")
    }

    @Test fun v2LocalAndUnspecKeepTheRealAddresses() {
        // LOCAL: "the receiver must accept this connection as valid and must use the real connection endpoints and discard
        // the protocol block including the family which is ignored"
        val local = decode(ProxyV2.header(verCmd = 0x20, fam = 0x11, body = ProxyV2.inet(ProxyV2.tlv(0x77, ByteArray(2)))))
        assertEquals(ProxyCommand.Local, local.command)
        assertNull(local.sourceAddress)
        assertFalse(local.namesClient)
        val unspec = decode(ProxyV2.header(verCmd = 0x21, fam = 0x00, body = ByteArray(5)))
        assertEquals(ProxyFamily.Unspecified, unspec.family)
        assertFalse(unspec.namesClient)
        assertEquals(ProxyCommand.Local, decode(ProxyV2.header(verCmd = 0x20, fam = 0x00, body = ByteArray(0))).command)
    }

    @Test fun negative_v2BadVersionCommandOrFamilyIsRefused() {
        refused(ProxyV2.header(verCmd = 0x11, body = ProxyV2.inet())) // version 1 in the binary form
        refused(ProxyV2.header(verCmd = 0x31, body = ProxyV2.inet()))
        refused(ProxyV2.header(verCmd = 0x22, body = ProxyV2.inet())) // command 2 is unassigned
        for (fam in listOf(0x01, 0x13, 0x41, 0x10, 0xff)) refused(ProxyV2.header(fam = fam, body = ProxyV2.inet()))
        refused(ProxyV2.SIG.copyOf().also { it[11] = 0x0B } + byteArrayOf(0x21, 0x11, 0, 12) + ProxyV2.inet())
    }

    @Test fun negative_v2AddressBlockShorterThanItsFamilyIsRefused() {
        refused(ProxyV2.header(fam = 0x11, body = ByteArray(11)))
        refused(ProxyV2.header(fam = 0x21, body = ByteArray(35)))
        refused(ProxyV2.header(fam = 0x31, body = ByteArray(215)))
        refused(ProxyV2.header(verCmd = 0x20, fam = 0x21, body = ByteArray(12)))
    }

    @Test fun negative_v2HugeLengthIsRefusedFromTheFixedPartAlone() {
        val fixed = ProxyV2.SIG + byteArrayOf(0x21, 0x11) + ProxyV2.u16(0xffff)
        val e = assertFailsWith<ProxyProtocolException> { ProxyProtocolCodec.frame(fixed, fixed.size, 4096) }
        assertTrue("65551" in e.message!!, e.message)
        // the largest a v2 header can be is still framed when the limit allows it
        assertEquals(ProxyProtocolCodec.V2_MAX, ProxyProtocolCodec.frame(fixed, fixed.size, ProxyProtocolCodec.V2_MAX))
    }

    @Test fun v2Tlvs() {
        val ssl = byteArrayOf(0x07, 0, 0, 0, 0) + ProxyV2.tlv(0x21, ascii("TLSv1.3")) + ProxyV2.tlv(0x22, ascii("client.test"))
        val tlvs =
            ProxyV2.tlv(0x01, ascii("h2")) + ProxyV2.tlv(0x02, ascii("example.test")) + ProxyV2.tlv(0x04, ByteArray(3)) +
                ProxyV2.tlv(0x05, ByteArray(128) { it.toByte() }) + ProxyV2.tlv(0x20, ssl) + ProxyV2.tlv(0xE0, ByteArray(0))
        val h = decode(ProxyV2.header(body = ProxyV2.inet(tlvs)))
        assertEquals(listOf(0x01, 0x02, 0x05, 0x20, 0xE0), h.tlvs.map { it.type }, "NOOP is left out")
        assertEquals("h2", h.alpn)
        assertEquals("example.test", h.authority)
        assertContentEquals(ByteArray(128) { it.toByte() }, h.uniqueId)
        val s = h.ssl!!
        assertTrue(s.clientSsl)
        assertEquals(0L, s.verify)
        assertEquals("TLSv1.3", s.version)
        assertEquals("client.test", s.commonName)
        assertNull(s.cipher)
    }

    @Test fun negative_v2TlvOverrunningTheHeaderIsRefused() {
        // a TLV whose length goes past the length field's end
        refused(ProxyV2.header(body = ProxyV2.inet(byteArrayOf(0x02, 0, 5, 0x61, 0x62))))
        // a TLV header cut by the end
        refused(ProxyV2.header(body = ProxyV2.inet(byteArrayOf(0x02, 0))))
        refused(ProxyV2.header(body = ProxyV2.inet(byteArrayOf(0x02))))
        // an SSL TLV whose sub-TLV overruns the SSL TLV (but not the header)
        val ssl = byteArrayOf(0x01, 0, 0, 0, 0) + byteArrayOf(0x21, 0, 9, 0x41)
        refused(ProxyV2.header(body = ProxyV2.inet(ProxyV2.tlv(0x20, ssl) + ByteArray(8))))
        // an SSL TLV shorter than its fixed client and verify fields
        refused(ProxyV2.header(body = ProxyV2.inet(ProxyV2.tlv(0x20, ByteArray(4)))))
        // a unique ID over 128 bytes
        refused(ProxyV2.header(body = ProxyV2.inet(ProxyV2.tlv(0x05, ByteArray(129)))))
    }

    @Test fun crc32cVector() {
        // RFC 3720 appendix B.4 check value of CRC32c ("123456789")
        assertEquals(0xE3069283.toInt(), ProxyProtocolCodec.crc32c(ascii("123456789")))
        assertEquals(0x8A9136AA.toInt(), ProxyProtocolCodec.crc32c(ByteArray(32)))
    }

    @Test fun v2CrcThatMatchesIsTaken() {
        val h = decode(ProxyV2.withCrc(ProxyV2.inet(ProxyV2.tlv(0x02, ascii("example.test")))))
        assertEquals(listOf(0x02, 0x03), h.tlvs.map { it.type })
        decode(ProxyV2.withCrc(ByteArray(36), fam = 0x21))
    }

    @Test fun negative_v2CrcMismatchIsRefused() {
        val h = ProxyV2.withCrc(ProxyV2.inet(ProxyV2.tlv(0x02, ascii("example.test"))))
        // the addresses and ports, the AUTHORITY value and the checksum itself; a flipped type or length byte frames other
        // TLVs (a CRC TLV turned into another type is no CRC TLV: nothing can authenticate its presence), and a flipped
        // command bit makes a LOCAL header, whose block is discarded unread
        val covered = (16..27) + (31..42) + (46..49)
        assertEquals(50, h.size)
        for (i in covered) {
            val bad = h.copyOf().also { it[i] = (it[i].toInt() xor 0x01).toByte() }
            refused(bad, what = "flipped byte $i")
        }
    }

    @Test fun negative_v2CrcTlvOfAnotherLengthOrTwiceIsRefused() {
        refused(ProxyV2.header(body = ProxyV2.inet(ProxyV2.tlv(0x03, ByteArray(3)))))
        val twice = ProxyV2.header(body = ProxyV2.inet(ProxyV2.tlv(0x03, ByteArray(4)) + ProxyV2.tlv(0x03, ByteArray(4))))
        refused(twice)
    }

    @Test fun readerTakesAHeaderSplitIntoSingleBytesAndLeavesWhatFollows() =
        runTest {
            for (header in listOf(ascii("PROXY TCP4 192.0.2.1 198.51.100.2 56324 443\r\n"), ProxyV2.header(body = ProxyV2.inet()))) {
                val ch = ByteChannel()
                val read = async { ch.readProxyHeader(4096) }
                for (b in header + ascii("GET")) {
                    ch.writeFully(byteArrayOf(b))
                    ch.flush()
                    yield()
                }
                assertEquals("192.0.2.1", read.await().sourceAddress)
                // the bytes after the header, pipelined with it, are still there for HTTP or TLS
                assertEquals('G'.code.toByte(), ch.readByte())
                assertEquals('E'.code.toByte(), ch.readByte())
                assertEquals('T'.code.toByte(), ch.readByte())
            }
        }

    @Test fun readerLeavesBytesThatCameInTheSameWrite() =
        runTest {
            val ch = ByteChannel()
            ch.writeFully(ProxyV2.header(body = ProxyV2.inet()) + ascii("\u0016\u0003\u0001"))
            ch.flush()
            assertEquals(443, ch.readProxyHeader(4096).destinationPort)
            assertEquals(0x16.toByte(), ch.readByte(), "the ClientHello's first byte")
        }

    @Test fun negative_readerFailsOnAConnectionThatEndsInsideTheHeader() =
        runTest {
            val ch = ByteChannel()
            ch.writeFully(ascii("PROXY TCP4 192.0.2.1"))
            ch.flushAndClose()
            assertFailsWith<ProxyProtocolException> { ch.readProxyHeader(4096) }
        }

    @Test fun negative_readerRefusesAHugeV2LengthWithoutWaitingForTheBody() =
        runTest {
            val ch = ByteChannel()
            ch.writeFully(ProxyV2.SIG + byteArrayOf(0x21, 0x11) + ProxyV2.u16(0xffff))
            ch.flush() // never closed: a reader that waited for the 65535 bytes would hang here
            assertFailsWith<ProxyProtocolException> { ch.readProxyHeader(4096) }
        }

    @Test fun negative_readerRefusesAV1LineWithoutCrlfWithoutWaitingForMore() =
        runTest {
            val ch = ByteChannel()
            ch.writeFully(ascii("PROXY UNKNOWN " + "x".repeat(93)))
            ch.flush() // 107 bytes, no CRLF, the channel left open
            assertFailsWith<ProxyProtocolException> { ch.readProxyHeader(4096) }
        }
}
