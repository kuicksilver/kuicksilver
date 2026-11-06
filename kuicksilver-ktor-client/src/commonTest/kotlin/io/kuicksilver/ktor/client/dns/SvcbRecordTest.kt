// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.client.dns

import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** Bytes from a hex string; spaces are ignored. */
internal fun hex(s: String): ByteArray {
    val h = s.filterNot { it.isWhitespace() }
    return ByteArray(h.length / 2) { h.substring(2 * it, 2 * it + 2).toInt(16).toByte() }
}

/** `foo.example.com.` and `foo.example.org.` in wire format. */
internal const val FOO_EXAMPLE_COM = "03666f6f 076578616d706c65 03636f6d 00"
internal const val FOO_EXAMPLE_ORG = "03666f6f 076578616d706c65 036f7267 00"

/**
 * The SVCB/HTTPS RDATA codec against the wire-format test vectors of RFC 9460 Appendix D (D.1, D.2) and the malformed
 * cases of section 2.2, section 7 and Appendix D.3: a malformed RR is an error (the caller rejects the RRSet, section 2.2),
 * an RR that only cannot be used (an unknown mandatory key, section 8) is skipped.
 */
class SvcbRecordTest {
    private fun parse(
        rdata: String,
        owner: String = "example.com",
    ): SvcbRecord? = hex(rdata).let { SvcbCodec.parseRdata(it, 0, it.size, owner, 300) }

    private fun parsed(rdata: String): SvcbRecord = assertNotNull(parse(rdata))

    private fun malformed(rdata: String) {
        assertFailsWith<DnsFormatException> { parse(rdata) }
    }

    // ---- RFC 9460 Appendix D.1 and D.2 (Figures 2 to 10)

    @Test fun aliasModeVector() { // Figure 2: example.com. HTTPS 0 foo.example.com.
        val r = parsed("0000 $FOO_EXAMPLE_COM")
        assertEquals(0, r.priority)
        assertEquals("foo.example.com", r.target)
        assertTrue(r.isAlias)
    }

    @Test fun dotTargetVector() { // Figure 3: example.com. SVCB 1 .
        val r = parsed("0001 00")
        assertEquals(1, r.priority)
        assertEquals(".", r.target)
        assertEquals("example.com", r.serviceHost)
    }

    @Test fun serviceModePortVector() { // Figure 4: example.com. SVCB 16 foo.example.com. port=53
        val r = parsed("0010 $FOO_EXAMPLE_COM 0003 0002 0035")
        assertEquals(16, r.priority)
        assertEquals(53, r.port)
    }

    @Test fun genericKeyVectors() { // Figures 5 and 6: key667=hello, key667="hello\210qoo" are ignored
        assertNull(parsed("0001 $FOO_EXAMPLE_COM 029b 0005 68656c6c6f").port)
        assertEquals(emptyList(), parsed("0001 $FOO_EXAMPLE_COM 029b 0009 68656c6c6fd2716f6f").alpn)
    }

    @Test fun ipv6HintVector() { // Figure 7: ipv6hint="2001:db8::1,2001:db8::53:1"
        val r =
            parsed(
                "0001 $FOO_EXAMPLE_COM 0006 0020 20010db8000000000000000000000001 20010db8000000000000000000530001",
            )
        assertEquals(2, r.ipv6Hints.size)
        assertContentEquals(hex("20010db8000000000000000000000001"), r.ipv6Hints[0])
        assertContentEquals(hex("20010db8000000000000000000530001"), r.ipv6Hints[1])
    }

    @Test fun ipv6HintEmbeddedIpv4Vector() { // Figure 8: ipv6hint="2001:db8:122:344::192.0.2.33"
        val r = parsed("0001 076578616d706c65 03636f6d 00 0006 0010 20010db8012203440000 0000c0000221")
        assertEquals("example.com", r.target)
        assertContentEquals(hex("20010db80122034400000000c0000221"), r.ipv6Hints.single())
    }

    @Test fun mandatoryVector() { // Figure 9: alpn=h2,h3-19 mandatory=ipv4hint,alpn ipv4hint=192.0.2.1, keys sorted on the wire
        val r = parsed("0010 $FOO_EXAMPLE_ORG 0000 0004 0001 0004 0001 0009 02 6832 05 68332d3139 0004 0004 c0000201")
        assertEquals("foo.example.org", r.target)
        assertEquals(listOf("h2", "h3-19"), r.alpn)
        assertContentEquals(hex("c0000201"), r.ipv4Hints.single())
    }

    @Test fun alpnWithEscapedCommaVector() { // Figure 10: alpn=f\\\092oo\092,bar,h2
        val r = parsed("0010 $FOO_EXAMPLE_ORG 0001 000c 08 665c6f6f2c626172 02 6832")
        assertEquals(listOf("f\\oo,bar", "h2"), r.alpn)
        assertFalse(r.noDefaultAlpn)
    }

    // ---- section 2.2 (format), section 7 (values), section 8 (mandatory), Appendix D.3 (failure cases)

    @Test fun negative_keysOutOfOrderIsMalformed() = malformed("0001 00 0003 0002 01bb 0001 0003 026833")

    @Test fun negative_duplicateKeyIsMalformed() = malformed("0001 00 0001 0003 026833 0001 0003 026832")

    @Test fun negative_mandatoryListsItselfIsMalformed() = malformed("0001 00 0000 0004 0000 0001 0001 0003 026833")

    @Test fun negative_mandatoryKeyMissingIsMalformed() = malformed("0001 00 0000 0002 0003 0001 0003 026833")

    @Test fun negative_mandatoryKeysOutOfOrderIsMalformed() = malformed("0001 00 0000 0004 0003 0001 0001 0003 026833 0003 0002 01bb")

    @Test fun negative_mandatoryEmptyOrOddIsMalformed() {
        malformed("0001 00 0000 0000")
        malformed("0001 00 0000 0003 000100 0001 0003 026833")
    }

    @Test fun unknownMandatoryKeySkipsRecord() { // section 8: key 667 is not one this client supports
        assertNull(parse("0001 00 0000 0002 029b 0001 0003 026833 029b 0005 68656c6c6f"))
    }

    @Test fun mandatoryEchSkipsRecord() { // ech is not supported (no client ECH), so a record that needs it is not used
        assertNull(parse("0001 00 0000 0002 0005 0001 0003 026833 0005 0002 abcd"))
    }

    @Test fun noDefaultAlpnWithoutAlpnSkipsRecord() = assertNull(parse("0001 00 0002 0000"))

    @Test fun negative_noDefaultAlpnWithValueIsMalformed() = malformed("0001 00 0001 0003 026833 0002 0001 00")

    @Test fun negative_emptyAlpnIdIsMalformed() = malformed("0001 00 0001 0004 00 026833")

    @Test fun negative_emptyAlpnIsMalformed() = malformed("0001 00 0001 0000")

    @Test fun negative_alpnIdOverrunsValueIsMalformed() = malformed("0001 00 0001 0003 036833")

    @Test fun negative_portLength3IsMalformed() = malformed("0001 00 0003 0003 0001bb")

    @Test fun negative_ipv4HintNotMultipleOf4IsMalformed() = malformed("0001 00 0004 0005 c000020101")

    @Test fun negative_emptyIpv4HintIsMalformed() = malformed("0001 00 0004 0000")

    @Test fun negative_ipv6HintNotMultipleOf16IsMalformed() = malformed("0001 00 0006 0004 20010db8")

    @Test fun negative_compressedTargetNameIsMalformed() = malformed("0001 03666f6f c00c") // section 2.2: MUST NOT be compressed

    @Test fun negative_labelOver63IsMalformed() = malformed("0001 40 ${"61".repeat(64)} 00")

    @Test fun negative_nameOver255IsMalformed() = malformed("0001 ${"3f${"61".repeat(63)}".repeat(4)} 00")

    @Test fun negative_truncatedRdataIsMalformed() {
        malformed("00")
        malformed("0001")
        malformed("0001 03666f6f")
        malformed("0001 00 0003")
        malformed("0001 00 0003 0002 01")
    }

    @Test fun negative_manyKeysWithAMalformedValueIsMalformed() { // section 2.2: every value is checked, however many keys
        val unknown = (100 until 170).joinToString(" ") { "${it.toString(16).padStart(4, '0')} 0000" }
        malformed("0001 00 0003 0003 0001bb $unknown")
    }

    @Test fun manyKeysAreRead() {
        val unknown = (100 until 170).joinToString(" ") { "${it.toString(16).padStart(4, '0')} 0000" }
        assertEquals(listOf("h3"), parsed("0001 00 0001 0003 026833 $unknown").alpn)
    }

    @Test fun aliasModeParamsAreIgnored() { // section 2.4.2: recipients MUST ignore SvcParams in AliasMode
        val r = parsed("0000 $FOO_EXAMPLE_COM 0000 0002 029b 0003 0002 0035 029b 0001 00")
        assertTrue(r.isAlias)
        assertNull(r.port)
    }

    @Test fun negative_aliasModeParamsOutOfOrderAreMalformed() = malformed("0000 $FOO_EXAMPLE_COM 0003 0002 0035 0001 0003 026833")

    @Test fun encodeRoundTrips() {
        val r = parsed("0010 $FOO_EXAMPLE_ORG 0000 0004 0001 0004 0001 0009 02 6832 05 68332d3139 0004 0004 c0000201")
        val back = SvcbTestEncoder.encode(r)
        assertEquals(r, SvcbCodec.parseRdata(back, 0, back.size, r.owner, r.ttlSeconds))
    }
}
