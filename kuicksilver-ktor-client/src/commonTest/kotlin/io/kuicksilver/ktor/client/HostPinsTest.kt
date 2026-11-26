// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.client

import io.kuicksilver.tls.PinScope
import io.kuicksilver.tls.SpkiSha256
import kotlin.test.Test
import kotlin.test.assertContains
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * `tls { pins { } }`'s patterns and their matching, as OkHttp's `CertificatePinner` (its `Pin` and `toCanonicalHost`):
 * exact hosts, `*.` for one label, `**.` for any number, IP literals, case and IDNs. Pure: no connection.
 */
class HostPinsTest {
    private val p1 = SpkiSha256(ByteArray(32) { 1 })
    private val p2 = SpkiSha256(ByteArray(32) { 2 })
    private val p3 = SpkiSha256(ByteArray(32) { 3 })

    private fun pins(block: HostPinsConfig.() -> Unit) = HostPinsConfig().apply(block)

    private fun matches(
        pattern: String,
        host: String,
    ): Boolean = pins { add(pattern, p1) }.pinsFor(host).isNotEmpty()

    @Test fun anExactHostMatchesItselfOnly() {
        assertTrue(matches("api.example.com", "api.example.com"))
        assertFalse(matches("api.example.com", "example.com"))
        assertFalse(matches("api.example.com", "www.api.example.com"))
        assertFalse(matches("api.example.com", "api.example.com.evil"))
        assertFalse(matches("api.example.com", "xapi.example.com"))
    }

    @Test fun oneStarIsExactlyOneLabel() {
        assertTrue(matches("*.example.com", "www.example.com"))
        assertTrue(matches("*.example.com", "a-b.example.com"))
        assertFalse(matches("*.example.com", "example.com"), "no label in front")
        assertFalse(matches("*.example.com", "a.b.example.com"), "two labels")
        assertFalse(matches("*.example.com", "wwwexample.com"))
        assertFailsWith<io.kuicksilver.tls.TlsException.Config>("no host: fails closed") { matches("*.example.com", ".example.com") }
    }

    @Test fun twoStarsAreAnyNumberOfLabelsNoneIncluded() {
        assertTrue(matches("**.example.com", "example.com"))
        assertTrue(matches("**.example.com", "www.example.com"))
        assertTrue(matches("**.example.com", "a.b.c.example.com"))
        assertFalse(matches("**.example.com", "badexample.com"), "a label boundary, not a suffix of characters")
        assertFalse(matches("**.example.com", "example.com.evil"))
        assertFalse(matches("**.example.com", "com"))
    }

    @Test fun caseOwsAndOneTrailingDotChangeNothing() {
        assertTrue(matches("API.Example.COM", "api.example.com"))
        assertTrue(matches("api.example.com", "API.EXAMPLE.COM"))
        assertTrue(matches("*.Example.com", "WWW.example.COM"))
        assertTrue(matches("api.example.com", "api.example.com."), "a request to the fully qualified name is pinned")
        assertTrue(matches("api.example.com.", "api.example.com"))
        assertTrue(matches("**.example.com", "example.com."))
        // the TLS layer's reference identifier drops spaces and tabs around a name, and so does the pins' key (B1)
        assertTrue(matches("api.example.com", " api.example.com"))
        assertTrue(matches("api.example.com", "api.example.com\t"))
        assertTrue(matches(" api.example.com ", "api.example.com"))
    }

    @Test fun internationalizedNamesAreWrittenAsALabels() {
        assertTrue(matches("xn--bcher-kva.example", "XN--BCHER-KVA.example"))
        assertTrue(matches("*.xn--bcher-kva.example", "www.xn--bcher-kva.example"))
        assertTrue(Punycode.roundTrips("bcher-kva"))
        assertTrue(Punycode.roundTrips("e1afmkfd"))
        assertTrue(Punycode.roundTrips("egbpdaj6bu4bxfgehfvwxn"))
        assertTrue(Punycode.roundTrips("ls8h"), "a character outside the BMP")
        assertFalse(Punycode.roundTrips("abc-"), "all ASCII: no A-label")
        assertFalse(Punycode.roundTrips("99999999999a"), "overflow")
        val e = assertFailsWith<IllegalArgumentException> { pins { add("bücher.example", p1) } }
        assertContains(e.message!!, "A-labels")
    }

    @Test fun ipLiteralsMatchByAddress() {
        assertTrue(matches("192.0.2.1", "192.0.2.1"))
        assertFalse(matches("192.0.2.1", "192.0.2.10"))
        assertTrue(matches("2001:db8::1", "[2001:db8::1]"))
        assertTrue(matches("[2001:DB8:0:0::1]", "2001:db8::1"), "RFC 5952 text on both sides")
        assertTrue(matches("::ffff:192.0.2.1", "192.0.2.1"), "an IPv4-mapped address is its IPv4 address, as OkHttp")
        assertTrue(matches("192.0.2.1", "[::ffff:c000:201]"))
        assertTrue(matches("192.0.2.1", " 192.0.2.1\t"))
    }

    @Test fun everyMatchingPatternAddsItsPins() {
        val p =
            pins {
                add("**.example.com", p1)
                add("*.example.com", p2)
                add("www.example.com", p3)
                add("www.example.com", p1)
            }
        assertEquals(setOf(p1, p2, p3), p.pinsFor("www.example.com"))
        assertEquals(setOf(p1, p2), p.pinsFor("api.example.com"))
        assertEquals(setOf(p1), p.pinsFor("example.com"))
        assertEquals(emptySet(), p.pinsFor("example.org"))
    }

    @Test fun textPinsAreOkHttpsForm() {
        val text = p1.toString()
        assertEquals(setOf(p1), pins { add("a.test", text) }.pinsFor("a.test"))
        assertEquals(PinScope.Leaf, HostPinsConfig().scope, "Leaf by default, as TrustConfig.Pinned (Q7)")
    }

    @Test fun negative_badPinsAreRefusedWithTheReason() {
        val sha1 = assertFailsWith<IllegalArgumentException> { pins { add("a.test", "sha1/BOGUSBOGUSBOGUSBOGUSBOGUSBOG=") } }
        assertContains(sha1.message!!, "sha1/ pin")
        assertContains(sha1.message!!, "tls { pins { add(\"a.test\", …) } }")
        val short = assertFailsWith<IllegalArgumentException> { pins { add("a.test", "sha256/AAAA") } }
        assertContains(short.message!!, "is not a pin")
        assertFailsWith<IllegalArgumentException> { pins { add("a.test", "AAAA") } }
        assertFailsWith<IllegalArgumentException> { pins { add("a.test", "sha256/!!!!") } }
        val none = assertFailsWith<IllegalArgumentException> { pins { add("a.test", *emptyArray<SpkiSha256>()) } }
        assertContains(none.message!!, "needs at least one pin")
        assertFailsWith<IllegalArgumentException> { pins { add("a.test", *emptyArray<String>()) } }
    }

    @Test fun negative_badPatternsAreRefused() {
        val bad =
            listOf(
                "",
                ".",
                "*",
                "**",
                "*.",
                "**.",
                "a.*.example.com",
                "*a.example.com",
                "a*.example.com",
                "***.example.com",
                "*.*.example.com",
                "example.*",
                "a..example.com",
                ".example.com",
                "a b.example.com",
                "a/b.example.com",
                "a:b",
                "[example.com]",
                "*.[::1]",
                "*.::1",
                "fe80::1%eth0",
                "a".repeat(64) + ".com",
                ("a".repeat(63) + ".").repeat(4) + "com",
                "010.0.0.1",
                "127.1",
                "2130706433",
                "0x7f.0.0.1",
                "a\u0000b.com",
                // the TLS layer's LDH rules (L6), and no wildcard in front of an IP literal (L5)
                "a_b.example.com",
                "-a.example.com",
                "a-.example.com",
                "example.123",
                "*.192.0.2.1",
                "**.192.0.2.1",
                "*.0.2.1",
                // non-ASCII (H2): the A-label is the one spelling, and the TLS layer refuses any other
                "bücher.example",
                "ｅｘａｍｐｌｅ.com",
                "例。example",
                "\uD800.com",
                "xn--99999999999a.example",
            )
        for (pattern in bad) {
            val e = assertFailsWith<IllegalArgumentException>(pattern) { pins { add(pattern, p1) } }
            assertContains(e.message!!, "not a host pattern", message = pattern)
        }
    }

    /**
     * Self-attack: every spelling of a host that the TLS layer takes as the same reference identifier meets its pins (B1: a
     * host with a leading space was served unpinned), and a host the TLS layer cannot take fails closed instead of matching
     * no pattern.
     */
    @Test fun negative_hostSpellingsDoNotEscapeThePins() {
        val p = pins { add("**.bank.test", p1) }
        val same =
            listOf(
                "bank.test",
                "BANK.TEST",
                "bank.test.",
                "www.Bank.Test",
                "WWW.BANK.TEST.",
                "a.b.bank.test",
                " bank.test",
                "bank.test ",
                "\tbank.test",
                "bank.test\t",
                " \tWWW.bank.test. ",
            )
        for (host in same) assertEquals(setOf(p1), p.pinsFor(host), "[$host]")
        for (host in listOf("bank.test\u0000.evil", "bank.test/evil", "bänk.test", "127.1", "2130706433", "0x7f.0.0.1", "fe80::1%en0")) {
            assertFailsWith<io.kuicksilver.tls.TlsException.Config>("[$host]") { p.pinsFor(host) }
        }
        // without pins nothing is keyed and nothing fails here (the TLS layer refuses such a host itself)
        assertEquals(emptySet(), HostPinsConfig().pinsFor("127.1"))
    }

    @Test fun canonicalPatternsKeepTheirWildcard() {
        assertEquals("*.example.com", PinHosts.canonicalPattern("*.EXAMPLE.com"))
        assertEquals("**.xn--bcher-kva.example", PinHosts.canonicalPattern("**.XN--BCHER-KVA.example."))
        assertEquals("2001:db8::1", PinHosts.canonicalPattern("[2001:0db8:0000::1]"))
        assertEquals("1:0:0:1::1", PinHosts.canonicalPattern("1:0:0:1:0:0:0:1"), "the longer zero run, RFC 5952 section 4.2.3")
    }
}
