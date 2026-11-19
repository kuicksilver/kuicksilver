// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.client

import io.ktor.http.Url
import kotlinx.io.IOException
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

/**
 * The host the cleartext policy is asked about ([cleartextPolicyHost]): one spelling per address, so that a rule for an
 * address (the policy matches strings) is not passed by another spelling of it. IPv6 in RFC 5952's text.
 */
class CleartextPolicyHostTest {
    @Test fun theFullFormOfLoopbackIsAskedAboutAsTheShortOne() {
        assertEquals("::1", cleartextPolicyHost("0:0:0:0:0:0:0:1"))
        assertEquals("::1", cleartextPolicyHost("[0:0:0:0:0:0:0:1]"))
        assertEquals("::1", cleartextPolicyHost(Url("http://[0:0:0:0:0:0:0:1]:8080/").host))
        assertEquals("::1", cleartextPolicyHost("[::1]"))
    }

    /** RFC 5952 section 4.3: "The characters "a", "b", "c", "d", "e", and "f" in an IPv6 address MUST be represented in lowercase". */
    @Test fun upperCaseHexIsAskedAboutInLowerCase() {
        assertEquals("2001:db8::abcd", cleartextPolicyHost("[2001:DB8::ABCD]"))
        assertEquals("fe80::1", cleartextPolicyHost("FE80::1"))
    }

    /** RFC 5952 section 4.1: "Leading zeros MUST be suppressed". */
    @Test fun leadingZerosAreDropped() {
        assertEquals("2001:db8::1", cleartextPolicyHost("[2001:0db8:0000:0000:0000:0000:0000:0001]"))
        assertEquals("2001:db8:0:1:1:1:1:1", cleartextPolicyHost("2001:0db8:0000:0001:0001:0001:0001:0001"))
    }

    /**
     * RFC 5952 section 4.2: `::` shortens as much as possible (4.2.1), never one group alone (4.2.2), the longest run, and
     * the first of runs of equal length (4.2.3).
     */
    @Test fun theLongestRunOfZerosIsTheOneCompressed() {
        assertEquals("2001:0:0:1::1", cleartextPolicyHost("2001:0:0:1:0:0:0:1"))
        assertEquals("2001:db8::1:0:0:1", cleartextPolicyHost("2001:db8:0:0:1:0:0:1"))
        assertEquals("2001:db8:0:1:1:1:1:1", cleartextPolicyHost("2001:db8::1:1:1:1:1"))
        assertEquals("::", cleartextPolicyHost("0:0:0:0:0:0:0:0"))
        assertEquals("1::", cleartextPolicyHost("1:0:0:0:0:0:0:0"))
    }

    /**
     * An IPv4-mapped literal (`::ffff:0:0/96`, RFC 4291 section 2.5.5.2) is asked about as the dotted quad it connects to,
     * however it was written, so a rule for the IPv4 address holds for it.
     */
    @Test fun aMappedIpv4AddressIsAskedAboutAsItsDottedQuad() {
        assertEquals("127.0.0.1", cleartextPolicyHost("[::ffff:127.0.0.1]"))
        assertEquals("127.0.0.1", cleartextPolicyHost("::FFFF:7f00:1"))
        assertEquals("127.0.0.1", cleartextPolicyHost("0:0:0:0:0:ffff:7f00:0001"))
        assertEquals("192.168.1.1", cleartextPolicyHost("[0:0:0:0:0:FFFF:192.168.1.1]"))
        assertEquals("192.168.1.1", cleartextPolicyHost(Url("http://[::ffff:192.168.1.1]:8080/").host))
    }

    /** Only `::ffff:0:0/96` is mapped: an IPv4-translated (`::ffff:0:0:0/96`) or IPv4-compatible address stays IPv6. */
    @Test fun negative_otherIpv4EmbeddingsStayIpv6() {
        assertEquals("::ffff:0:7f00:1", cleartextPolicyHost("[::ffff:0:127.0.0.1]"))
        assertEquals("::7f00:1", cleartextPolicyHost("[::127.0.0.1]"))
        assertEquals("64:ff9b::7f00:1", cleartextPolicyHost("[64:ff9b::127.0.0.1]"))
        // one bit off the prefix, in bytes 8 to 11
        assertEquals("::1:ffff:7f00:1", cleartextPolicyHost("[::1:ffff:7f00:1]"))
        assertEquals("::ff:7f00:1", cleartextPolicyHost("[::ff:7f00:1]"))
        assertEquals("::fffe:7f00:1", cleartextPolicyHost("[::fffe:7f00:1]"))
    }

    /** The policy knows no interfaces: the zone is dropped, and a rule for the address holds on every link. */
    @Test fun theZoneIsDropped() {
        assertEquals("fe80::1", cleartextPolicyHost("fe80::1%wlan0"))
        assertEquals("fe80::1", cleartextPolicyHost("[fe80:0:0:0:0:0:0:1%25wlan0]"))
        assertEquals("fe80::1", cleartextPolicyHost("[FE80::1%3]"))
    }

    /** An IP literal that is no IPv6 address fails closed, before the policy is asked (its connection could go nowhere). */
    @Test fun negative_aLiteralThatDoesNotParseFails() {
        for (h in listOf("[FE80::G%eth0]", "1:2:3:4:5:6:7:8:9", "[1::2::3]", "[127.0.0.1]", "[]", "[::ffff:256.0.0.1]")) {
            val e = assertFailsWith<IOException>(h) { cleartextPolicyHost(h) }
            assertEquals("$h is not an IP address", e.message)
        }
    }

    /**
     * The engine does not map an internationalised name to its A-label: the policy's rules name A-labels, so a Unicode
     * name is refused before the policy is asked; its A-label is asked about as it is.
     */
    @Test fun negative_aNonAsciiNameIsRefused() {
        val e = assertFailsWith<IOException> { cleartextPolicyHost("b\u00fccher.example") }
        assertTrue("A-label" in e.message.orEmpty(), "${e.message}")
        assertEquals("xn--bcher-kva.example", cleartextPolicyHost("xn--bcher-kva.example"))
    }

    /** Android's policy throws IllegalArgumentException for a host beginning with a dot: it is refused before it. */
    @Test fun negative_aHostBeginningWithADotIsRefused() {
        val e = assertFailsWith<IOException> { cleartextPolicyHost(".example.test") }
        assertEquals(".example.test is not a host name: it begins with a dot", e.message)
    }

    @Test fun namesAndDottedQuadsStayAsTheyAre() {
        assertEquals("example.test", cleartextPolicyHost("example.test"))
        assertEquals("127.0.0.1", cleartextPolicyHost("127.0.0.1"))
        assertEquals("127.0.0.1", cleartextPolicyHost("127.1"))
    }
}
