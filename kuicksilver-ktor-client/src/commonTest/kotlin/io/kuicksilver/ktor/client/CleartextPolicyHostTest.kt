// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.client

import io.ktor.http.Url
import kotlin.test.Test
import kotlin.test.assertEquals

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

    /** RFC 5952 section 5: an IPv4-mapped address is `::ffff:` and the dotted quad, however it was written. */
    @Test fun aMappedIpv4AddressIsAskedAboutInMixedNotation() {
        assertEquals("::ffff:127.0.0.1", cleartextPolicyHost("[::ffff:127.0.0.1]"))
        assertEquals("::ffff:127.0.0.1", cleartextPolicyHost("::FFFF:7f00:1"))
        assertEquals("::ffff:127.0.0.1", cleartextPolicyHost("0:0:0:0:0:ffff:7f00:0001"))
        assertEquals("::ffff:192.0.2.1", cleartextPolicyHost("0:0:0:0:0:FFFF:192.0.2.1"))
    }

    /** The policy knows no interfaces: the zone is dropped, and a rule for the address holds on every link. */
    @Test fun theZoneIsDropped() {
        assertEquals("fe80::1", cleartextPolicyHost("fe80::1%wlan0"))
        assertEquals("fe80::1", cleartextPolicyHost("[fe80:0:0:0:0:0:0:1%25wlan0]"))
        assertEquals("fe80::1", cleartextPolicyHost("[FE80::1%3]"))
    }

    /** A literal that does not parse is asked about as written, lower case and without its zone (its connection fails anyway). */
    @Test fun negative_aLiteralThatDoesNotParseIsAskedAboutAsWritten() {
        assertEquals("fe80::g", cleartextPolicyHost("[FE80::G%eth0]"))
        assertEquals("1:2:3:4:5:6:7:8:9", cleartextPolicyHost("1:2:3:4:5:6:7:8:9"))
    }

    @Test fun namesAndDottedQuadsStayAsTheyAre() {
        assertEquals("example.test", cleartextPolicyHost("example.test"))
        assertEquals("127.0.0.1", cleartextPolicyHost("127.0.0.1"))
        assertEquals("127.0.0.1", cleartextPolicyHost("127.1"))
    }
}
