// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.client

import io.ktor.http.Url
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull

/**
 * An origin cannot point the client's QUIC Initials at its loopback, link-local or private network, or at a multicast or
 * unspecified address (RFC 9000 section 21.5, RFC 7838 section 9; threat model 3.14; security review 2026-10-14, finding 7),
 * unless the origin itself is on such an address, as migration does (threat model 3.5).
 */
class AltSvcDestinationTest {
    private val store = InMemoryAltSvcStore()
    private val cache = AltSvcCache(store) { 1_000_000L }

    private fun learned(
        origin: String,
        alt: String,
    ): AltSvcEntry? {
        val url = Url(origin)
        cache.onResponse(url, 200, listOf("h3=\"$alt\""), verifiedTls = true)
        return cache.h3For(url)
    }

    @Test fun negative_altSvcToLocalNetworkFromPublicOrigin() {
        for (alt in listOf(
            "127.0.0.1:443",
            "127.8.9.10:443",
            "[::1]:443",
            "[::ffff:127.0.0.1]:443",
            "localhost:443",
            "a.localhost:443",
            "10.0.0.5:443",
            "172.16.1.1:443",
            "172.31.255.255:443",
            "192.168.1.1:443",
            "100.64.0.1:443",
            "[fc00::1]:443",
            "[fd12:3456::1]:443",
            "169.254.169.254:443",
            "[fe80::1]:500",
            "[fe80::1%25eth0]:443",
            "[::ffff:10.0.0.1]:443",
        )) {
            assertNull(learned("https://example.com/", alt), "$alt from a public origin")
        }
    }

    /**
     * IPv4 literals in the other forms `inet_aton` accepts. The resolvers map them without DNS (the JVM's InetAddress
     * `127.1` and `2130706433` to 127.0.0.1, `10.1` to 10.0.0.1; getaddrinfo also the octal and hex forms), and they
     * were classified as DNS names, so a public origin could still aim clients' Initials at their own network.
     */
    @Test fun negative_shorthandIpv4AltSvcToLocalNetworkRefused() {
        for (alt in listOf("127.1", "2130706433", "10.1", "192.168.1", "127.0.1", "169.254.43518", "172.16.1", "100.64.1")) {
            assertFalse(AltSvcDestination.allowed("example.com", alt), alt)
            assertNull(learned("https://example.com/", "$alt:443"), "$alt from a public origin")
        }
    }

    /**
     * Octal and hex parts (`0177.0.0.1`, `0x7f.1`, `0x7f000001`) are read as octal and hex by inet_aton (getaddrinfo on
     * Linux, Apple, Android and Windows) but as decimal, or refused, by the JVM: what they name depends on the platform,
     * so they are never a destination. Neither is a numeric host that is no address at all (`256.1.1.1`, `4294967296`,
     * `1.2.3.4.5`): RFC 1123 section 2.1 keeps host names from looking like a dotted-decimal number.
     */
    @Test fun negative_ambiguousOrInvalidNumericAltSvcHostRefused() {
        for (origin in listOf("https://example.com/", "https://127.0.0.1:8443/")) {
            for (alt in listOf(
                "0177.0.0.1",
                "0x7f.1",
                "0x7f000001",
                "017700000001",
                "127.0.0.01",
                "0x8.0x8.0x8.0x8",
                "010.8.8.8",
                "0x",
                "256.1.1.1",
                "4294967296",
                "1.2.3.4.5",
                "1..2",
                "1.2.3.256",
                "1.16777216",
            )) {
                assertFalse(AltSvcDestination.allowed(origin, alt), "$alt from $origin")
            }
        }
    }

    @Test fun negative_altSvcToUnspecifiedOrMulticastAlwaysRefused() {
        for (origin in listOf("https://example.com/", "https://127.0.0.1:8443/", "https://10.0.0.1/")) {
            for (alt in listOf(
                "0.0.0.0:443",
                "0.1.2.3:443",
                "[::]:443",
                "224.0.0.1:443",
                "239.1.1.1:443",
                "[ff02::1]:443",
                "255.255.255.255:443",
            )) {
                assertNull(learned(origin, alt), "$alt from $origin")
            }
        }
    }

    @Test fun publicAlternativesAreKept() {
        for (alt in listOf("8.8.8.8:443", "[2001:db8::1]:443", "alt.example.com:443", "172.32.0.1:443", "192.169.0.1:443", ":443")) {
            assertNotNull(learned("https://example.com/", alt), alt)
        }
    }

    @Test fun localOriginMayPointToLocalAlternatives() {
        assertEquals(8443, learned("https://127.0.0.1:8443/", "127.0.0.1:8443")?.port)
        assertNotNull(learned("https://localhost:8443/", "[::1]:8443"))
        assertNotNull(learned("https://10.0.0.1/", "10.0.0.2:443"))
        assertNotNull(learned("https://[fe80::1]/", "[fe80::2]:443"))
    }

    @Test fun classification() {
        assertEquals(AltSvcDestination.Class.Local, AltSvcDestination.classify("127.0.0.1"))
        assertEquals(AltSvcDestination.Class.Local, AltSvcDestination.classify("::ffff:192.168.0.1"))
        assertEquals(AltSvcDestination.Class.Never, AltSvcDestination.classify("ff05::2"))
        assertEquals(AltSvcDestination.Class.Public, AltSvcDestination.classify("2001:db8::ffff:1"))
        assertEquals(AltSvcDestination.Class.Public, AltSvcDestination.classify("1.2.3"), "inet_aton: 1.2.0.3")
        assertEquals(AltSvcDestination.Class.Public, AltSvcDestination.classify("8.8.2056"), "inet_aton: 8.8.8.8")
        assertEquals(AltSvcDestination.Class.Local, AltSvcDestination.classify("2130706433"), "inet_aton: 127.0.0.1")
        assertEquals(AltSvcDestination.Class.Never, AltSvcDestination.classify("0"), "inet_aton: 0.0.0.0")
        assertEquals(AltSvcDestination.Class.Public, AltSvcDestination.classify("1.example"), "a name")
        assertEquals(AltSvcDestination.Class.Public, AltSvcDestination.classify("0x1.example"), "a name")
        assertEquals(AltSvcDestination.Class.Public, AltSvcDestination.classify("::g"), "not a literal: a name")
    }
}
