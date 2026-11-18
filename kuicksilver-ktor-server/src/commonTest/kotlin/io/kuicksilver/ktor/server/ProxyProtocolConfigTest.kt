// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.server

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import kotlin.time.Duration
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.seconds

/** The trusted sources of `proxyProtocol { }`: who may send a PROXY header ("only trusted proxies are allowed to use this protocol"). */
class ProxyProtocolConfigTest {
    private fun config(vararg sources: String) = ProxyProtocolConfig.Builder().apply { trust(*sources) }.build()

    private fun ip(text: String) = parseIpLiteral(text)!!

    @Test fun addressesAndBlocksMatch() {
        val c = config("10.0.0.0/8", "192.0.2.7", "2001:db8::/32", "::1")
        assertTrue(c.trusts(ip("10.1.2.3")))
        assertTrue(c.trusts(ip("192.0.2.7")))
        assertTrue(c.trusts(ip("2001:db8:ffff::1")))
        assertTrue(c.trusts(ip("::1")))
        assertFalse(c.trusts(ip("11.0.0.1")))
        assertFalse(c.trusts(ip("192.0.2.8")))
        assertFalse(c.trusts(ip("2001:db9::1")))
        assertFalse(c.trusts(ip("::2")))
    }

    @Test fun oddPrefixLengths() {
        val c = config("198.51.100.128/25", "2001:db8:8000::/33", "0.0.0.0/0")
        assertTrue(c.trusts(ip("1.2.3.4")), "0.0.0.0/0 takes every IPv4 peer")
        assertFalse(c.trusts(ip("2001:db8::1")), "an IPv4 block takes no IPv6 peer")
        assertTrue(c.trusts(ip("2001:db8:8000::1")))
        assertTrue(config("198.51.100.128/25").trusts(ip("198.51.100.255")))
        assertFalse(config("198.51.100.128/25").trusts(ip("198.51.100.127")))
    }

    @Test fun ipv4MappedPeersMatchIpv4Blocks() {
        // a dual-stack listener reports an IPv4 peer as ::ffff:a.b.c.d
        assertTrue(config("10.0.0.0/8").trusts(ip("::ffff:10.9.8.7")))
        assertTrue(config("::ffff:10.0.0.0/104").trusts(ip("10.9.8.7")), "a mapped block is the IPv4 block it maps")
        assertTrue(config("::ffff:10.0.0.0/104").trusts(ip("::ffff:10.9.8.7")))
        assertFalse(config("::ffff:10.0.0.0/104").trusts(ip("11.0.0.1")))
    }

    @Test fun negative_ipv6BlocksDoNotTakeMappedIpv4Peers() {
        assertFalse(config("::/0").trusts(ip("::ffff:10.9.8.7")), "an IPv4 peer is matched as IPv4 only")
        assertFalse(config("::/0").trusts(ip("10.9.8.7")))
        assertFalse(config("::/80").trusts(ip("10.9.8.7")))
    }

    @Test fun negative_unknownPeerIsNotTrusted() {
        assertFalse(config("0.0.0.0/0", "::/0").trusts(null))
    }

    @Test fun negative_invalidConfigurationsAreRefused() {
        val bad =
            listOf(
                "10.0.0.1/8", // bits past the prefix
                "2001:db8::1/32",
                "10.0.0.0/33",
                "::/129",
                "10.0.0.0/",
                "10.0.0.0/08",
                "10.0.0.0/-1",
                "fe80::1%en0",
                "[::1]",
                "host.test",
                "10.0.0",
                "",
                " 10.0.0.1",
            )
        for (s in bad) assertFailsWith<IllegalArgumentException>(s) { config(s) }
        assertFailsWith<IllegalArgumentException>("no source") { config() }
        // section 2: a timeout of "at least 3 seconds to cover a TCP retransmit"
        for (t in listOf(Duration.ZERO, 2999.milliseconds)) {
            assertFailsWith<IllegalArgumentException>("headerTimeout $t") {
                ProxyProtocolConfig
                    .Builder()
                    .apply {
                        trust("10.0.0.0/8")
                        headerTimeout = t
                    }.build()
            }
        }
        ProxyProtocolConfig
            .Builder()
            .apply {
                trust("10.0.0.0/8")
                headerTimeout = 3.seconds
            }.build()
        for (size in listOf(231, ProxyProtocolCodec.V2_MAX + 1)) {
            assertFailsWith<IllegalArgumentException>("maxHeaderSize $size") {
                ProxyProtocolConfig
                    .Builder()
                    .apply {
                        trust("10.0.0.0/8")
                        maxHeaderSize = size
                    }.build()
            }
        }
    }

    /**
     * The header's wait is `headerTimeout`, cut to what is left of the request-head deadline, but never below the 3 s the
     * spec asks for ("at least 3 seconds to cover a TCP retransmit").
     */
    @Test fun headerWaitIsNeverBelowThreeSeconds() {
        val c =
            ProxyProtocolConfig
                .Builder()
                .apply {
                    trust("10.0.0.0/8")
                    headerTimeout = 5.seconds
                }.build()
        assertEquals(5.seconds, c.headerWait(30.seconds))
        assertEquals(4.seconds, c.headerWait(4.seconds))
        assertEquals(3.seconds, c.headerWait(1.seconds), "a request-head deadline of 1 s still gives the header 3 s")
        assertEquals(3.seconds, c.headerWait(Duration.ZERO))
    }
}
