// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(ExperimentalKuicksilverApi::class)

package io.kuicksilver.http3.connectudp

import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.http3.UdpProxyConfig
import io.kuicksilver.http3.UdpTargetFilter
import io.kuicksilver.http3.message.UdpHost
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.seconds

/** RFC 9298 section 7: which targets a proxy reaches (CWE-918). */
class UdpTargetFilterTest {
    private fun bytes(ip: String): ByteArray = UdpHost.parseIpv4(ip) ?: UdpHost.parseIpv6(ip)!!

    private fun public(ip: String) = UdpTargetFilter.PublicOnly.allows(ip, bytes(ip), 443)

    @Test fun negative_publicOnlyRefusesSpecialPurposeAddresses() {
        val refused =
            listOf(
                "0.0.0.0",
                "0.1.2.3",
                "10.0.0.1",
                "100.64.0.1",
                "100.127.255.254",
                "127.0.0.1",
                "127.255.255.255",
                "169.254.169.254",
                "172.16.0.1",
                "172.31.255.255",
                "192.0.0.1",
                "192.0.2.1",
                "192.88.99.1",
                "192.168.1.1",
                "198.18.0.1",
                "198.19.255.255",
                "198.51.100.1",
                "203.0.113.1",
                "224.0.0.251",
                "239.255.255.250",
                "240.0.0.1",
                "255.255.255.255",
                "::",
                "::1",
                "::ffff:127.0.0.1",
                "::ffff:10.0.0.1",
                "::ffff:0:0",
                "64:ff9b::7f00:1",
                "64:ff9b::a00:1",
                "64:ff9b:1::1",
                "100::1",
                "2001::1",
                "2001:db8::1",
                "2002:7f00:1::1",
                "2002:a00:1::",
                "3fff::1",
                "5f00::1",
                "fc00::1",
                "fd12:3456::1",
                "fe80::1",
                "febf::1",
                "fec0::1",
                "ff02::1",
                "ff05::1:3",
            )
        for (ip in refused) assertFalse(public(ip), "$ip passed as public")
    }

    @Test fun publicOnlyAllowsGlobalUnicast() {
        for (ip in listOf(
            "1.1.1.1",
            "8.8.8.8",
            "100.63.255.255",
            "100.128.0.0",
            "172.15.255.255",
            "172.32.0.0",
            "192.0.3.1",
            "223.255.255.254",
            "2606:4700::1111",
            "2a00:1450::1",
            "::ffff:8.8.8.8",
            "64:ff9b::808:808",
            "2002:808:808::1",
            "2001:200::1",
        )) {
            assertTrue(public(ip), "$ip refused")
        }
        assertFalse(UdpTargetFilter.PublicOnly.allows("x", ByteArray(5), 1))
    }

    @Test fun prefixesHostsPortsAndCombinators() {
        val lab = UdpTargetFilter.addresses("10.1.0.0/16", "2001:db8:1::/48", "192.0.2.7")
        assertTrue(lab.allows("a", bytes("10.1.255.1"), 1))
        assertTrue(lab.allows("a", bytes("::ffff:10.1.0.1"), 1)) // an IPv4-mapped address is its IPv4 address
        assertFalse(lab.allows("a", bytes("10.2.0.1"), 1))
        assertTrue(lab.allows("a", bytes("2001:db8:1:ff::1"), 1))
        assertFalse(lab.allows("a", bytes("2001:db8:2::1"), 1))
        assertTrue(lab.allows("a", bytes("192.0.2.7"), 1))
        assertFalse(lab.allows("a", bytes("192.0.2.8"), 1))
        val own = UdpTargetFilter.PublicOnly and UdpTargetFilter.excluding("198.51.100.0/24", "8.8.4.4")
        assertFalse(own.allows("a", bytes("8.8.4.4"), 1))
        assertTrue(own.allows("a", bytes("8.8.8.8"), 1))
        val dnsOnly = UdpTargetFilter.hosts("Resolver.Example.") and UdpTargetFilter.ports(53..53)
        assertTrue(dnsOnly.allows("resolver.example", bytes("8.8.8.8"), 53))
        assertFalse(dnsOnly.allows("resolver.example", bytes("8.8.8.8"), 54))
        assertFalse(dnsOnly.allows("other.example", bytes("8.8.8.8"), 53))
        val either = UdpTargetFilter.ports(443..443) or UdpTargetFilter.hosts("a.example")
        assertTrue(either.allows("a.example", bytes("8.8.8.8"), 1))
        assertTrue(either.allows("b.example", bytes("8.8.8.8"), 443))
        for (bad in listOf("10.0.0.0/33", "10.0.0.1/8", "x/8", "10.0.0.0/", "::/129", "10.0.0.0/-1", "")) {
            assertFailsWith<IllegalArgumentException>(bad) { UdpTargetFilter.addresses(bad) }
        }
    }

    @Test fun negative_configRefusesAnIdleTimeoutBelowTwoMinutesAndBadValues() {
        assertFailsWith<IllegalArgumentException> { UdpProxyConfig(idleTimeout = 119.seconds) }
        assertFailsWith<IllegalArgumentException> { UdpProxyConfig(linkMtu = 1279) }
        assertFailsWith<IllegalArgumentException> { UdpProxyConfig(packetRate = 0) }
        assertFailsWith<IllegalArgumentException> { UdpProxyConfig(proxyName = "bad name") }
        assertFailsWith<IllegalArgumentException> { UdpProxyConfig(proxyName = "1abc") }
        assertFailsWith<IllegalArgumentException> { UdpProxyConfig(pathTemplate = "/m/{target_host}{target_port}") }
        assertEquals("proxy", UdpProxyConfig().proxyName)
    }
}
