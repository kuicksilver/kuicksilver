// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.client.pac

import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals

/**
 * The PAC utility functions (Netscape's PAC format, Microsoft's IPv6 extensions) as scripts see them, with name
 * resolution and the host's addresses answered by a fake [PacHost].
 */
class PacUtilsAppleTest {
    private lateinit var ctx: PacContext

    private object FakeHost : PacHost {
        override fun resolve(
            name: String,
            ipv4Only: Boolean,
        ): List<String> =
            when (name) {
                "intranet.corp.example" -> if (ipv4Only) listOf("10.1.2.3") else listOf("2001:db8::7", "10.1.2.3")
                "v6only.example" -> if (ipv4Only) emptyList() else listOf("2001:db8:1::5")
                else -> emptyList()
            }

        override fun myAddresses(ipv4Only: Boolean): List<String> =
            if (ipv4Only) listOf("192.168.1.20") else listOf("192.168.1.20", "fd00::20")
    }

    @BeforeTest fun setUp() {
        PacHost.setForTest(FakeHost)
        ctx = PacContext("function FindProxyForURL(url, host) { return 'DIRECT'; }")
    }

    @AfterTest fun tearDown() {
        ctx.close()
        PacHost.setForTest(null)
    }

    private fun js(code: String): String? = ctx.eval(code)

    @Test fun isPlainHostName() {
        assertEquals("true", js("isPlainHostName('www')"))
        assertEquals("false", js("isPlainHostName('www.example.com')"))
    }

    @Test fun dnsDomainIs() {
        assertEquals("true", js("dnsDomainIs('www.example.com', '.example.com')"))
        assertEquals("false", js("dnsDomainIs('www', '.example.com')"))
        assertEquals("false", js("dnsDomainIs('www.badexample.org', '.example.com')"))
    }

    @Test fun localHostOrDomainIs() {
        assertEquals("true", js("localHostOrDomainIs('www.example.com', 'www.example.com')"))
        assertEquals("true", js("localHostOrDomainIs('www', 'www.example.com')"))
        assertEquals("false", js("localHostOrDomainIs('www.other.com', 'www.example.com')"))
        assertEquals("false", js("localHostOrDomainIs('home', 'www.example.com')"))
    }

    @Test fun dnsResolveAndIsResolvable() {
        assertEquals("10.1.2.3", js("dnsResolve('intranet.corp.example')"))
        assertEquals(null, js("dnsResolve('nowhere.example')"))
        assertEquals("true", js("isResolvable('intranet.corp.example')"))
        assertEquals("false", js("isResolvable('nowhere.example')"))
        assertEquals("false", js("isResolvable('v6only.example')"))
    }

    @Test fun isInNet() {
        assertEquals("true", js("isInNet('10.1.2.3', '10.0.0.0', '255.0.0.0')"))
        assertEquals("false", js("isInNet('11.1.2.3', '10.0.0.0', '255.0.0.0')"))
        assertEquals("true", js("isInNet('intranet.corp.example', '10.1.0.0', '255.255.0.0')")) // a name is resolved
        assertEquals("false", js("isInNet('nowhere.example', '10.0.0.0', '255.0.0.0')"))
    }

    @Test fun myIpAddress() {
        assertEquals("192.168.1.20", js("myIpAddress()"))
        assertEquals("192.168.1.20;fd00::20", js("myIpAddressEx()"))
    }

    @Test fun dnsDomainLevels() {
        assertEquals("0", js("dnsDomainLevels('www')"))
        assertEquals("2", js("dnsDomainLevels('www.example.com')"))
    }

    @Test fun shExpMatch() {
        assertEquals("true", js("shExpMatch('http://home.example.com/people/a/index.html', '*/a/*')"))
        assertEquals("false", js("shExpMatch('http://home.example.com/people/b/index.html', '*/a/*')"))
        assertEquals("true", js("shExpMatch('www.example.com', 'www.?xample.com')"))
        assertEquals("false", js("shExpMatch('www.example.com', 'www.example.co')"))
        assertEquals("false", js("shExpMatch('wwwXexample.com', 'www.example.com')")) // '.' is literal
    }

    @Test fun weekdayRange() {
        assertEquals("true", js("weekdayRange(__pacDays[new Date().getUTCDay()], 'GMT')"))
        assertEquals("false", js("weekdayRange(__pacDays[(new Date().getUTCDay() + 1) % 7], 'GMT')"))
        assertEquals("true", js("weekdayRange('SUN', 'SAT')"))
        assertEquals("false", js("weekdayRange('XYZ')"))
    }

    @Test fun dateRange() {
        assertEquals("true", js("dateRange(new Date().getUTCFullYear(), 'GMT')"))
        assertEquals("false", js("dateRange(new Date().getUTCFullYear() + 1, 'GMT')"))
        assertEquals("true", js("dateRange(__pacMonths[new Date().getUTCMonth()], 'GMT')"))
        assertEquals("true", js("dateRange('JAN', 'DEC')"))
        assertEquals("true", js("dateRange(1, 31)"))
        assertEquals("false", js("dateRange('JAN', 1)")) // mixed kinds in a pair
    }

    /**
     * Mozilla's semantics: two hours exclude the end hour; with minutes the whole end minute is included; no wrap past
     * midnight. Before, two hours included the end hour.
     */
    @Test fun timeRange() {
        assertEquals("true", js("timeRange(new Date().getUTCHours(), 'GMT')"))
        assertEquals("false", js("timeRange((new Date().getUTCHours() + 12) % 24, 'GMT')"))
        assertEquals("true", js("timeRange(0, 0, 0, 23, 59, 59)"))
        assertEquals("true", js("timeRange(0, 0, 23, 59)"))
        // (h1, h2): h1 <= hour < h2
        assertEquals("false", js("var h = new Date().getUTCHours(); timeRange(h, h, 'GMT')"))
        assertEquals("true", js("var h = new Date().getUTCHours(); h == 23 || timeRange(h, h + 1, 'GMT')"))
        assertEquals("false", js("var h = new Date().getUTCHours(); h == 0 || timeRange(h - 1, h, 'GMT')"))
        // (h1, m1, h2, m2): the end minute is whole
        assertEquals(
            "true",
            js("var d = new Date(); timeRange(d.getUTCHours(), d.getUTCMinutes(), d.getUTCHours(), d.getUTCMinutes(), 'GMT')"),
        )
        assertEquals("false", js("timeRange(23, 0, 1, 0)")) // no wrap past midnight
    }

    /**
     * `*` and `?` are the only wildcards; every other character is literal, `[`, `]`, `+`, `(`, `)`, `^`, `$` and `|`
     * included.
     */
    @Test fun shExpMatchTakesOtherCharactersLiterally() {
        assertEquals("true", js("shExpMatch('a[b]c', 'a[b]c')"))
        assertEquals("false", js("shExpMatch('abc', 'a[b]c')"))
        assertEquals("true", js("shExpMatch('a+b', 'a+b')"))
        assertEquals("false", js("shExpMatch('aab', 'a+b')"))
        assertEquals("true", js("shExpMatch('(x)|y', '(x)|y')"))
        assertEquals("false", js("shExpMatch('x', '(x)|y')"))
        assertEquals("true", js("shExpMatch('^a$', '^a$')"))
        assertEquals("true", js("shExpMatch('http://x.test/a?b', 'http://*.test/a?b')"))
    }

    @Test fun ipv6Extensions() {
        assertEquals("2001:db8::7;10.1.2.3", js("dnsResolveEx('intranet.corp.example')"))
        assertEquals("", js("dnsResolveEx('nowhere.example')"))
        assertEquals("true", js("isResolvableEx('v6only.example')"))
        assertEquals("false", js("isResolvableEx('nowhere.example')"))
        assertEquals("true", js("isInNetEx('2001:db8::7', '2001:db8::/32')"))
        assertEquals("false", js("isInNetEx('2001:db9::7', '2001:db8::/32')"))
        assertEquals("true", js("isInNetEx('10.1.2.3', '10.1.0.0/16')"))
        assertEquals("false", js("isInNetEx('10.2.2.3', '10.1.0.0/16')"))
        assertEquals("2001:db8::1;10.0.0.1;10.0.0.2", js("sortIpAddressList('10.0.0.2;2001:db8::1;10.0.0.1')"))
        assertEquals("1.0", js("getClientVersion()"))
    }
}
