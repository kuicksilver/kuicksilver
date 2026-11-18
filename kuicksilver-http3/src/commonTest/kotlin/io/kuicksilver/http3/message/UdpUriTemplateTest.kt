// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.http3.message

import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertIs
import kotlin.test.assertTrue

/** RFC 9298 section 2 (the URI Template of a UDP proxy) and section 3 (the target_host and target_port variables). */
class UdpUriTemplateTest {
    private fun target(m: TemplateMatch): TemplateMatch.Target = assertIs<TemplateMatch.Target>(m, "expected a target, got $m")

    // ---- client: parsing and expansion (section 2) ----

    /** The three examples of RFC 9298 section 2, expanded as in its section 3 and RFC 6570 section 3.2. */
    @Test fun rfcExamplesExpand() {
        val a = UdpUriTemplate.parseAbsolute("https://example.org/.well-known/masque/udp/{target_host}/{target_port}/")
        val ea = a.expand("192.0.2.6", 443)
        assertEquals("https", ea.scheme)
        assertEquals("example.org", ea.authority)
        assertEquals("/.well-known/masque/udp/192.0.2.6/443/", ea.pathAndQuery)
        val b = UdpUriTemplate.parseAbsolute("https://proxy.example.org:4443/masque?h={target_host}&p={target_port}")
        assertEquals("/masque?h=example.net&p=443", b.expand("example.net", 443).pathAndQuery)
        assertEquals("proxy.example.org:4443", b.expand("example.net", 443).authority)
        val c = UdpUriTemplate.parseAbsolute("https://proxy.example.org:4443/masque{?target_host,target_port}")
        assertEquals("/masque?target_host=2001%3Adb8%3A%3A42&target_port=443", c.expand("2001:db8::42", 443).pathAndQuery)
    }

    /** Section 3: "if target_host contains an IPv6 literal, the colons (":") MUST be percent-encoded"; brackets are not part of it. */
    @Test fun ipv6TargetIsPercentEncodedWithoutBrackets() {
        val t = UdpUriTemplate.parseAbsolute("https://p.example/.well-known/masque/udp/{target_host}/{target_port}/")
        assertEquals("/.well-known/masque/udp/2001%3Adb8%3A%3A42/443/", t.expand("2001:db8::42", 443).pathAndQuery)
        assertEquals("/.well-known/masque/udp/2001%3Adb8%3A%3A42/443/", t.expand("[2001:db8::42]", 443).pathAndQuery)
        assertEquals("/.well-known/masque/udp/%3A%3Affff%3A192.0.2.1/1/", t.expand("::ffff:192.0.2.1", 1).pathAndQuery)
    }

    @Test fun ampersandExpressionAndExtraVariablesExpand() {
        val t = UdpUriTemplate.parseAbsolute("https://p.example/m?x=1{&target_host,target_port,other}")
        // RFC 6570 section 3.2.1: an undefined variable expands to nothing
        assertEquals("/m?x=1&target_host=h.example&target_port=53", t.expand("h.example", 53).pathAndQuery)
    }

    @Test fun wellKnownDefaultTemplate() {
        val t = UdpUriTemplate.wellKnown("proxy.example:8443")
        assertEquals("https://proxy.example:8443/.well-known/masque/udp/{target_host}/{target_port}/", t.text)
        assertEquals("/.well-known/masque/udp/a.example/1/", t.expand("a.example", 1).pathAndQuery)
    }

    /** Section 2: every listed requirement, each one failing alone. */
    @Test fun negative_templatesBreakingSection2AreRejected() {
        val bad =
            mapOf(
                "level 4 explode" to "https://p.example/m/{target_host*}/{target_port}",
                "level 4 prefix" to "https://p.example/m/{target_host:3}/{target_port}",
                "relative" to "/m/{target_host}/{target_port}",
                "no scheme" to "//p.example/m/{target_host}/{target_port}",
                "empty authority" to "https:///m/{target_host}/{target_port}",
                "empty path" to "https://p.example?h={target_host}&p={target_port}",
                "variable in authority" to "https://{target_host}.example/{target_port}",
                "variable in scheme" to "{s}://p.example/{target_host}/{target_port}",
                "no target_host" to "https://p.example/m/{target_port}",
                "no target_port" to "https://p.example/m/{target_host}",
                "space" to "https://p.example/m /{target_host}/{target_port}",
                "non-ASCII" to "https://p.example/mé/{target_host}/{target_port}",
                "control" to "https://p.example/m\t/{target_host}/{target_port}",
                "reserved expansion" to "https://p.example/m/{+target_host}/{target_port}",
                "fragment expansion" to "https://p.example/m/{#target_host}/{target_port}",
                "label expansion" to "https://p.example/m/{.target_host}/{target_port}",
                "path segment expansion" to "https://p.example/m{/target_host,target_port}",
                "path-style parameters" to "https://p.example/m{;target_host,target_port}",
                "reserved operator" to "https://p.example/m/{=target_host}/{target_port}",
                "unclosed expression" to "https://p.example/m/{target_host/{target_port}",
                "stray brace" to "https://p.example/m/}/{target_host}/{target_port}",
                "empty expression" to "https://p.example/m/{}/{target_host}/{target_port}",
                "empty variable" to "https://p.example/m/{target_host,}/{target_port}",
                "bad variable name" to "https://p.example/m/{target-host}/{target_port}",
                "bad pct in literal" to "https://p.example/m%zz/{target_host}/{target_port}",
                "quote in literal" to "https://p.example/m\"/{target_host}/{target_port}",
                "fragment" to "https://p.example/m/{target_host}/{target_port}#f",
                "userinfo" to "https://u@p.example/m/{target_host}/{target_port}",
                "empty" to "",
            )
        for ((why, t) in bad) {
            assertFailsWith<IllegalArgumentException>("$why: $t") { UdpUriTemplate.parseAbsolute(t) }
        }
    }

    /** Section 3: the variables must be valid; the client refuses before anything is sent. */
    @Test fun negative_invalidTargetsAreRejectedByTheClient() {
        val t = UdpUriTemplate.wellKnown("p.example")
        for (port in listOf(
            0,
            -1,
            65536,
            Int.MAX_VALUE,
        )) {
            assertFailsWith<IllegalArgumentException>("port $port") { t.expand("a.example", port) }
        }
        for (host in listOf("", "fe80::1%en0", "[fe80::1%25en0]", "a b", "a..b", "-a.example", "a/b", "1.2.3", "256.1.1.1", "xé.example")) {
            assertFailsWith<IllegalArgumentException>("host '$host'") { t.expand(host, 443) }
        }
    }

    // ---- server: matching (section 3.1) ----

    @Test fun matchesTheDefaultTemplate() {
        val t = UdpUriTemplate.parsePath(UdpUriTemplate.WELL_KNOWN_PATH)
        val m = target(t.match("/.well-known/masque/udp/192.0.2.6/443/"))
        assertContentEquals(byteArrayOf(192.toByte(), 0, 2, 6), assertIs<UdpHost.Ipv4>(m.host).bytes)
        assertEquals(443, m.port)
        val v6 = target(t.match("/.well-known/masque/udp/2001%3adb8%3A%3A42/443/"))
        assertEquals("2001:db8::42", assertIs<UdpHost.Ipv6>(v6.host).text)
        val name = target(t.match("/.well-known/masque/udp/example.net/53/"))
        assertEquals("example.net", assertIs<UdpHost.Name>(name.host).name)
    }

    @Test fun matchesQueryTemplates() {
        val q = UdpUriTemplate.parsePath("/masque{?target_host,target_port}")
        val m = target(q.match("/masque?target_host=2001%3Adb8%3A%3A42&target_port=443"))
        assertEquals("2001:db8::42", m.host.text)
        val l = UdpUriTemplate.parsePath("/masque?h={target_host}&p={target_port}")
        assertEquals(443, target(l.match("/masque?h=example.net&p=443")).port)
        val mixed = UdpUriTemplate.parsePath("/m{?target_host}&x=1{&target_port}")
        assertEquals(80, target(mixed.match("/m?target_host=a.example&x=1&target_port=80")).port)
    }

    /** Every expansion of the client parses back to its target on the server, for each form of template. */
    @Test fun expandThenMatchRoundTrips() {
        val templates =
            listOf(
                "https://p.example/.well-known/masque/udp/{target_host}/{target_port}/",
                "https://p.example/masque?h={target_host}&p={target_port}",
                "https://p.example/masque{?target_host,target_port}",
                "https://p.example/x/{target_port}/{target_host}",
                "https://p.example/m{?target_port}{&target_host}",
            )
        val hosts =
            listOf(
                "192.0.2.6",
                "2001:db8::42",
                "::",
                "::ffff:192.0.2.1",
                "1:2:3:4:5:6:7:8",
                "example.net",
                "a_b.example.",
                "xn--d1acj3b.example",
            )
        for (text in templates) {
            val client = UdpUriTemplate.parseAbsolute(text)
            val server = UdpUriTemplate.parsePath(text.substring(text.indexOf('/', 8)))
            for (h in hosts) {
                for (port in listOf(1, 443, 65535)) {
                    val m = target(server.match(client.expand(h, port).pathAndQuery))
                    assertEquals(port, m.port, "$text $h")
                    assertEquals(UdpHost.parse(h)!!.text, m.host.text, "$text $h")
                }
            }
        }
    }

    @Test fun pathThatDoesNotFitTheTemplateIsNoMatch() {
        val t = UdpUriTemplate.parsePath(UdpUriTemplate.WELL_KNOWN_PATH)
        for (p in listOf(
            "/",
            "/.well-known/masque/ip/1.2.3.4/443/",
            "/.well-known/masque/udp/1.2.3.4/443",
            "/.well-known/masque/udp/1.2.3.4/443/x",
        )) {
            assertIs<TemplateMatch.NoMatch>(t.match(p), p)
        }
    }

    /** Section 3: empty variables, a port outside 1..65535, unencoded colons, zone IDs, brackets: invalid, which a proxy answers with 400. */
    @Test fun negative_invalidTargetValuesAreInvalidNotMatched() {
        val t = UdpUriTemplate.parsePath(UdpUriTemplate.WELL_KNOWN_PATH)
        val invalid =
            listOf(
                "/.well-known/masque/udp//443/",
                "/.well-known/masque/udp/192.0.2.6//",
                "/.well-known/masque/udp/192.0.2.6/0/",
                "/.well-known/masque/udp/192.0.2.6/65536/",
                "/.well-known/masque/udp/192.0.2.6/4x3/",
                "/.well-known/masque/udp/192.0.2.6/99999999999999999999/",
                "/.well-known/masque/udp/2001:db8::42/443/",
                "/.well-known/masque/udp/fe80%3A%3A1%25en0/443/",
                "/.well-known/masque/udp/%5B2001%3Adb8%3A%3A42%5D/443/",
                "/.well-known/masque/udp/192.0.2.256/443/",
                "/.well-known/masque/udp/1.2.3/443/",
                "/.well-known/masque/udp/a%2Fb/443/",
                "/.well-known/masque/udp/a%00b/443/",
                "/.well-known/masque/udp/%E2%82%AC.example/443/",
                "/.well-known/masque/udp/a%zzb/443/",
                "/.well-known/masque/udp/a%2/443/",
            )
        for (p in invalid) assertIs<TemplateMatch.Invalid>(t.match(p), p)
        val q = UdpUriTemplate.parsePath("/masque{?target_host,target_port}")
        assertIs<TemplateMatch.Invalid>(q.match("/masque?target_host=a.example"))
        assertIs<TemplateMatch.Invalid>(q.match("/masque?target_host=&target_port=1"))
    }

    /** A server's template must be one a request can be matched against without guessing. */
    @Test fun negative_ambiguousServerTemplatesAreRejected() {
        for (bad in listOf(
            "/m/{target_host}{target_port}",
            "/m/{target_host}-{target_port}",
            "/m/{target_host,target_port}",
            "/m/{target_host}/{target_port}/{target_port}",
            "/m{?target_host}x{&target_port}",
            "m/{target_host}/{target_port}",
        )) {
            assertFailsWith<IllegalArgumentException>(bad) { UdpUriTemplate.parsePath(bad) }
        }
        // the same templates are fine for a client, which only expands them (but for the missing slash)
        UdpUriTemplate.parseAbsolute("https://p.example/m/{target_host}{target_port}")
        assertTrue(UdpUriTemplate.parseAbsolute("https://p.example/m/{target_host,target_port}").text.isNotEmpty())
    }

    // ---- target_host syntax (RFC 3986 IPv4address / IPv6address / reg-name) ----

    @Test fun hostSyntax() {
        assertEquals("2001:db8::42", UdpHost.parse("2001:0db8:0:0:0:0:0:42")!!.text)
        assertEquals("::", UdpHost.parse("::")!!.text)
        assertEquals("::1", UdpHost.parse("0:0:0:0:0:0:0:1")!!.text)
        assertEquals("1::", UdpHost.parse("1:0:0:0:0:0:0:0")!!.text)
        assertEquals("1:0:0:2::", UdpHost.parse("1:0:0:2:0:0:0:0")!!.text)
        assertEquals("::ffff:192.0.2.1", UdpHost.parse("::ffff:c000:201")!!.text)
        assertEquals(16, (UdpHost.parse("1:2:3:4:5:6:1.2.3.4") as UdpHost.Ipv6).bytes.size)
        for (bad in listOf(
            "1:2:3:4:5:6:7:8:9",
            "1::2::3",
            ":1:2:3:4:5:6:7",
            "1:2:3:4:5:6:7:",
            "12345::",
            "::g",
            "1:2:3:4:5:6:7:1.2.3.4",
            "::1.2.3",
            "01.2.3.4",
            "1.2.3.4.5",
            "",
        )) {
            assertEquals(null, UdpHost.parse(bad), "'$bad' parsed")
        }
        assertEquals(null, UdpHost.parse("a".repeat(64) + ".example"))
        assertEquals(null, UdpHost.parse(("a".repeat(63) + ".").repeat(4) + "example"))
        assertEquals("a-b.example", (UdpHost.parse("A-B.Example") as UdpHost.Name).name.lowercase())
    }
}
