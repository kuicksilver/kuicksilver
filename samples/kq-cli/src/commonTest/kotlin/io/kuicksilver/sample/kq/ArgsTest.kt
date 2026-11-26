// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.sample.kq

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.milliseconds

class ArgsTest {
    private fun run(vararg a: String): Options = assertIs<Parsed.Run>(parseArgs(a.toList())).options

    private fun error(vararg a: String): String = assertIs<Parsed.Error>(parseArgs(a.toList())).message

    @Test fun getWithEveryOption() {
        val o =
            run(
                "get", "-v", "-i", "--http3", "-H", "Accept: text/plain", "-o", "out.bin", "--qlog", "q", "--cacert", "ca.pem",
                "--alt-svc", "alt.txt", "--repeat", "3", "--0rtt", "--connect-timeout", "1.5", "https://example.com/x?y=1",
            )
        assertEquals("GET", o.method)
        assertEquals("https://example.com/x?y=1", o.url.toString())
        assertEquals(Mode.Http3, o.mode)
        assertTrue(o.verbose && o.includeHeaders && o.zeroRtt)
        assertEquals(listOf("Accept" to "text/plain"), o.headers)
        assertEquals(listOf("out.bin", "q", "ca.pem", "alt.txt"), listOf(o.output, o.qlogDir, o.caCert, o.altSvcFile))
        assertEquals(3, o.repeat)
        assertEquals(1500.milliseconds, o.connectTimeout)
    }

    @Test fun modes() {
        assertEquals(Mode.Auto, run("get", "https://a.test/").mode)
        assertEquals(Mode.Http3Only, run("get", "--http3-only", "https://a.test/").mode)
        assertEquals(Mode.Http2, run("get", "--http2", "https://a.test/").mode)
        assertEquals(Mode.Http11, run("head", "--http1.1", "http://a.test/").mode)
        assertEquals("HEAD", run("head", "https://a.test/").method)
        assertEquals("-", run("get", "-o", "-", "https://a.test/").output)
    }

    @Test fun helpAndVersion() {
        assertEquals(Parsed.Help, parseArgs(listOf("get", "--help")))
        assertEquals(Parsed.Help, parseArgs(listOf("-h")))
        assertEquals(Parsed.Version, parseArgs(listOf("--version")))
        assertEquals(Parsed.Help, parseArgs(listOf("-v", "--help", "get")))
    }

    @Test fun optionsBeforeTheCommandAndTheSeparator() {
        val o = run("-v", "--http3-only", "get", "-i", "--", "https://a.test/")
        assertEquals(Mode.Http3Only, o.mode)
        assertTrue(o.verbose && o.includeHeaders)
        assertEquals("https://a.test/", o.url.toString())
        assertEquals("--help", run("get", "-H", "X: --help", "https://a.test/").headers.single().second) // a value, not the option
        assertEquals("X-Empty" to "", run("get", "-H", "X-Empty:", "https://a.test/").headers.single()) // sent empty
        assertEquals("X" to "a\tb", run("get", "-H", "X:  a\tb ", "https://a.test/").headers.single())
    }

    @Test fun userinfoIsRedacted() {
        assertEquals("https://h.test/p@q", redact("https://u:p@h.test/p@q"))
        assertEquals("https://h.test/", redact("https://h.test/"))
        assertTrue("secret" !in error("get", "ftp://u:secret@h.test/"))
        assertTrue("secret" !in error("get", "https://u:secret@a.test/", "https://v:secret@b.test/"), "two URLs")
        assertEquals("kq: GET https://h.test/ failed: url=https://h.test/x", redact("kq: GET https://u:p@h.test/ failed: url=https://u:p@h.test/x"))
    }

    @Test fun negative_usageErrors() {
        assertEquals("no command", error())
        assertTrue("unknown command" in error("post", "https://a.test/"))
        assertEquals("no URL", error("get", "-v"))
        assertTrue("exclude each other" in error("get", "--http3", "--http2", "https://a.test/"))
        assertTrue("unknown option" in error("get", "--insecure", "https://a.test/"))
        assertTrue("more than one URL" in error("get", "https://a.test/", "https://b.test/"))
        assertTrue("more than one URL" in error("get", "https://a.test/", "--", "https://b.test/"))
        assertTrue("not an http" in error("get", "ftp://a.test/"))
        assertTrue("not an http" in error("get", "a.test"))
        assertTrue("needs an https" in error("get", "--http3-only", "http://a.test/"))
        assertTrue("1..100" in error("get", "--repeat", "0", "https://a.test/"))
        assertTrue("1..100" in error("get", "--repeat", "101", "https://a.test/"))
        assertTrue("needs a number" in error("get", "--repeat", "x", "https://a.test/"))
        assertTrue("needs a value" in error("get", "-H"))
        assertTrue("needs a file" in error("get", "-o", "--http3", "https://a.test/"))
        assertTrue("needs a file" in error("get", "-o", "--help", "https://a.test/")) // never the help text
        assertTrue("seconds" in error("get", "--connect-timeout", "0", "https://a.test/"))
        assertTrue("seconds" in error("get", "--connect-timeout", "NaN", "https://a.test/"))
        assertTrue("HTTP/3 only" in error("get", "--0rtt", "--http2", "https://a.test/"))
        assertTrue("HTTP/3 only" in error("get", "--0rtt", "--http1.1", "https://a.test/"))
        assertTrue("HTTP/3 only" in error("get", "--0rtt", "http://a.test/"))
    }

    @Test fun negative_invalidHeaders() {
        assertTrue("not 'name: value'" in error("get", "-H", "novalue", "https://a.test/"))
        assertTrue("empty name" in error("get", "-H", ": v", "https://a.test/"))
        assertTrue("not a token" in error("get", "-H", "Bad Name: v", "https://a.test/"))
        assertTrue("not a token" in error("get", "-H", "X(y): v", "https://a.test/"))
        assertTrue("not a token" in error("get", "-H", "Na\u00efve: v", "https://a.test/"))
        assertTrue("control character" in error("get", "-H", "X: a\r\nInjected: 1", "https://a.test/"))
        assertTrue("control character" in error("get", "-H", "X: a\nb", "https://a.test/"))
        assertTrue("control character" in error("get", "-H", "X: a\u0000b", "https://a.test/"))
        assertTrue("control character" in error("get", "-H", "X: a\u007fb", "https://a.test/"))
        assertTrue("above U+00FF" in error("get", "-H", "X: \u20ac", "https://a.test/"))
        assertEquals("X" to "caf\u00e9", run("get", "-H", "X: caf\u00e9", "https://a.test/").headers.single()) // obs-text
    }
}
