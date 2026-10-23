// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)

package io.kuicksilver.ktor.client.h1

import io.ktor.utils.io.ByteChannel
import io.ktor.utils.io.readRemaining
import io.ktor.utils.io.writeFully
import io.kuicksilver.ktor.client.ProxyCredentials
import io.kuicksilver.ktor.client.ProxyException
import kotlinx.coroutines.runBlocking
import kotlinx.io.readByteArray
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** The SOCKS5 client handshake (RFC 1928, RFC 1929) against scripted proxy replies, byte for byte. */
class Socks5Test {
    private val ok = bytes(5, 0, 0, 1, 127, 0, 0, 1, 0x1f, 0x90) // succeeded, BND 127.0.0.1:8080

    private fun bytes(vararg b: Int) = ByteArray(b.size) { b[it].toByte() }

    /** Runs the handshake with the proxy's [replies] queued; the bytes the client sent, or the failure. */
    private fun handshake(
        replies: ByteArray,
        target: Socks5Target = Socks5Target.Domain("localhost"),
        port: Int = 443,
        credentials: ProxyCredentials? = null,
    ): Pair<ByteArray, Throwable?> =
        runBlocking {
            val input = ByteChannel()
            input.writeFully(replies)
            input.flushAndClose()
            val output = ByteChannel()
            val failure = runCatching { socks5Connect(input, output, target, port, credentials, "proxy.test:1080") }.exceptionOrNull()
            output.flushAndClose()
            output.readRemaining().readByteArray() to failure
        }

    @Test fun greetingOffersUserPassOnlyWithCredentials() {
        val (plain, _) = handshake(bytes(5, 0) + ok)
        assertContentEquals(bytes(5, 1, 0), plain.copyOf(3))
        val (auth, _) = handshake(bytes(5, 2, 1, 0) + ok, credentials = ProxyCredentials("u", "p"))
        assertContentEquals(bytes(5, 2, 0, 2), auth.copyOf(4))
        assertContentEquals(bytes(1, 1, 'u'.code, 1, 'p'.code), auth.copyOfRange(4, 9), "RFC 1929 request")
    }

    @Test fun hostnameSentAsDomainAtyp() {
        val (sent, failure) = handshake(bytes(5, 0) + ok)
        assertNull(failure)
        assertContentEquals(bytes(5, 1, 0, 3, 9) + "localhost".encodeToByteArray() + bytes(1, 0xBB), sent.copyOfRange(3, sent.size))
    }

    @Test fun ipv6LiteralUsesAtyp4() {
        val v6 = ByteArray(16).also { it[15] = 1 } // ::1
        val (sent, failure) = handshake(bytes(5, 0) + ok, target = Socks5Target.Address(v6), port = 8443)
        assertNull(failure)
        assertContentEquals(bytes(5, 1, 0, 4) + v6 + bytes(0x20, 0xFB), sent.copyOfRange(3, sent.size))
        val (v4, _) = handshake(bytes(5, 0) + ok, target = Socks5Target.Address(bytes(10, 0, 0, 1)), port = 80)
        assertContentEquals(bytes(5, 1, 0, 1, 10, 0, 0, 1, 0, 80), v4.copyOfRange(3, v4.size))
    }

    @Test fun replyWithDomainOrIpv6BoundAddressIsConsumed() {
        val domain = bytes(5, 0, 0, 3, 4) + "host".encodeToByteArray() + bytes(0, 80)
        assertNull(handshake(bytes(5, 0) + domain).second)
        val v6 = bytes(5, 0, 0, 4) + ByteArray(16) + bytes(0, 80)
        assertNull(handshake(bytes(5, 0) + v6).second)
    }

    @Test fun negative_socksNoAcceptableMethodFails() {
        val e = handshake(bytes(5, 0xFF)).second
        assertTrue(e is ProxyException && "no acceptable" in e.message!!, "$e")
    }

    /** A proxy that picks "no authentication" never sees the password (RFC 1929 section 5: it travels in clear). */
    @Test fun negative_socksCredentialsNotSentWhenServerChoosesNoAuth() {
        val (sent, failure) = handshake(bytes(5, 0) + ok, credentials = ProxyCredentials("user", "s3cret"))
        assertNull(failure)
        assertFalse(sent.decodeToString().contains("s3cret"), "the password went to a proxy that did not ask for it")
    }

    /** Username/password chosen by a proxy we offered none to is a protocol violation, not a prompt for credentials. */
    @Test fun negative_socksUnofferedMethodFails() {
        assertTrue(handshake(bytes(5, 2)).second is ProxyException)
        assertTrue(handshake(bytes(4, 0) + ok).second is ProxyException, "a reply that is not SOCKS5")
    }

    /** RFC 1929 says the reply's VER is 1; a proxy that answers 5 (the SOCKS version) is tolerated, as curl does. */
    @Test fun authReplyVersion5Tolerated() {
        assertNull(handshake(bytes(5, 2, 5, 0) + ok, credentials = ProxyCredentials("u", "p")).second)
        assertTrue(handshake(bytes(5, 2, 4, 0) + ok, credentials = ProxyCredentials("u", "p")).second is ProxyException)
    }

    @Test fun negative_socksAuthRejected() {
        val e = handshake(bytes(5, 2, 1, 1), credentials = ProxyCredentials("u", "p")).second
        assertTrue(e is ProxyException && e.replyCode == null && "rejected" in e.message!!, "$e")
        assertFalse(e.message!!.contains("p@") || e.message!!.contains(":p"), e.message)
    }

    @Test fun negative_socksReplyUnknownAtypFails() {
        val e = handshake(bytes(5, 0, 5, 0, 0, 7, 1, 2, 3, 4, 0, 80)).second
        assertTrue(e is ProxyException && "address type" in e.message!!, "$e")
    }

    @Test fun negative_socksOverlongCredentialsRejected() {
        val (sent, failure) = handshake(bytes(5, 2, 1, 0) + ok, credentials = ProxyCredentials("u".repeat(256), "p"))
        assertTrue(failure is IllegalArgumentException, "$failure")
        assertEquals(0, sent.size, "something was sent before the credentials were checked")
        assertTrue(handshake(bytes(5, 0) + ok, credentials = ProxyCredentials("", "p")).second is IllegalArgumentException)
        val long = handshake(bytes(5, 0) + ok, target = Socks5Target.Domain("a".repeat(256))).second
        assertTrue(long is IllegalArgumentException, "a name longer than 255 bytes: $long")
    }

    @Test fun socksReplyCodesMapped() {
        val e = handshake(bytes(5, 0, 5, 5, 0, 1, 0, 0, 0, 0, 0, 0)).second
        assertTrue(e is ProxyException && e.replyCode == 5 && "connection refused" in e.message!!, "$e")
        val other = handshake(bytes(5, 0, 5, 0x42, 0, 1, 0, 0, 0, 0, 0, 0)).second
        assertTrue(other is ProxyException && other.replyCode == 0x42, "$other")
    }

    @Test fun negative_truncatedReplyFails() {
        assertTrue(handshake(bytes(5, 0, 5, 0, 0, 1, 127)).second != null)
    }
}
