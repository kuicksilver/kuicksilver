// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class, io.kuicksilver.annotations.InternalKuicksilverApi::class)

package io.kuicksilver.quic

import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.seconds

/**
 * The in-memory identity of a default path: an [NwPathKey] names the interface only, so a move from one Wi-Fi network to
 * another on `en0` gives an equal key; the identity also holds the gateways and the interface's addresses, so that move is
 * a change (RFC 9460 section 12: the HTTPS record cache must be flushed on network changes; RFC 7838 section 2.2).
 */
class NwPathIdentityTest {
    private val en0 = NwPathKey(4, NwInterfaceType.Wifi, "en0")

    @Test fun negative_sameInterfaceAnotherNetworkIsAnotherIdentity() {
        val cafe = pathIdentity(en0, listOf("192.168.1.1", "fe80::1:aaaa"), listOf("192.168.1.23", "20010db8000a0000::/64"))
        val home = pathIdentity(en0, listOf("192.168.1.1", "fe80::2:bbbb"), listOf("192.168.1.23", "20010db8000b0000::/64"))
        assertEquals(en0, NwPathKey(4, NwInterfaceType.Wifi, "en0"), "NwPathKey alone does not tell them apart")
        assertNotEquals(cafe, home)
        assertNotEquals(pathIdentity(en0, listOf("10.0.0.1"), emptyList()), pathIdentity(en0, listOf("192.168.1.1"), emptyList()))
        // the same network in another order is the same identity
        assertEquals(pathIdentity(en0, listOf("a", "b"), listOf("c", "d")), pathIdentity(en0, listOf("b", "a"), listOf("d", "c")))
        // nothing known about the network behind the interface: no identity (the monitor then makes every update a change)
        assertNull(pathIdentity(en0, emptyList(), emptyList()))
    }

    /**
     * The identity's text holds local addresses: its toString is a keyed hash (HMAC-SHA256 under a per-process random key),
     * equal for equal identities within the process, distinct for distinct ones, and never shows the text.
     */
    @Test fun negative_identityToStringRevealsNoAddress() {
        val text = pathIdentity(en0, listOf("192.168.1.1"), listOf("192.168.1.23"))!!
        val a = NwPathIdentity(text)
        assertEquals(a, NwPathIdentity(text))
        assertEquals(a.toString(), NwPathIdentity(text).toString())
        val other = NwPathIdentity(pathIdentity(en0, listOf("192.168.1.1"), listOf("192.168.1.24"))!!)
        assertNotEquals(a, other)
        assertNotEquals(a.toString(), other.toString())
        assertFalse("192.168" in a.toString() || "en0" in a.toString() || "Wifi" in a.toString(), a.toString())
        assertTrue(Regex("NwPathIdentity\\(#[0-9a-f]{16}\\)").matches(a.toString()), a.toString())
    }

    /** The live source answers at once with the current path (null without a satisfied one). */
    @Test fun liveSourceAnswers() =
        runBlocking {
            withTimeout(10.seconds) { nwPathIdentities().first() }
            Unit
        }
}
