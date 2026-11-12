// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(io.kuicksilver.annotations.InternalKuicksilverApi::class)

package io.kuicksilver.tls

import io.kuicksilver.native.KslConst
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** [KslNet]: one family per lookup through `ksl_resolve`, and the attributes of the host's own loopback address. */
class KslNetTest {
    @Test fun resolvesOneFamilyAtATime() {
        val v4 = assertNotNull(KslNet.resolve("localhost", ipv6 = false))
        assertTrue(v4.isNotEmpty() && v4.all { it.bytes.size == 4 }, "${v4.map { it.bytes.toList() }}")
        val literal = assertNotNull(KslNet.resolve("127.0.0.1", ipv6 = false)).single()
        assertContentEquals(byteArrayOf(127, 0, 0, 1), literal.bytes)
        // an IPv4 literal has no IPv6 address (getaddrinfo would hand out ::ffff:127.0.0.1 on Apple with AI_V4MAPPED)
        assertEquals(emptyList(), KslNet.resolve("127.0.0.1", ipv6 = true)?.map { it.bytes.toList() } ?: emptyList())
    }

    @Test fun negative_badNameIsAFailedLookup() {
        assertNull(KslNet.resolve("a b.example", ipv6 = false))
    }

    @Test fun negative_malformedAnswersAreRefused() {
        assertNull(KslNet.decode(ByteArray(KslConst.RESOLVE_ENTRY_LEN - 1), KslConst.ADDR_V4))
        val v6Entry = ByteArray(KslConst.RESOLVE_ENTRY_LEN).also { it[0] = KslConst.ADDR_V6.toByte() }
        assertNull(KslNet.decode(v6Entry, KslConst.ADDR_V4), "an entry of the other family")
        val scoped = v6Entry.copyOf().also { it[20] = 3 }
        assertEquals(3, KslNet.decode(scoped, KslConst.ADDR_V6)!!.single().scopeId)
    }

    @Test fun loopbackIsAnAddressOfThisHost() {
        val info = assertNotNull(KslNet.addressInfo(byteArrayOf(127, 0, 0, 1), 0))
        assertEquals(8, info.prefixLength)
        assertTrue(!info.deprecated && !info.tunnel)
        assertNull(KslNet.addressInfo(byteArrayOf(192.toByte(), 0, 2, 1), 0), "TEST-NET-1 is no address of this host")
    }
}
