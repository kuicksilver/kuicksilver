// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic

import io.ktor.network.sockets.InetSocketAddress
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNull

/**
 * A [PreferredAddress] given a host name is refused naming that name, and the literal of an unresolved address is its
 * text: built with `createUnresolved`, the address needs no resolver, so this runs the same on every host (the common
 * test's address is resolved by java.net where a resolver answers for `.invalid`). Ktor's constructor from a java.net
 * address is internal to Ktor (Kotlin `internal`, public in the bytecode), hence the reflection: a NoSuchMethodException
 * here means a Ktor upgrade changed that constructor, not that the code under test broke.
 */
class PreferredAddressJvmTest {
    private val name: InetSocketAddress =
        InetSocketAddress::class.java
            .getConstructor(java.net.InetSocketAddress::class.java)
            .newInstance(java.net.InetSocketAddress.createUnresolved("preferred.invalid", 4433))

    @Test fun nameIsRefusedByItsName() {
        assertNull(name.ipBytesNoDns(), "unresolved")
        assertEquals("preferred.invalid", name.ipLiteral())
        val v4 = assertFailsWith<IllegalArgumentException> { PreferredAddress(name, null) }
        assertEquals("ipv4 is not an IPv4 literal: preferred.invalid", v4.message)
        val v6 = assertFailsWith<IllegalArgumentException> { PreferredAddress(null, name) }
        assertEquals("ipv6 is not an IPv6 literal: preferred.invalid", v6.message)
    }
}
