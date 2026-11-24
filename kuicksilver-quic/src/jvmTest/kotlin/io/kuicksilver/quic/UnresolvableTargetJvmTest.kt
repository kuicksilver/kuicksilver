// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic

import io.ktor.network.sockets.InetSocketAddress
import io.kuicksilver.tls.KslQuicCrypto
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertSame
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.seconds

/**
 * A connect target whose name did not resolve: built with `createUnresolved` (what java.net leaves when the lookup fails), so
 * this runs the same on every host whatever its DNS answers. The address is internal to Ktor, hence the reflection (as in
 * [PreferredAddressJvmTest]).
 */
class UnresolvableTargetJvmTest {
    private val name: InetSocketAddress =
        InetSocketAddress::class.java
            .getConstructor(java.net.InetSocketAddress::class.java)
            .newInstance(java.net.InetSocketAddress.createUnresolved("unresolvable.invalid", 443))

    /** The name stays as it is, as the KDoc says: no lookup, no exception. */
    @Test fun withLiteralHostKeepsAnUnresolvedName() {
        assertSame(name, name.withLiteralHost())
        assertEquals("unresolvable.invalid", name.withLiteralHost(444).hostname)
    }

    /**
     * Connecting to it fails at once with [QuicException.ConnectionLost.NoViablePath] whose cause is an `IOException`
     * naming the target, as on Kotlin/Native (KtorDatagramIoTest). Red before: the handshake timeout, 10 s later, every
     * datagram to the unresolved address lost.
     */
    @Test fun negative_aConnectToAnUnresolvableTargetIsNoViablePathAtOnce(): Unit =
        runBlocking {
            val client =
                QuicEndpoint.bind(
                    InetSocketAddress("127.0.0.1", 0),
                    QuicEndpointConfig.Builder().apply { crypto = KslQuicCrypto }.build(),
                )
            try {
                val e =
                    assertFailsWith<QuicException.ConnectionLost.NoViablePath> {
                        withTimeout(5.seconds) { client.connect(name, QuicClientConfig.Builder(CoreFixtures.client()).build()) }
                    }
                val cause = e.cause
                assertTrue(cause is kotlinx.io.IOException, "the address error as the cause: $cause")
                assertTrue("unresolvable.invalid" in (cause.message ?: ""), "${cause.message}")
            } finally {
                client.closeAndJoin()
            }
        }
}
