// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.api

import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.native.KslLoader
import io.kuicksilver.quic.ConnectionInfo
import io.kuicksilver.quic.ConnectionListener
import io.kuicksilver.quic.QuicConfig
import io.kuicksilver.quic.QuicException
import io.kuicksilver.quic.VersionProfile
import io.kuicksilver.tls.KslQuicCrypto
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import kotlin.concurrent.atomics.AtomicReference
import kotlin.concurrent.atomics.ExperimentalAtomicApi
import kotlin.concurrent.atomics.update
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertSame
import kotlin.time.Duration.Companion.seconds

/**
 * `QuicConnection.version` and `ConnectionInfo.version` (docs/guide/quic.md, "Versions"): the version the handshake settled,
 * which compatible version negotiation (RFC 9368) can make differ from the one the client's first flight offered.
 */
@OptIn(ExperimentalKuicksilverApi::class, ExperimentalAtomicApi::class)
class NegotiatedVersionTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    /** What the client's listener read from [ConnectionInfo.version] in each callback, in order. */
    private class Heard : ConnectionListener {
        val seen = AtomicReference(emptyList<String>())
        val closed = CompletableDeferred<Unit>()

        override fun onOpened(connection: ConnectionInfo) {
            seen.update { it + "opened=${connection.version}" }
        }

        override fun onHandshakeCompleted(connection: ConnectionInfo) {
            seen.update { it + "completed=${connection.version}" }
        }

        override fun onClosed(
            connection: ConnectionInfo,
            reason: QuicException.ConnectionLost,
        ) {
            seen.update { it + "closed=${connection.version}" }
            closed.complete(Unit)
        }
    }

    private fun versions(vararg v: VersionProfile) = QuicConfig.Builder().apply { versions = v.toList() }.build()

    /** Connects a client offering [client] to a server offering [server] and checks both sides settled on [expected]. */
    private fun settles(
        client: QuicConfig,
        server: QuicConfig,
        expected: VersionProfile,
    ): Unit =
        runBlocking {
            withTimeout(10.seconds) {
                val heard = Heard()
                ApiPair.open(serverQuic = server, crypto = KslQuicCrypto, clientListener = heard).use { p ->
                    val (c, s) = p.connect(client)
                    s.awaitHandshake()
                    assertSame(expected, c.version, "client")
                    assertSame(expected, s.version, "server")
                    assertSame(expected, c.info?.version)
                    c.close()
                    c.closed.await()
                    assertSame(expected, c.version, "kept after the close")
                    heard.closed.await()
                    // null before the handshake settled it, the settled one from onHandshakeCompleted on
                    assertEquals(listOf("opened=null", "completed=$expected", "closed=$expected"), heard.seen.load())
                }
            }
        }

    @Test fun v1Only() = settles(QuicConfig.Default, QuicConfig.Default, VersionProfile.V1)

    @Test fun v2Negotiated() = settles(versions(VersionProfile.V2), versions(VersionProfile.V2, VersionProfile.V1), VersionProfile.V2)

    @Test fun compatibleNegotiationFromV1ToV2() {
        // the client's first flight is v1 (its first listed version); the server prefers v2 and switches (RFC 9368 section 2.3)
        val client = versions(VersionProfile.V1, VersionProfile.V2)
        assertSame(VersionProfile.V1, client.firstVersion)
        settles(client, versions(VersionProfile.V2, VersionProfile.V1), VersionProfile.V2)
    }

    @Test fun aServerPreferringV1StaysInV1() =
        settles(versions(VersionProfile.V1, VersionProfile.V2), versions(VersionProfile.V1, VersionProfile.V2), VersionProfile.V1)
}
