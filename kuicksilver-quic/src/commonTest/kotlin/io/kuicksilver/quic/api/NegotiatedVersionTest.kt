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
import kotlinx.coroutines.async
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import kotlinx.coroutines.yield
import kotlin.concurrent.atomics.AtomicReference
import kotlin.concurrent.atomics.ExperimentalAtomicApi
import kotlin.concurrent.atomics.update
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertSame
import kotlin.test.assertTrue
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
        admission: io.kuicksilver.quic.ConnectionAdmission? = null,
        onServerStats: (io.kuicksilver.quic.EndpointStats) -> Unit = {},
    ): Unit =
        runBlocking {
            withTimeout(10.seconds) {
                val heard = Heard()
                ApiPair.open(serverQuic = server, crypto = KslQuicCrypto, clientListener = heard, admission = admission).use { p ->
                    val (c, s) = p.connect(client)
                    onServerStats(p.server.stats)
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

    /**
     * Incompatible version negotiation (RFC 9000 section 6): the client starts in v2, which the server does not speak; its
     * Version Negotiation packet makes the client start over in v1, the version the connection reports.
     */
    @Test fun aVersionNegotiationRestartReportsTheVersionItRestartedIn() {
        val client = versions(VersionProfile.V2, VersionProfile.V1)
        assertSame(VersionProfile.V2, client.firstVersion)
        settles(client, versions(VersionProfile.V1), VersionProfile.V1) { stats ->
            // one per datagram of the v2 first flight (a post-quantum ClientHello takes two)
            assertTrue(stats.versionNegotiations > 0, "the server answered the v2 Initial with Version Negotiation")
        }
    }

    /** Through a Retry (RFC 9000 section 8.1.2), the compatible switch from v1 to v2 still settles on v2 for both. */
    @Test fun aRetryKeepsTheNegotiatedVersion() =
        settles(
            versions(VersionProfile.V1, VersionProfile.V2),
            versions(VersionProfile.V2, VersionProfile.V1),
            VersionProfile.V2,
            admission = io.kuicksilver.quic.ConnectionAdmission.AlwaysRetry,
        ) { stats -> assertTrue(stats.retriesSent > 0, "a Retry went out") }

    /**
     * A server's 0-RTT connection (RFC 9001 section 4.6) is handed to accept() before its handshake completed: its version
     * is set by then, and the listener reads it in onZeroRtt(Accepted).
     */
    @Test fun aServersEarlyConnectionHasItsVersionBeforeTheHandshakeCompleted(): Unit =
        runBlocking {
            withTimeout(20.seconds) {
                val atZeroRtt = CompletableDeferred<Pair<VersionProfile?, Boolean>>()
                val serverListener =
                    object : ConnectionListener {
                        override fun onZeroRtt(
                            connection: ConnectionInfo,
                            outcome: io.kuicksilver.quic.ZeroRttOutcome,
                        ) {
                            if (outcome == io.kuicksilver.quic.ZeroRttOutcome.Accepted) {
                                atZeroRtt.complete(connection.version to connection.connection.isHandshakeComplete)
                            }
                        }
                    }
                // both sides v2 only: a version left at the v1 default could not pass
                val v2 = versions(VersionProfile.V2)
                ApiPair
                    .open(serverQuic = v2, crypto = KslQuicCrypto, serverEarlyData = true, serverConfigure = { listener = serverListener })
                    .use { p ->
                        val clientConfig =
                            io.kuicksilver.quic.QuicClientConfig
                                .Builder(
                                    io.kuicksilver.quic.CoreFixtures
                                        .client(),
                                ).apply {
                                    earlyData = io.kuicksilver.tls.EarlyDataState.Allowed
                                    quic = v2
                                }.build()
                        // a first connection leaves the client a ticket
                        val firstAccepted = async { p.server.accept() }
                        val first = p.client.connect(p.server.localAddress, clientConfig)
                        firstAccepted.await().awaitHandshake()
                        val sessions = (p.client as io.kuicksilver.quic.runtime.EndpointLoop).sessions
                        while (sessions.size() == 0) yield()
                        first.close()
                        // the client's packets wait: the server accepts the early connection before the handshake can complete
                        p.net.hold(p.clientIo.localAddress)
                        val accepted = async { p.server.accept() }
                        val second = p.client.connectEarly(p.server.localAddress, clientConfig)
                        second.openUni().output.flushAndClose() // something early, so the server has 0-RTT to accept
                        p.net.release(p.clientIo.localAddress)
                        val (version, complete) = atZeroRtt.await()
                        assertSame(VersionProfile.V2, version, "set when the early data was accepted")
                        assertEquals(false, complete, "before the handshake completed")
                        val s = accepted.await()
                        assertSame(VersionProfile.V2, s.version, "from accept(), whether or not the handshake completed since")
                        second.awaitHandshake()
                        assertSame(VersionProfile.V2, second.version)
                        second.close()
                    }
            }
        }
}
