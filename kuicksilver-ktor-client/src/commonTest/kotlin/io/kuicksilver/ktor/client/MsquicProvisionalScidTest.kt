// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.client

import io.ktor.client.request.get
import io.ktor.client.statement.bodyAsText
import io.ktor.http.HttpProtocolVersion
import io.ktor.utils.io.writeStringUtf8
import io.kuicksilver.native.KslLoader
import io.kuicksilver.quic.QuicException
import io.kuicksilver.quic.TimeoutKind
import io.kuicksilver.quic.quicConfig
import kotlinx.coroutines.coroutineScope
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertTrue
import kotlin.time.Duration
import kotlin.time.Duration.Companion.seconds
import kotlin.time.TimeSource

/**
 * An msquic server (IIS, .NET Kestrel on Windows) that gets a ClientHello of three or more datagrams acknowledges the first
 * ones from the client's own DCID before its listener accepts the connection, then answers with the ServerHello from a new
 * SCID and names that one in initial_source_connection_id (msquic#3762, #4905). RFC 9000 section 7.2 makes the client
 * discard everything from the new SCID, and section 7.3 would fail the parameter anyway, so QUIC cannot connect: the call
 * goes over TCP, and the diagnostics say why.
 */
@OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)
class MsquicProvisionalScidTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    /**
     * An HTTP/3 origin behind a [udpRelay] on [port] whose TCP side of the same number serves HTTP/1.1; with
     * [msquicProvisionalScid] the relay answers the client's first Initial as msquic does. Runs [block] with the port.
     */
    private suspend fun msquicLikeOrigin(
        msquicProvisionalScid: Boolean,
        block: suspend (port: Int, relay: UdpRelay) -> Unit,
    ) = coroutineScope {
        val ep = h3Origin()
        try {
            udpRelay(ep.localAddress.port, tcpTwin = true) { port, relay ->
                relay.msquicProvisionalScid = msquicProvisionalScid
                tlsH1WithSilentUdp(silentUdp = false, listener = relay.tcp, handler = { _, input, output ->
                    while (readRequest(input).isNotEmpty()) {
                        output.writeStringUtf8("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nh1")
                    }
                }) { block(port, relay) }
            }
        } finally {
            ep.close()
        }
    }

    /**
     * The QUIC attempt ends by the handshake timeout (the client discards the ServerHello, RFC 9000 section 7.2, and
     * never hangs), and HTTP/1.1, which starts only once HTTP/3 failed here, serves the call: `FallbackReason.HandshakeTimeout`
     * with the QUIC failure in `h3Failure`.
     */
    @Test fun negative_msquicProvisionalScidFallsBackToTcp() =
        h3Test {
            msquicLikeOrigin(msquicProvisionalScid = true) { port, relay ->
                testClient(Http3DiscoveryMode.Preferred, engine = {
                    quic = quicConfig { handshakeTimeout = 2.seconds }
                    http3 { hardDelay = Duration.INFINITE }
                }).use { c ->
                    val t0 = TimeSource.Monotonic.markNow()
                    val r = c.get("https://127.0.0.1:$port/")
                    assertEquals("h1", r.bodyAsText())
                    val d = assertNotNull(r.kuicksilverDiagnostics)
                    assertEquals(HttpProtocolVersion.HTTP_1_1, d.protocol, "$d")
                    assertEquals(FallbackReason.HandshakeTimeout, d.fallback, "$d")
                    val failure = assertIs<QuicException.ConnectionLost.Timeout>(d.h3Failure, "$d")
                    assertEquals(TimeoutKind.Handshake, failure.kind)
                    assertTrue(t0.elapsedNow() < 20.seconds, "bounded by the handshake timeout: ${t0.elapsedNow()}")
                    assertEquals(1, relay.provisionalInitialsSent, "the provisional Initial went first")
                    assertTrue(relay.serverDatagramsForwarded > 0, "the server's ServerHello reached the client (and was discarded)")
                }
            }
        }

    /** The control: the same rig without the provisional Initial connects over HTTP/3. */
    @Test fun withoutTheProvisionalInitialTheRigConnectsOverHttp3() =
        h3Test {
            msquicLikeOrigin(msquicProvisionalScid = false) { port, relay ->
                testClient(Http3DiscoveryMode.Preferred, engine = {
                    quic = quicConfig { handshakeTimeout = 2.seconds }
                    http3 { hardDelay = Duration.INFINITE }
                }).use { c ->
                    val r = c.get("https://127.0.0.1:$port/")
                    assertEquals("h3", r.bodyAsText())
                    assertEquals(HttpProtocolVersion.HTTP_3_0, r.version)
                    assertEquals(0, relay.provisionalInitialsSent)
                }
            }
        }
}
