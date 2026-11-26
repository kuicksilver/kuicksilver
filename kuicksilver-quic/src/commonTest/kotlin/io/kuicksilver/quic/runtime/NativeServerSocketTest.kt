// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.runtime

import io.ktor.network.sockets.InetSocketAddress
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.native.KslLoader
import io.kuicksilver.quic.CoreFixtures
import io.kuicksilver.quic.DatagramIo
import io.kuicksilver.quic.KslDatagramIo
import io.kuicksilver.quic.KuicksilverLogger
import io.kuicksilver.quic.NullCryptoProvider
import io.kuicksilver.quic.QuicEndpoint
import io.kuicksilver.quic.QuicException
import io.kuicksilver.quic.QuicServerConfig
import io.kuicksilver.quic.quicEndpointConfig
import io.kuicksilver.tls.KslUdpSocket
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

/** A QUIC server without the accelerated socket: the JVM serves on the portable one, Kotlin/Native refuses. */
@OptIn(ExperimentalKuicksilverApi::class, io.kuicksilver.annotations.InternalKuicksilverApi::class)
class NativeServerSocketTest {
    @Test fun serverWithoutTheAcceleratedSocket(): Unit =
        runBlocking {
            KslLoader.ensureLoaded()
            val real = KslDatagramIo.unsupportedReason
            KslDatagramIo.unsupportedReason = { "probe refused" }
            try {
                val config =
                    quicEndpointConfig {
                        server = QuicServerConfig.Builder(CoreFixtures.server()).build()
                        runtime { crypto = NullCryptoProvider }
                        observability { logger = KuicksilverLogger.None }
                    }
                val local = InetSocketAddress("127.0.0.1", 0)
                if (portableServerSupported) {
                    QuicEndpoint.bind(local, config).closeAndJoin()
                } else {
                    val e = assertFailsWith<UnsupportedOperationException> { QuicEndpoint.bind(local, config) }
                    // every platform with a Kotlin/Native QUIC server, Windows included (ksl_udp over Winsock)
                    assertEquals(
                        "a QUIC server on Kotlin/Native needs the accelerated ksl socket (Linux, Apple, Windows), " +
                            "which is unavailable here",
                        e.message,
                    )
                }
            } finally {
                KslDatagramIo.unsupportedReason = real
            }
        }

    private val serverConfig
        get() =
            quicEndpointConfig {
                server = QuicServerConfig.Builder(CoreFixtures.server()).build()
                runtime { crypto = NullCryptoProvider }
                observability { logger = KuicksilverLogger.None }
            }

    /**
     * A port in use is the bind's own failure, an IOException as on the JVM (a caller trying another port can tell),
     * not UnsupportedOperationException nor DontFragmentUnavailable.
     */
    @Test fun negative_aServerOnAPortInUseFailsWithTheRefusedBind(): Unit =
        runBlocking {
            KslLoader.ensureLoaded()
            val held = DatagramIo.open(InetSocketAddress("127.0.0.1", 0))
            try {
                val e =
                    runCatching {
                        QuicEndpoint.bind(InetSocketAddress("127.0.0.1", held.localAddress.port), serverConfig).closeAndJoin()
                    }.exceptionOrNull()
                assertTrue(e is kotlinx.io.IOException && e !is QuicException, "the refused bind itself, got $e")
            } finally {
                held.close()
            }
        }

    /**
     * Kotlin/Native: the accelerated socket opens, but the system gives it no DF (a seccomp filter refusing
     * IP_MTU_DISCOVER): no QUIC without DF (RFC 9000 section 14), said as DontFragmentUnavailable, not as a missing
     * socket.
     */
    @Test fun negative_aNativeServerWhoseSocketGotNoDfSaysSo(): Unit =
        runBlocking {
            if (portableServerSupported) return@runBlocking // the JVM decides DF on its portable socket (NioDatagramIoTest)
            KslLoader.ensureLoaded()
            val real = KslDatagramIo.socketOpener
            KslDatagramIo.socketOpener = { a, f, failed -> KslUdpSocket.openOrNull(a, f and KslUdpSocket.DF.inv(), failed) }
            try {
                val e =
                    assertFailsWith<QuicException.DontFragmentUnavailable> {
                        QuicEndpoint.bind(
                            InetSocketAddress("127.0.0.1", 0),
                            serverConfig,
                        )
                    }
                assertEquals(null, e.family)
            } finally {
                KslDatagramIo.socketOpener = real
            }
        }

    /** Kotlin/Native: a bind address that does not resolve is the address's error, an IOException, as a port in use. */
    @Test fun negative_aNativeServerOnAnUnresolvableAddressFailsWithTheAddressError(): Unit =
        runBlocking {
            if (portableServerSupported) return@runBlocking // the JVM's own bind reports it (UnresolvedAddressException)
            KslLoader.ensureLoaded()
            val e =
                runCatching { QuicEndpoint.bind(InetSocketAddress("no-such-host.invalid", 0), serverConfig).closeAndJoin() }
                    .exceptionOrNull()
            assertTrue(e is kotlinx.io.IOException && e !is QuicException, "the address error, got $e")
        }
}
