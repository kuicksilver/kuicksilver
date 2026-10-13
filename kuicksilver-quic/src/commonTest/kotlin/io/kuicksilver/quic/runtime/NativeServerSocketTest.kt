// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.runtime

import io.ktor.network.sockets.InetSocketAddress
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.native.KslLoader
import io.kuicksilver.quic.CoreFixtures
import io.kuicksilver.quic.KslDatagramIo
import io.kuicksilver.quic.KuicksilverLogger
import io.kuicksilver.quic.NullCryptoProvider
import io.kuicksilver.quic.QuicEndpoint
import io.kuicksilver.quic.QuicServerConfig
import io.kuicksilver.quic.quicEndpointConfig
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

/** A QUIC server without the accelerated socket: the JVM serves on the portable one, Kotlin/Native refuses. */
@OptIn(ExperimentalKuicksilverApi::class)
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
                        crypto = NullCryptoProvider
                        logger = KuicksilverLogger.None
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
}
