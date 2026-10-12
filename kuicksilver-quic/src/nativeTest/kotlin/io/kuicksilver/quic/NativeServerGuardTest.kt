// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic

import io.ktor.network.sockets.InetSocketAddress
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.tls.KslUdpSocket
import kotlinx.coroutines.runBlocking
import kotlin.experimental.ExperimentalNativeApi
import kotlin.native.OsFamily
import kotlin.native.Platform
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

/**
 * A Native server needs the accelerated transport (ADR-0006): Linux and Apple have it and `bind` starts the server; where it
 * is absent (Windows) the server is still refused, because the portable Native io cannot serve.
 */
@OptIn(ExperimentalKuicksilverApi::class, io.kuicksilver.annotations.InternalKuicksilverApi::class, ExperimentalNativeApi::class)
class NativeServerGuardTest {
    private fun serverConfig() =
        QuicEndpointConfig
            .Builder()
            .apply {
                server =
                    QuicServerConfig.Builder(CoreFixtures.server()).build()
            }.build()

    @Test fun nativeServerBindsWhereTheAcceleratedIoExists() =
        runBlocking {
            val accelerated = Platform.osFamily != OsFamily.WINDOWS
            assertEquals(accelerated, KslUdpSocket.supported, "ksl_udp on ${Platform.osFamily}")
            if (!accelerated) return@runBlocking
            val server = QuicEndpoint.bind(InetSocketAddress("127.0.0.1", 0), serverConfig())
            server.close()
        }

    @Test fun nativeServerWithPortableIoRejected() =
        runBlocking {
            if (KslUdpSocket.supported) return@runBlocking // Linux, Apple: nativeServerBindsWhereTheAcceleratedIoExists
            assertFailsWith<UnsupportedOperationException> { QuicEndpoint.bind(InetSocketAddress("127.0.0.1", 0), serverConfig()) }
            Unit
        }
}
