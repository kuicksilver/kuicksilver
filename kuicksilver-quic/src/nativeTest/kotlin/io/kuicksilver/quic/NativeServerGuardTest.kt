// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic

import io.ktor.network.sockets.InetSocketAddress
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.tls.KslUdpSocket
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertFailsWith

/** Where the accelerated transport is absent (Apple, Windows) a Native server is still refused: the portable Native io cannot serve (ADR-0006). */
@OptIn(ExperimentalKuicksilverApi::class, io.kuicksilver.annotations.InternalKuicksilverApi::class)
class NativeServerGuardTest {
    @Test fun nativeServerWithPortableIoRejected() =
        runBlocking {
            if (KslUdpSocket.supported) return@runBlocking // Linux: NativeServerLoopbackTest
            assertFailsWith<UnsupportedOperationException> {
                QuicEndpoint.bind(
                    InetSocketAddress("127.0.0.1", 0),
                    QuicEndpointConfig
                        .Builder()
                        .apply {
                            server =
                                QuicServerConfig.Builder(CoreFixtures.server()).build()
                        }.build(),
                )
            }
            Unit
        }
}
