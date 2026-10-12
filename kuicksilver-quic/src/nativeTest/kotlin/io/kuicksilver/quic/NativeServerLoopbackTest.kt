// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(ExperimentalKuicksilverApi::class, io.kuicksilver.annotations.InternalKuicksilverApi::class)

package io.kuicksilver.quic

import io.ktor.network.sockets.InetSocketAddress
import io.ktor.utils.io.writeFully
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.quic.api.readExactly
import io.kuicksilver.tls.KslQuicCrypto
import kotlinx.coroutines.async
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import kotlin.experimental.ExperimentalNativeApi
import kotlin.native.OsFamily
import kotlin.native.Platform
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.time.Duration.Companion.seconds

/** A QUIC server on Kotlin/Native over the accelerated transport (Linux, Apple); Windows has none and the guard test covers the refusal. */
@OptIn(ExperimentalNativeApi::class)
class NativeServerLoopbackTest {
    @Test fun nativeServerServes10MiB() =
        runBlocking {
            if (Platform.osFamily == OsFamily.WINDOWS) return@runBlocking // no ksl_udp: NativeServerGuardTest
            val lo = InetSocketAddress("127.0.0.1", 0)
            val server =
                QuicEndpoint.bind(
                    lo,
                    QuicEndpointConfig
                        .Builder()
                        .apply {
                            this.server =
                                QuicServerConfig.Builder(CoreFixtures.server()).build()
                            ; crypto = KslQuicCrypto
                        }.build(),
                )
            val client = QuicEndpoint.bind(lo, QuicEndpointConfig.Builder().apply { crypto = KslQuicCrypto }.build())
            try {
                withTimeout(120.seconds) {
                    val accepted = async { server.accept() }
                    val c = client.connect(server.localAddress, QuicClientConfig.Builder(CoreFixtures.client()).build())
                    val s = accepted.await()
                    val data = ByteArray(10 shl 20) { (it * 5).toByte() }
                    val echo =
                        launch {
                            val st = s.acceptStream()
                            val got = st.input.readExactly(data.size)
                            st.output.writeFully(got, 0, got.size)
                            st.output.flushAndClose()
                        }
                    val st = c.openBidi()
                    launch {
                        st.output.writeFully(data, 0, data.size)
                        st.output.flushAndClose()
                    }
                    assertContentEquals(data, st.input.readExactly(data.size))
                    echo.join()
                    assertEquals(EcnState.Capable, s.stats.ecnState)
                    c.close()
                    s.close()
                }
            } finally {
                client.close()
                server.close()
            }
        }
}
