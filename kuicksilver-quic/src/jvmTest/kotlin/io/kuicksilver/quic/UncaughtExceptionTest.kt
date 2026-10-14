// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic

import io.kuicksilver.annotations.DelicateKuicksilverApi
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.native.KslLoader
import io.kuicksilver.quic.api.ApiPair
import io.kuicksilver.quic.runtime.EndpointLoop
import io.kuicksilver.tls.CertificateVerifier
import io.kuicksilver.tls.KslQuicCrypto
import io.kuicksilver.tls.TrustConfig
import io.kuicksilver.tls.VerifyResult
import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import java.util.Collections
import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.seconds

/** Nothing the runtime launches may end in the thread's uncaught-exception handler (on Android that kills the process). */
@OptIn(ExperimentalKuicksilverApi::class, DelicateKuicksilverApi::class, kotlin.concurrent.atomics.ExperimentalAtomicApi::class)
class UncaughtExceptionTest {
    private val uncaught = Collections.synchronizedList(ArrayList<Throwable>())
    private var previous: Thread.UncaughtExceptionHandler? = null

    @BeforeTest fun install() {
        KslLoader.ensureLoaded()
        previous = Thread.getDefaultUncaughtExceptionHandler()
        Thread.setDefaultUncaughtExceptionHandler { _, e ->
            uncaught +=
                e
        }
    }

    @AfterTest fun restore() {
        Thread.setDefaultUncaughtExceptionHandler(previous)
    }

    private suspend fun connectWith(verifier: CertificateVerifier) =
        ApiPair.open(crypto = KslQuicCrypto).use { p ->
            val cfg =
                QuicClientConfig
                    .Builder(CoreFixtures.client(trust = TrustConfig.Custom(verifier)))
                    .apply {
                        quic =
                            quicConfig { handshakeTimeout = 300.milliseconds }
                    }.build()
            assertFailsWith<QuicException.ConnectionLost> { withTimeout(10.seconds) { p.client.connect(p.server.localAddress, cfg) } }
            delay(1_500) // a late verifier finishes after the connection is gone
            assertEquals(0L, (p.client as EndpointLoop).uncaughtFailures.load(), "the loop's last-resort handler saw nothing either")
        }

    @Test fun throwingVerifierFailsTheConnectionOnly() =
        runBlocking {
            connectWith { _, _, _ -> throw IllegalStateException("verifier bug") }
            assertTrue(uncaught.isEmpty(), "uncaught: $uncaught")
        }

    @Test fun aVerifierThrowingCancellationRejectsThePeerAtOnce() =
        runBlocking {
            // not the verifying coroutine's cancellation: the peer is rejected with a TLS alert, not left to the handshake timeout
            ApiPair.open(crypto = KslQuicCrypto).use { p ->
                val cfg =
                    QuicClientConfig
                        .Builder(
                            CoreFixtures.client(
                                trust =
                                    TrustConfig.Custom { _, _, _ ->
                                        throw kotlinx.coroutines.CancellationException("verifier bug")
                                    },
                            ),
                        ).apply { quic = quicConfig { handshakeTimeout = 5.seconds } }
                        .build()
                val lost =
                    assertFailsWith<QuicException.ConnectionLost> {
                        withTimeout(
                            10.seconds,
                        ) { p.client.connect(p.server.localAddress, cfg) }
                    }
                assertTrue(lost !is QuicException.ConnectionLost.Timeout, "rejected at once, not timed out: $lost")
            }
            assertTrue(uncaught.isEmpty(), "uncaught: $uncaught")
        }

    @Test fun lateVerifierAfterTheHandshakeTimeout() =
        runBlocking {
            connectWith { chain, _, _ ->
                delay(1_000)
                VerifyResult.Accepted(chain)
            }
            assertTrue(uncaught.isEmpty(), "uncaught: $uncaught")
        }
}
