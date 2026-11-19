// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.api

import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.native.KslLoader
import io.kuicksilver.quic.CoreFixtures
import io.kuicksilver.quic.QuicClientConfig
import io.kuicksilver.quic.QuicException
import io.kuicksilver.quic.TestCerts
import io.kuicksilver.quic.ksl
import io.kuicksilver.tls.SpkiSha256
import io.kuicksilver.tls.TofuStore
import io.kuicksilver.tls.TrustConfig
import io.kuicksilver.tls.VerifyReason
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeout
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertTrue
import kotlin.test.fail
import kotlin.time.Duration.Companion.seconds

/**
 * `TrustConfig.Tofu` over QUIC through the connection runtime: the key of a first contact is stored before `connect` returns,
 * so a connection the application closes at once (and its endpoint with it) still leaves its pin, a later server with another
 * key under the same name fails with `PinMismatch`, and a store that fails fails the connection, as over TCP. The first runtime
 * committed in a coroutine of the endpoint's scope after `connect` had returned: closing the endpoint could cancel it.
 */
@OptIn(ExperimentalKuicksilverApi::class, kotlin.concurrent.atomics.ExperimentalAtomicApi::class)
class TofuRuntimeTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    /** A store whose `put` waits for [gate] once [entered] says it was called. */
    private class GatedStore : TofuStore {
        // written by the commit's coroutine, read by the test's thread: an immutable map behind an atomic reference
        private val pins = kotlin.concurrent.atomics.AtomicReference(emptyMap<String, SpkiSha256>())
        val m: Map<String, SpkiSha256> get() = pins.load()
        val entered = CompletableDeferred<Unit>()
        val gate = CompletableDeferred<Unit>()
        var failWith: Throwable? = null
        var hang = false

        override suspend fun get(name: String): SpkiSha256? = m[name]

        override suspend fun put(
            name: String,
            pin: SpkiSha256,
        ) {
            entered.complete(Unit)
            if (hang) kotlinx.coroutines.awaitCancellation()
            gate.await()
            failWith?.let { throw it }
            while (true) {
                val old = pins.load()
                if (pins.compareAndSet(old, old + (name to pin))) break
            }
        }
    }

    private fun clientConfig(store: TofuStore) = QuicClientConfig.Builder(CoreFixtures.client(trust = TrustConfig.Tofu(store))).build()

    private fun Throwable.chain(): Sequence<Throwable> = generateSequence(this) { it.cause }

    @Test fun negative_aConnectionClosedAtOncePinsItsKeyAndAnotherKeyIsRefused(): Unit =
        runBlocking {
            val store = GatedStore()
            val first = ApiPair.open(crypto = ksl)
            try {
                coroutineScope {
                    val accepted = async { first.server.accept() }
                    val connect = async { first.client.connect(first.server.localAddress, clientConfig(store)) }
                    withTimeout(10.seconds) { store.entered.await() }
                    // the loop task that asked the store has ended (its handshake event is processed): with the key not stored
                    // yet, the handshake must not be complete, so that connect cannot return and the application cannot close
                    val loop = first.client as io.kuicksilver.quic.runtime.EndpointLoop
                    val handshaken =
                        withContext(loop.dispatcher) {
                            loop.runtimes.values
                                .single()
                                .isHandshakeComplete
                        }
                    assertFalse(handshaken, "the handshake completed while the store still held the key")
                    assertFalse(connect.isCompleted, "connect returned before the key was stored")
                    store.gate.complete(Unit)
                    val c = withTimeout(10.seconds) { connect.await() }
                    // the application closes at once, the endpoint with it: the pin is already there
                    c.close()
                    first.client.closeAndJoin()
                    accepted.cancel()
                }
            } finally {
                first.close()
            }
            assertEquals(setOf("server.test"), store.m.keys, "the first contact left its pin")
            // another server under the same name, with another key
            val second =
                ApiPair.open(
                    crypto = ksl,
                    serverTls = CoreFixtures.server(chain = listOf(TestCerts.serverOtherKey), key = TestCerts.serverOtherKeyKey),
                )
            try {
                val e =
                    runCatching { withTimeout(10.seconds) { second.client.connect(second.server.localAddress, clientConfig(store)) } }
                        .exceptionOrNull() ?: fail("a server with another key was accepted")
                assertTrue(
                    e.chain().any { (it as? io.kuicksilver.tls.TlsException.Verify)?.reason is VerifyReason.PinMismatch } ||
                        e.chain().any { it.message?.contains("PinMismatch") == true },
                    "refused with PinMismatch: $e",
                )
            } finally {
                second.close()
            }
        }

    @Test fun negative_aStoreThatFailsFailsTheConnection(): Unit =
        runBlocking {
            val store = GatedStore().also { it.gate.complete(Unit) }
            val boom = IllegalStateException("store unavailable")
            store.failWith = boom
            val p = ApiPair.open(crypto = ksl)
            try {
                val e =
                    runCatching { withTimeout(10.seconds) { p.client.connect(p.server.localAddress, clientConfig(store)) } }
                        .exceptionOrNull()
                assertNotNull(e, "the connection did not fail with its store")
                assertTrue(e is QuicException.ConnectionLost && e.chain().any { it === boom }, "failed with the store's error: $e")
                assertTrue(store.m.isEmpty())
            } finally {
                p.close()
            }
        }

    /** A store that never answers holds the handshake for its timeout at most: the call is cancelled and connect fails. */
    @Test fun negative_aStoreThatNeverAnswersEndsAtTheHandshakeTimeout(): Unit =
        runBlocking {
            val store = GatedStore().also { it.hang = true }
            val p = ApiPair.open(crypto = ksl)
            try {
                val config =
                    QuicClientConfig
                        .Builder(CoreFixtures.client(trust = TrustConfig.Tofu(store)))
                        .apply { quic = io.kuicksilver.quic.quicConfig { handshakeTimeout = 1.seconds } }
                        .build()
                val e = runCatching { withTimeout(10.seconds) { p.client.connect(p.server.localAddress, config) } }.exceptionOrNull()
                assertTrue(store.entered.isCompleted, "the store was asked")
                val t = assertIs<QuicException.ConnectionLost.Timeout>(e, "failed at the handshake timeout: $e")
                assertEquals(io.kuicksilver.quic.TimeoutKind.Handshake, t.kind)
                assertTrue(store.m.isEmpty())
            } finally {
                p.close()
            }
        }
}
