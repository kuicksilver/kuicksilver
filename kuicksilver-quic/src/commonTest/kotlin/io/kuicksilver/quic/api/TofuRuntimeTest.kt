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
import kotlinx.coroutines.withTimeout
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
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
@OptIn(ExperimentalKuicksilverApi::class)
class TofuRuntimeTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    /** A store whose `put` waits for [gate] once [entered] says it was called. */
    private class GatedStore : TofuStore {
        val m = HashMap<String, SpkiSha256>()
        val entered = CompletableDeferred<Unit>()
        val gate = CompletableDeferred<Unit>()
        var failWith: Throwable? = null

        override suspend fun get(name: String): SpkiSha256? = m[name]

        override suspend fun put(
            name: String,
            pin: SpkiSha256,
        ) {
            entered.complete(Unit)
            gate.await()
            failWith?.let { throw it }
            m[name] = pin
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
                    if (connect.isCompleted) {
                        // connect returned before the key was stored: the application closes at once, the endpoint with it
                        connect.await().close()
                        first.client.closeAndJoin()
                        store.gate.complete(Unit)
                    } else {
                        store.gate.complete(Unit)
                        val c = withTimeout(10.seconds) { connect.await() }
                        c.close()
                        first.client.closeAndJoin()
                    }
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
}
