// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(ExperimentalForeignApi::class)

package io.kuicksilver.tls

import io.kuicksilver.native.KslLoader
import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeout
import kotlinx.coroutines.yield
import platform.CoreFoundation.CFErrorRef
import platform.darwin.dispatch_async
import platform.darwin.dispatch_queue_t
import kotlin.concurrent.atomics.AtomicInt
import kotlin.concurrent.atomics.AtomicReference
import kotlin.concurrent.atomics.ExperimentalAtomicApi
import kotlin.concurrent.atomics.incrementAndFetch
import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.seconds

/**
 * SecTrust off the caller's thread: an evaluation stuck on the network (OCSP, AIA) holds no Kotlin thread, and the Platform base
 * combined with a root the device trusts beyond the system store (a configuration profile, MDM) and with pins.
 */
@OptIn(ExperimentalAtomicApi::class)
class AppleTrustAsyncTest {
    private val defaultEvaluator = PlatformVerifier.evaluator

    @BeforeTest fun load() = KslLoader.ensureLoaded()

    @AfterTest fun restore() {
        PlatformVerifier.evaluator = defaultEvaluator
        PlatformVerifier.extraAnchorsForTest = emptyList()
        PlatformVerifier.verifyDateForTest = null
    }

    /** The 800-day leaf under a root "installed" beside the system store, evaluated inside its validity. */
    private val installed = listOf(Certificate(AppleTrustCerts.server))

    private fun installRoot() {
        PlatformVerifier.extraAnchorsForTest = listOf(AppleTrustCerts.root)
        PlatformVerifier.verifyDateForTest = AppleTrustCerts.verifyAt
    }

    /**
     * False where SecTrust cannot evaluate at all: a test binary that `simctl spawn --standalone` starts on the iOS simulator
     * has no app context, and SecTrust answers OSStatus -26276 (not in the SDK headers) for every evaluation, accepting nothing. The acceptance
     * tests then say so and pass; they run on macOS and need an app on a device for iOS.
     */
    private suspend fun secTrustEvaluates(): Boolean {
        var code = 0L
        PlatformVerifier.evaluator = { t, q, h, done ->
            defaultEvaluator(t, q, h) { ok, err ->
                if (!ok && err != null) code = platform.CoreFoundation.CFErrorGetCode(err)
                done(ok, err)
            }
        }
        try {
            PlatformVerifier.verify(installed, HostName.normalize("server.test"), TlsRole.Client)
        } finally {
            PlatformVerifier.evaluator = defaultEvaluator
        }
        if (code ==
            SEC_TRUST_UNAVAILABLE
        ) {
            println("AppleTrustAsyncTest: SecTrust answers OSStatus -26276 here (standalone simulator process); acceptance not checked")
        }
        return code != SEC_TRUST_UNAVAILABLE
    }

    private val chain = listOf(Certificate(TestCerts.server), Certificate(TestCerts.testCa))

    private class Stalled(
        val trust: platform.Security.SecTrustRef,
        val queue: dispatch_queue_t,
        val done: (Boolean, CFErrorRef?) -> Unit,
    )

    @Test fun stalledEvaluationsHoldNoThreadAndDoNotStallOthers() =
        runBlocking<Unit> {
            // "slow.test" never answers until released, like an OCSP responder that does not reply; everything else is real
            // the evaluator runs on GCD worker threads concurrently: the list is replaced atomically
            val stalled = AtomicReference<List<Stalled>>(emptyList())
            val started = AtomicInt(0)
            PlatformVerifier.evaluator = { trust, q, host, done ->
                if (host == "slow.test") {
                    val s = Stalled(trust, q, done)
                    while (true) {
                        val old = stalled.load()
                        if (stalled.compareAndSet(old, old + s)) break
                    }
                    started.incrementAndFetch()
                } else {
                    defaultEvaluator(trust, q, host, done)
                }
            }
            // far more than Dispatchers.Default has threads: a blocking evaluation would occupy every one of them
            val slow =
                List(64) {
                    async(Dispatchers.Default) { PlatformVerifier.verify(chain, HostName.normalize("slow.test"), TlsRole.Client) }
                }
            withTimeout(20.seconds) { while (started.load() < 64) yield() }
            withTimeout(20.seconds) {
                // another handshake's verification and plain Default work still complete
                val other =
                    withContext(Dispatchers.Default) { PlatformVerifier.verify(chain, HostName.normalize("server.test"), TlsRole.Client) }
                assertIs<VerifyResult.Rejected>(other)
                assertEquals(42, withContext(Dispatchers.Default) { 42 })
            }
            assertTrue(slow.none { it.isCompleted }, "the stalled evaluations are still waiting")
            // the responder answers: each completes on its queue
            val release = stalled.load()
            for (s in release) dispatch_async(s.queue) { defaultEvaluator(s.trust, s.queue, "slow.test", s.done) }
            withTimeout(30.seconds) { slow.awaitAll() }.forEach { assertIs<VerifyResult.Rejected>(it) }
        }

    @Test fun platformTrustsARootInstalledBesideTheSystemStore() =
        runBlocking<Unit> {
            installRoot()
            if (!secTrustEvaluates()) return@runBlocking
            // the leaf alone: SecTrust builds the chain up to the installed root
            val r = PlatformVerifier.verify(installed, HostName.normalize("server.test"), TlsRole.Client)
            val ok = assertIs<VerifyResult.Accepted>(r, "rejected: ${(r as? VerifyResult.Rejected)?.reason}")
            assertEquals(
                Certificate(AppleTrustCerts.root).spkiSha256,
                ok.validatedChain.last().spkiSha256,
                "the chain ends at the installed root",
            )
            // the name still counts
            val wrong = PlatformVerifier.verify(installed, HostName.normalize("other.test"), TlsRole.Client)
            assertIs<VerifyReason.HostnameMismatch>(assertIs<VerifyResult.Rejected>(wrong).reason)
        }

    private fun pinned(
        pin: SpkiSha256,
        scope: PinScope,
    ) = Verification(
        tlsConfig(TlsRole.Client) {
            serverName = "server.test"
            trust = TrustConfig.Pinned(setOf(pin), scope, base = TrustConfig.Platform)
        },
    )

    @Test fun pinsOnTopOfThePlatformBase() =
        runBlocking<Unit> {
            installRoot()
            if (!secTrustEvaluates()) return@runBlocking
            val host = HostName.normalize("server.test")
            val rootPin = Certificate(AppleTrustCerts.root).spkiSha256
            val leafPin = Certificate(AppleTrustCerts.server).spkiSha256
            assertIs<VerifyResult.Accepted>(pinned(leafPin, PinScope.Leaf).verify(installed, host))
            // the root pin needs the chain scope: it matches the validated chain SecTrust built, never a presented certificate
            assertIs<VerifyResult.Accepted>(pinned(rootPin, PinScope.AnyInValidatedChain).verify(installed, host))
            assertIs<VerifyReason.PinMismatch>(
                assertIs<VerifyResult.Rejected>(pinned(rootPin, PinScope.Leaf).verify(installed, host)).reason,
            )
        }

    @Test fun negative_pinsNeverReplaceThePlatformBase() =
        runBlocking<Unit> {
            // the pin matches, but the device does not trust the root: AND, never OR (ADR-0011)
            PlatformVerifier.verifyDateForTest = AppleTrustCerts.verifyAt
            val r =
                pinned(
                    Certificate(AppleTrustCerts.server).spkiSha256,
                    PinScope.Leaf,
                ).verify(installed, HostName.normalize("server.test"))
            assertIs<VerifyReason.UnknownIssuer>(assertIs<VerifyResult.Rejected>(r).reason)
        }
}

/** What SecTrust answers in a standalone simulator process (undocumented OSStatus, observed on the iOS 27 simulator). */
private const val SEC_TRUST_UNAVAILABLE = -26276L
