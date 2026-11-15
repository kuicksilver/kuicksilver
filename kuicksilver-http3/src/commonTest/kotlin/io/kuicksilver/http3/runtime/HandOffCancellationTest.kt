// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)

package io.kuicksilver.http3.runtime

import io.kuicksilver.http3.Capsule
import io.kuicksilver.http3.CapsuleConfig
import io.kuicksilver.http3.H3Pair
import io.kuicksilver.http3.http3Settings
import io.kuicksilver.http3.useScoped
import io.kuicksilver.native.KslLoader
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.Runnable
import kotlinx.coroutines.async
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import kotlinx.coroutines.withTimeout
import kotlinx.coroutines.withTimeoutOrNull
import kotlin.concurrent.atomics.AtomicLong
import kotlin.concurrent.atomics.ExperimentalAtomicApi
import kotlin.concurrent.atomics.incrementAndFetch
import kotlin.coroutines.CoroutineContext
import kotlin.random.Random
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.seconds

private const val TYPE = 0x2843L

/** A dispatcher whose tasks wait in [tasks] until the test runs them: a receiver resumed here can be cancelled in between. */
internal class StepDispatcher : CoroutineDispatcher() {
    val tasks = Channel<Runnable>(Channel.UNLIMITED)

    override fun dispatch(
        context: CoroutineContext,
        block: Runnable,
    ) {
        tasks.trySend(block)
    }
}

/**
 * A receiver of a coroutine channel that is cancelled after an element was handed to it but before it resumed loses that
 * element unless the hand-off guards it (kotlinx.coroutines' prompt cancellation). An application that polls under a
 * timeout, or a `select`, is such a receiver: nothing it was given may be lost.
 */
class HandOffCancellationTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    private val connectOn = http3Settings { enableConnectProtocol = true }
    private val known = CapsuleConfig(knownTypes = setOf(TYPE))

    /** A capsule handed to a collector cancelled while being resumed goes to the next collector, in order. */
    @Test fun negative_aCapsuleCollectorCancelledWhileBeingResumedLosesNoCapsule() =
        h3Test {
            H3Pair.open(serverSettings = connectOn).useScoped { p ->
                val server =
                    async {
                        p.server
                            .acceptRequest()
                            .acceptConnect()
                            .useCapsuleProtocol(known)
                    }
                val c = p.client.connect(connectReq(), "test-capsules").useCapsuleProtocol(known)
                val s = withTimeout(5.seconds) { server.await() }
                val steps = StepDispatcher()
                val collector = launch(steps, start = CoroutineStart.UNDISPATCHED) { s.capsules.first() }
                c.send(Capsule(TYPE, byteArrayOf(1)))
                c.send(Capsule(TYPE, byteArrayOf(2)))
                val resumed = withTimeout(5.seconds) { steps.tasks.receive() } // the first capsule was handed over
                collector.cancel()
                resumed.run()
                while (!collector.isCompleted) steps.tasks.receive().run()
                assertTrue(collector.isCancelled)
                assertEquals(1, withTimeoutOrNull(5.seconds) { s.capsules.first() }?.value?.single()?.toInt(), "capsule 1 was lost")
                assertEquals(2, withTimeout(5.seconds) { s.capsules.first() }.value.single().toInt())
            }
        }

    /**
     * Numbered capsules, each taken by a new collector that an adversarial dispatcher cancels before about one resumption
     * in three: they arrive all, once each, in order.
     */
    @Test fun negative_capsulesSurviveRandomlyCancelledCollectors() =
        h3Test {
            val d = CancellingDispatcher(Random.nextLong())
            H3Pair.open(serverSettings = connectOn).useScoped { p ->
                val server =
                    async {
                        p.server
                            .acceptRequest()
                            .acceptConnect()
                            .useCapsuleProtocol(known)
                    }
                val c = p.client.connect(connectReq(), "test-capsules").useCapsuleProtocol(known)
                val s = withTimeout(5.seconds) { server.await() }
                val n = 200
                // each capsule goes once the one before it was taken: the collector is mostly waiting when one arrives
                val taken = MutableStateFlow(0)
                launch {
                    for (i in 0 until n) {
                        taken.first { it >= i }
                        c.send(Capsule(TYPE, i.toString().encodeToByteArray()))
                    }
                    c.close()
                }
                var next = 0
                withTimeoutOrNull(15.seconds) {
                    while (next < n) {
                        val got = underCancellation(d) { s.capsules.first() } ?: continue
                        assertEquals(next, got.value.decodeToString().toInt(), "$d: capsule $next was lost")
                        next++
                        taken.value = next
                    }
                }
                assertEquals(n, next, "$d: capsule $next was lost (${d.cancelled} cancelled)")
                assertTrue(d.cancelled > 0, "$d cancelled no collector")
            }
        }
}

/**
 * Runs tasks on [Dispatchers.Default], but first cancels the coroutine a task resumes for about one task in [every]
 * (decided from [seed], printed with the dispatcher): a receiver resumed with an element is cancelled before it runs.
 */
@OptIn(ExperimentalAtomicApi::class)
internal class CancellingDispatcher(
    private val seed: Long,
    private val every: Int = 3,
) : CoroutineDispatcher() {
    private val tasks = AtomicLong(0)
    private val cancels = AtomicLong(0)
    val cancelled: Long get() = cancels.load()

    override fun dispatch(
        context: CoroutineContext,
        block: Runnable,
    ) {
        if (Random(seed + tasks.incrementAndFetch()).nextInt(every) == 0) {
            cancels.incrementAndFetch()
            context[Job]?.cancel()
        }
        Dispatchers.Default.dispatch(context, block)
    }

    override fun toString(): String = "CancellingDispatcher(seed $seed)"
}

/** [block] in a child on [d], started undispatched; null when [d] cancelled it. */
internal suspend fun <T> CoroutineScope.underCancellation(
    d: CancellingDispatcher,
    block: suspend () -> T,
): T? {
    val job = async(d, start = CoroutineStart.UNDISPATCHED) { block() }
    return try {
        job.await()
    } catch (e: CancellationException) {
        currentCoroutineContext().ensureActive()
        null
    }
}
