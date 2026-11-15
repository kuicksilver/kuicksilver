// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)

package io.kuicksilver.http3.runtime

import io.kuicksilver.http3.Capsule
import io.kuicksilver.http3.CapsuleConfig
import io.kuicksilver.http3.H3Pair
import io.kuicksilver.http3.http3Settings
import io.kuicksilver.http3.readAllBytes
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
import kotlinx.coroutines.job
import kotlinx.coroutines.launch
import kotlinx.coroutines.withTimeout
import kotlinx.coroutines.withTimeoutOrNull
import kotlinx.coroutines.yield
import kotlin.concurrent.atomics.AtomicLong
import kotlin.concurrent.atomics.AtomicReference
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

    /**
     * A collector cancelled while it handles capsule 1 (its own job cancelled, a sibling failing) leaves capsule 2 queued
     * for the next collector: the cancellation is seen before the next capsule is taken, not after.
     */
    @Test fun negative_aCapsuleCollectorCancelledWhileHandlingOneLosesNoCapsule() =
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
                val s = withTimeout(5.seconds) { server.await() } as CapsuleStreamImpl
                c.send(Capsule(TYPE, byteArrayOf(1)))
                c.send(Capsule(TYPE, byteArrayOf(2)))
                while (s.heldForTest < 2) yield() // both received, neither collected (bounded by the test's timeout)
                val seen = ArrayList<Int>()
                launch {
                    s.capsules.collect { cap ->
                        seen += cap.value.single().toInt()
                        if (seen.size == 1) currentCoroutineContext().job.cancel()
                    }
                }.join()
                assertEquals(listOf(1), seen)
                assertEquals(2, withTimeoutOrNull(5.seconds) { s.capsules.first() }?.value?.single()?.toInt(), "capsule 2 was lost")
            }
        }

    /**
     * Numbered capsules collected by collectors that another thread cancels at arbitrary moments (waiting, running, handling
     * a capsule): every capsule handed to a collector's block arrives, once, in order.
     */
    @Test fun negative_capsulesSurviveCollectorsCancelledAtAnyTime() =
        h3Test {
            val k = Killer(Random.nextLong())
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
                val n = 300
                val taken = MutableStateFlow(0)
                launch {
                    for (i in 0 until n) {
                        // a few capsules ahead of the collector: some wait in the queue, some arrive at a waiting collector
                        taken.first { it >= i - 3 }
                        c.send(Capsule(TYPE, i.toString().encodeToByteArray()))
                    }
                    c.close()
                }
                val got = ArrayList<Int>()
                // bounded: with a capsule lost the run would wait for it, and the assertion below names the seed
                withTimeoutOrNull(15.seconds) {
                    k.run(this) {
                        s.capsules.collect {
                            got += it.value.decodeToString().toInt()
                            taken.value = got.size
                        }
                    }
                }
                assertEquals((0 until n).toList(), got, "$k")
                assertTrue(k.kills > 0, "$k cancelled no collector")
            }
        }

    /** A request handed to an acceptRequest caller cancelled while being resumed goes to the next caller, and is answered. */
    @Test fun negative_anAcceptRequestCancelledWhileBeingResumedLosesNoRequest() =
        h3Test {
            H3Pair.open().useScoped { p ->
                val steps = StepDispatcher()
                val acceptor = launch(steps, start = CoroutineStart.UNDISPATCHED) { p.server.acceptRequest() }
                val response = async { p.client.request(get("/lost")) }
                val resumed = withTimeout(5.seconds) { steps.tasks.receive() }
                acceptor.cancel()
                resumed.run()
                while (!acceptor.isCompleted) steps.tasks.receive().run()
                assertTrue(acceptor.isCancelled)
                val again = withTimeoutOrNull(5.seconds) { p.server.acceptRequest() }
                assertEquals("/lost", again?.path, "the request was lost")
                again!!.respond(204).finish()
                assertEquals(204, withTimeout(5.seconds) { response.await() }.status)
            }
        }

    /** Requests taken by acceptRequest callers that an adversarial dispatcher cancels are all answered. */
    @Test fun negative_requestsSurviveRandomlyCancelledAcceptors() =
        h3Test {
            val d = CancellingDispatcher(Random.nextLong())
            H3Pair.open().useScoped { p ->
                val n = 60
                // each request goes once the one before it was taken: the acceptor is mostly waiting when one arrives
                val taken = MutableStateFlow(0)
                val responses =
                    (0 until n).map { i ->
                        async {
                            taken.first { it >= i }
                            p.client.request(get("/$i")).also { it.body.readAllBytes() }
                        }
                    }
                var answered = 0
                // bounded: with a request lost the loop would wait for it forever
                withTimeoutOrNull(15.seconds) {
                    while (answered < n) {
                        val r = underCancellation(d) { p.server.acceptRequest() } ?: continue
                        launch { r.respond(204).finish() }
                        answered++
                        taken.value = answered
                    }
                }
                assertEquals(n, answered, "$d: requests were lost (${d.cancelled} cancelled)")
                assertTrue(d.cancelled > 0, "$d cancelled no acceptor")
                responses.forEachIndexed { i, r -> assertEquals(204, withTimeout(10.seconds) { r.await() }.status, "/$i") }
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

/**
 * Runs a consumer again and again, each time in a new child on [Dispatchers.Default], while another coroutine there
 * cancels the running child at random moments (decided from [seed]): waiting, running, or between two elements.
 */
@OptIn(ExperimentalAtomicApi::class)
internal class Killer(
    private val seed: Long,
) {
    private val current = AtomicReference<Job?>(null)
    private val killCount = AtomicLong(0)
    val kills: Long get() = killCount.load()

    /** Runs [consume] until one run ends without being cancelled. */
    suspend fun run(
        scope: CoroutineScope,
        consume: suspend () -> Unit,
    ) {
        val rnd = Random(seed)
        val killer =
            scope.launch(Dispatchers.Default) {
                while (true) {
                    repeat(rnd.nextInt(200)) { yield() }
                    current.load()?.let {
                        it.cancel()
                        killCount.incrementAndFetch()
                    }
                }
            }
        try {
            while (true) {
                val job = scope.launch(Dispatchers.Default, start = CoroutineStart.LAZY) { consume() }
                current.store(job)
                job.start()
                job.join()
                current.store(null)
                if (!job.isCancelled) break
            }
        } finally {
            killer.cancel()
        }
    }

    override fun toString(): String = "Killer(seed $seed)"
}
