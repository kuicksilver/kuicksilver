// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)

package io.kuicksilver.http3.webtransport

import io.ktor.utils.io.writeFully
import io.kuicksilver.http3.H3Pair
import io.kuicksilver.http3.readAllBytes
import io.kuicksilver.http3.runtime.CancellingDispatcher
import io.kuicksilver.http3.runtime.StepDispatcher
import io.kuicksilver.http3.runtime.h3Test
import io.kuicksilver.http3.runtime.underCancellation
import io.kuicksilver.http3.useScoped
import io.kuicksilver.native.KslLoader
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import kotlinx.coroutines.withTimeout
import kotlinx.coroutines.withTimeoutOrNull
import kotlin.random.Random
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.seconds

/**
 * A peer's stream handed to an acceptBidi/acceptUni caller that is cancelled before it returns (a timeout, a select) stays
 * the application's to accept: it is neither lost nor left open and unread, holding the peer and its stream credit.
 */
class WtAcceptCancellationTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    /** Cancelled while being resumed with the stream (the channel's receive). */
    @Test fun negative_anAcceptorCancelledWhileBeingResumedLosesNoStream() =
        h3Test {
            H3Pair.open(clientSettings = wtOn, serverSettings = wtOn).useScoped { p ->
                val (client, server) = sessions(p)
                val steps = StepDispatcher()
                val acceptor = launch(steps, start = CoroutineStart.UNDISPATCHED) { server.acceptBidi() }
                val st = client.openBidi()
                st.output.writeFully("one".encodeToByteArray())
                st.output.flushAndClose()
                val resumed = withTimeout(5.seconds) { steps.tasks.receive() }
                acceptor.cancel()
                resumed.run()
                while (!acceptor.isCompleted) steps.tasks.receive().run()
                assertTrue(acceptor.isCancelled)
                val again = withTimeoutOrNull(5.seconds) { server.acceptBidi() }
                assertEquals(st.streamId, again?.streamId, "the stream was lost")
                assertContentEquals("one".encodeToByteArray(), withTimeout(5.seconds) { again!!.input.readAllBytes() })
            }
        }

    /** Cancelled after the stream was taken and wrapped, while acceptBidi returns to the caller's dispatcher. */
    @Test fun negative_anAcceptorCancelledAsItReturnsLosesNoStream() =
        h3Test {
            H3Pair.open(clientSettings = wtOn, serverSettings = wtOn).useScoped { p ->
                val (client, server) = sessions(p)
                val steps = StepDispatcher()
                val acceptor = launch(steps, start = CoroutineStart.UNDISPATCHED) { server.acceptUni() }
                val st = client.openUni()
                st.output.writeFully("two".encodeToByteArray())
                st.output.flushAndClose()
                // the receive resumes on the step dispatcher; the stream is wrapped on the connection's dispatcher, and the
                // return comes back here as the next step: the caller is cancelled in between
                withTimeout(5.seconds) { steps.tasks.receive() }.run()
                val back = withTimeout(5.seconds) { steps.tasks.receive() }
                acceptor.cancel()
                back.run()
                while (!acceptor.isCompleted) steps.tasks.receive().run()
                assertTrue(acceptor.isCancelled)
                val again = withTimeoutOrNull(5.seconds) { server.acceptUni() }
                assertEquals(st.streamId, again?.streamId, "the stream was lost")
                assertContentEquals("two".encodeToByteArray(), withTimeout(5.seconds) { again!!.input.readAllBytes() })
            }
        }

    /** Streams taken by acceptUni callers that an adversarial dispatcher cancels are all delivered, each once, with their data. */
    @Test fun negative_streamsSurviveRandomlyCancelledAcceptors() =
        h3Test {
            val d = CancellingDispatcher(Random.nextLong())
            H3Pair.open(clientSettings = wtOn, serverSettings = wtOn).useScoped { p ->
                val (client, server) = sessions(p)
                val n = 20
                val got = HashSet<Int>()
                // each stream opens once the one before it was taken: the acceptor is mostly waiting when one arrives
                val taken = MutableStateFlow(0)
                launch {
                    repeat(n) { i ->
                        taken.first { it >= i }
                        val st = client.openUni()
                        st.output.writeFully(i.toString().encodeToByteArray())
                        st.output.flushAndClose()
                    }
                }
                withTimeoutOrNull(15.seconds) {
                    while (got.size < n) {
                        val st = underCancellation(d) { server.acceptUni() } ?: continue
                        val i = withTimeout(5.seconds) { st.input.readAllBytes() }.decodeToString().toInt()
                        assertTrue(got.add(i), "$d: stream $i delivered twice")
                        taken.value = got.size
                    }
                }
                assertEquals(n, got.size, "$d: streams were lost (${d.cancelled} cancelled)")
                assertTrue(d.cancelled > 0, "$d cancelled no acceptor")
            }
        }
}
