// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.network

import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.async
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.yield
import kotlinx.io.IOException
import kotlin.test.Test
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertSame

/**
 * The read side asks [SendFailures] what an end of stream stands for: on Linux a receive after a send that took the peer's
 * reset returns the end, so the send's failure is the read side's.
 */
class SendFailuresTest {
    /** An end read while a send is under way waits for it: that send may be the one that took the reset. */
    @Test fun negative_anEndReadDuringAFailingSendGetsItsFailure() =
        runBlocking {
            val failures = SendFailures()
            val reset = IOException("Connection reset by peer")
            val inSend = CompletableDeferred<Unit>()
            val fail = CompletableDeferred<Unit>()
            val send =
                async(start = CoroutineStart.UNDISPATCHED) {
                    runCatching {
                        failures.send {
                            inSend.complete(Unit)
                            fail.await()
                            throw reset
                        }
                    }
                }
            inSend.await()
            val settled = async(start = CoroutineStart.UNDISPATCHED) { failures.settled() }
            yield()
            assertFalse(settled.isCompleted, "the end was settled while the send was under way")
            fail.complete(Unit)
            assertSame(reset, settled.await())
            assertSame(reset, send.await().exceptionOrNull())
        }

    /** Sends that succeed, a cancellation, or a failure the caller does not count (the socket's own close) leave the end an end. */
    @Test fun anEndAfterSendsThatDidNotFailIsAnEnd() =
        runBlocking {
            val failures = SendFailures()
            failures.send { 5 }
            assertFailsWith<CancellationException> { failures.send<Unit> { throw CancellationException("stopped") } }
            val own = IOException("Socket closed")
            assertFailsWith<IOException> { failures.send<Unit>({ it !== own }) { throw own } }
            assertNull(failures.settled())
        }

    /** The first failure is the one kept. */
    @Test fun theFirstFailureIsKept() =
        runBlocking {
            val failures = SendFailures()
            val first = IOException("Connection reset by peer")
            runCatching { failures.send<Unit> { throw first } }
            runCatching { failures.send<Unit> { throw IOException("Broken pipe") } }
            assertSame(first, failures.recorded)
            assertSame(first, failures.settled())
        }
}
