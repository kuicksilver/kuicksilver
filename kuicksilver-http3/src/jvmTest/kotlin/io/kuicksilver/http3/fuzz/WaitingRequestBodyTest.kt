// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(kotlinx.coroutines.ExperimentalCoroutinesApi::class)

package io.kuicksilver.http3.fuzz

import io.ktor.utils.io.ByteChannel
import io.kuicksilver.http3.Http3Connection
import io.kuicksilver.http3.Http3Exception
import io.kuicksilver.http3.Http3ServerRequest
import io.kuicksilver.http3.http3Request
import io.kuicksilver.http3.http3Settings
import io.kuicksilver.http3.runtime.H3Session
import io.kuicksilver.native.KslLoader
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.StandardTestDispatcher
import kotlinx.coroutines.test.TestCoroutineScheduler
import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/**
 * A request with a body that waits for stream credit (RFC 9000 section 4.6) when its wait ends without a stream: the
 * connection ends, or its caller gives up. Its body was read by no one, and only a sender (never started) would have
 * ended it, so an application writing the body waited forever; the request now ends the body with its failure. A
 * request refused by GOAWAY while it waited was never sent (RequestNotProcessed.neverSent) and keeps its body unread,
 * for the retry. Deterministic: one virtual-time dispatcher, and the test delivers every piece of the in-memory transport.
 */
class WaitingRequestBodyTest {
    private val scheduler = TestCoroutineScheduler()
    private val dispatcher = StandardTestDispatcher(scheduler)
    private val scope = CoroutineScope(SupervisorJob() + dispatcher)
    private val net = MemNet(scope, bidiLimit = 1, uniLimit = 100)
    private lateinit var client: Http3Connection
    private lateinit var server: Http3Connection
    private val seen = ArrayList<Http3ServerRequest>()

    @BeforeTest fun setUp() {
        KslLoader.ensureLoaded()
        H3Session.dispatcherForTest = dispatcher
        val settings = http3Settings { h3Datagram = false }
        scope.launch { server = Http3Connection.server(net.server, settings) }
        scope.launch { client = Http3Connection.client(net.client, settings) }
        settle()
        scope.launch { while (true) seen += runCatching { server.acceptRequest() }.getOrNull() ?: break }
    }

    @AfterTest fun tearDown() {
        H3Session.dispatcherForTest = null
        net.client.closeNow(0, "")
        scope.cancel()
    }

    private fun settle() {
        repeat(20) {
            net.deliverAll()
            scheduler.advanceTimeBy(10)
            scheduler.runCurrent()
        }
    }

    private class Waiting(
        val body: ByteChannel,
        val job: Job,
        val result: MutableList<Result<Int>>,
    )

    /** A GET that takes the only stream, then a POST with a body that waits for its credit. */
    private fun postWaitingForCredit(): Waiting {
        scope.launch { runCatching { client.request(http3Request("GET", "server.test", "/first")) } }
        settle()
        assertEquals(1, seen.size, "the first request reached the server and holds the only stream")
        val body = ByteChannel()
        val out = ArrayList<Result<Int>>()
        val job =
            scope.launch {
                out += runCatching { client.request(http3Request("POST", "server.test", "/second") { this.body = body }).status }
            }
        settle()
        assertEquals(1, seen.size, "the POST waits for stream credit")
        assertFalse(body.isClosedForWrite, "the waiting POST left its body alone")
        return Waiting(body, job, out)
    }

    @Test fun requestWaitingForStreamCreditReleasesItsBodyWhenTheConnectionEnds() {
        val w = postWaitingForCredit()
        net.server.closeNow(0, "")
        settle()
        assertTrue(w.result.singleOrNull()?.isFailure == true, "the waiting POST failed with the connection: ${w.result}")
        assertTrue(w.body.isClosedForWrite, "the body of the POST that failed with the connection is closed for writing")
    }

    @Test fun requestWaitingForStreamCreditReleasesItsBodyWhenItsCallerGivesUp() {
        val w = postWaitingForCredit()
        w.job.cancel()
        settle()
        assertTrue(w.job.isCancelled, "the caller gave up")
        assertTrue(w.body.isClosedForWrite, "the body of the POST whose caller gave up is closed for writing")
    }

    @Test fun negative_requestRefusedByGoAwayWhileWaitingKeepsItsBody() {
        val w = postWaitingForCredit()
        scope.launch { server.goAway() }
        scheduler.runCurrent()
        net.deliverAll()
        scheduler.runCurrent()
        assertNotNull(client.goAwayReceived.value, "the client has the GOAWAY")
        scope.launch { seen[0].respond(200).finish() } // the first stream ends: its credit returns
        settle()
        val e = w.result.singleOrNull()?.exceptionOrNull()
        assertIs<Http3Exception.RequestNotProcessed>(e, "the waiting POST: $e")
        @OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)
        assertTrue(e.neverSent, "the POST was never sent")
        assertFalse(w.body.isClosedForWrite, "the body of a request never sent stays open for a retry")
    }
}
