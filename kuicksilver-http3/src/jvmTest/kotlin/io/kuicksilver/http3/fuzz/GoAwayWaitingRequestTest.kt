// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(kotlinx.coroutines.ExperimentalCoroutinesApi::class)

package io.kuicksilver.http3.fuzz

import io.kuicksilver.http3.Http3Connection
import io.kuicksilver.http3.Http3Exception
import io.kuicksilver.http3.Http3ServerRequest
import io.kuicksilver.http3.http3Request
import io.kuicksilver.http3.http3Settings
import io.kuicksilver.http3.runtime.H3Session
import io.kuicksilver.native.KslLoader
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.StandardTestDispatcher
import kotlinx.coroutines.test.TestCoroutineScheduler
import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/**
 * RFC 9114 section 5.2: "Endpoints MUST NOT initiate new requests or promise new pushes on the connection after receipt of
 * a GOAWAY frame from the peer." A request that was waiting for stream credit when the server's GOAWAY arrived is a new
 * request: it is not sent, also when the credit comes later and its stream id is below the GOAWAY's, and it fails with the
 * retry-safe RequestNotProcessed, not with the client's own close of the then idle connection (found by `h3Connection`).
 * Deterministic: one virtual-time dispatcher, and the test delivers every piece of the in-memory transport.
 */
class GoAwayWaitingRequestTest {
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

    private fun request(path: String): MutableList<Result<Int>> {
        val out = ArrayList<Result<Int>>()
        scope.launch { out += runCatching { client.request(http3Request("GET", "server.test", path)).status } }
        return out
    }

    @Test fun negative_requestWaitingForStreamCreditIsNotSentAfterGoAway() {
        val first = request("/first")
        settle()
        assertEquals(1, seen.size, "the first request reached the server and holds the only stream")
        val second = request("/second") // waits for stream credit
        settle()
        assertEquals(1, seen.size)
        scope.launch { server.goAway() } // GOAWAY(2^62-4): the second request's stream id would be below it
        scheduler.runCurrent()
        net.deliverAll()
        scheduler.runCurrent()
        assertNotNull(client.goAwayReceived.value, "the client has the GOAWAY")
        scope.launch { seen[0].respond(200).finish() } // the first stream ends: its credit returns
        settle()
        assertEquals(listOf("/first"), seen.map { it.path }, "the server never saw the second request")
        assertEquals(200, first.single().getOrThrow())
        val e = second.singleOrNull()?.exceptionOrNull()
        assertIs<Http3Exception.RequestNotProcessed>(e, "the waiting request: $e")
        assertTrue(e.neverSent)
    }

    /** The same after our own GOAWAY: a client that sent GOAWAY issues no new requests, also ones that were waiting. */
    @Test fun negative_requestWaitingForStreamCreditIsNotSentAfterOurGoAway() {
        val first = request("/first")
        settle()
        val second = request("/second")
        settle()
        scope.launch { client.goAway() }
        scheduler.runCurrent()
        scope.launch { seen[0].respond(200).finish() }
        settle()
        assertEquals(listOf("/first"), seen.map { it.path }, "the server never saw the second request")
        assertEquals(200, first.single().getOrThrow())
        val e = second.singleOrNull()?.exceptionOrNull()
        assertIs<Http3Exception.RequestNotProcessed>(e, "the waiting request: $e")
        assertTrue(e.neverSent)
    }

    /**
     * Many requests queued behind the stream limit when the GOAWAY arrives open no stream at all: each would otherwise
     * be opened and reset, spending one of the server's reset tokens, so that enough of them turned a graceful shutdown
     * into H3_EXCESSIVE_LOAD.
     */
    @Test fun negative_queuedRequestsOpenNoStreamAfterGoAway() {
        val first = request("/first")
        settle()
        val queued = (0 until 1500).map { request("/q$it") }
        settle()
        assertEquals(1L, net.client.openedBidi)
        scope.launch { server.goAway() }
        scheduler.runCurrent()
        net.deliverAll()
        scheduler.runCurrent()
        scope.launch { seen[0].respond(200).finish() }
        settle()
        assertEquals(200, first.single().getOrThrow())
        assertEquals(1L, net.client.openedBidi, "streams the client opened")
        for (q in queued) assertIs<Http3Exception.RequestNotProcessed>(q.singleOrNull()?.exceptionOrNull())
        assertTrue(!server.closed.isCompleted || server.closed.getCompleted().let { it is Http3Exception.Protocol && it.h3Code == 0x100L })
    }
}
