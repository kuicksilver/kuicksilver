// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(io.kuicksilver.annotations.InternalKuicksilverApi::class)

package io.kuicksilver.http2.runtime

import io.ktor.utils.io.ByteChannel
import io.kuicksilver.http2.Http2Settings
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong
import kotlin.concurrent.thread
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.seconds

/**
 * RFC 9218 sections 7 and 8 under real threads: the client's PRIORITY_UPDATEs arrive on the connection's dispatch while
 * the response chooses its priority from another thread. Once chosen, no update changes the scheduling, and the signals
 * reach the engine with their order, so the most recent one can win.
 */
class PriorityConcurrencyTest {
    @Test fun updatesNeverOverrideTheResponsesChoice() =
        runBlocking {
            val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
            try {
                repeat(20) { round ->
                    val toServer = ByteChannel()
                    val toClient = ByteChannel()
                    val server = H2ServerConnection.start(toServer, toClient, Http2Settings(), scope, { toServer.close() })
                    val client =
                        H2ClientConnection.start(
                            toClient,
                            toServer,
                            Http2Settings(),
                            scope,
                            kotlin.time.Duration.INFINITE,
                            { toClient.close() },
                        )
                    val updates = 200
                    val seen = AtomicInteger()
                    val lastSeq = AtomicLong(-1)
                    val all = CompletableDeferred<Unit>()
                    val ordered = AtomicInteger() // signals whose seq grew: at least the last one carries the largest
                    val policy =
                        object : PriorityPolicy {
                            override fun parse(value: String): Int = value.removePrefix("u=").toInt() * 2

                            override fun signal(
                                urgency: Int,
                                incremental: Boolean,
                                seq: Long,
                            ) {
                                if (lastSeq.getAndAccumulate(seq, ::maxOf) < seq) ordered.incrementAndGet()
                                if (seen.incrementAndGet() == updates) all.complete(Unit)
                            }
                        }
                    val accepted = CompletableDeferred<H2ServerStream>()
                    scope.launch { accepted.complete(server.requests.receive()) }
                    assertTrue(client.tryReserve())
                    val s = client.open("GET", "https", "example.com", "/", emptyList(), endStream = false)
                    val r = withTimeout(10.seconds) { accepted.await() }
                    r.schedule(3, false, policy)
                    val chooser =
                        thread {
                            Thread.sleep(0, (round * 997) % 100_000)
                            r.choosePriority { _, _ -> 1 } // u=0, incremental
                        }
                    for (i in 0 until updates) assertTrue(s.priorityUpdate("u=${1 + i % 7}", 1 + i % 7))
                    chooser.join()
                    withTimeout(10.seconds) { all.await() }
                    assertEquals(0 to true, r.urgency to r.incremental, "round $round")
                    assertTrue(ordered.get() >= 1)
                    s.cancel()
                    s.release()
                    r.release()
                    client.abort(kotlinx.io.IOException("done"))
                    server.abort(kotlinx.io.IOException("done"))
                }
            } finally {
                scope.cancel()
            }
        }
}
