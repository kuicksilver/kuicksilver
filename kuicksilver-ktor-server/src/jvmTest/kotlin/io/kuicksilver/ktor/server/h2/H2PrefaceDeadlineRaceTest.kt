// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.server.h2

import io.ktor.server.response.respondText
import io.ktor.server.routing.get
import io.ktor.server.routing.routing
import io.kuicksilver.ktor.server.RawFrame
import io.kuicksilver.ktor.server.RawH2Client
import io.kuicksilver.ktor.server.serverTest
import io.kuicksilver.ktor.server.tlsServer
import io.kuicksilver.native.KslLoader
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.job
import kotlinx.coroutines.withTimeout
import kotlinx.coroutines.yield
import kotlin.concurrent.Volatile
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertTrue
import kotlin.test.fail
import kotlin.time.Duration.Companion.seconds
import kotlin.time.TimeSource

/**
 * An HTTP/2 client preface read as its deadline (the request-head timeout) fires is the preface: the timeout lands on
 * another thread after the wait for the preface returned, before the timeout's scope completed, and the connection must
 * not be ended with GOAWAY for a client that sent its preface in time. A run whose preface was not read before the
 * deadline (a cold or loaded JVM) does not reach the race and is repeated with the deadline doubled.
 */
class H2PrefaceDeadlineRaceTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    @Volatile private var reached = false

    @Test fun negative_aPrefaceReadAsItsDeadlineFiresIsThePreface() =
        serverTest {
            var seconds = 2
            repeat(4) {
                reached = false
                val (server, port) =
                    tlsServer(configure = {
                        http2 { enabled = true }
                        http3 { enabled = false }
                        requestHeaderTimeout = seconds.seconds
                        h2PrefaceForTest = {
                            yield() // returns through a resumption, as the wait does; throws once the deadline fired
                            reached = true
                            val job = currentCoroutineContext().job
                            val giveUp = TimeSource.Monotonic.markNow() + 30.seconds
                            while (!job.isCancelled && giveUp.hasNotPassedNow()) Thread.onSpinWait() // the deadline fires
                        }
                    }) { routing { get("/") { call.respondText("ok") } } }
                try {
                    val frames =
                        RawH2Client.connect(port).use { raw ->
                            raw.preface()
                            raw.headers(1, RawH2Client.get())
                            // the frames up to the answer on stream 1, or to the server's GOAWAY or close
                            withTimeout(30.seconds) {
                                buildList {
                                    while (true) {
                                        val f = raw.readFrame() ?: break
                                        add(f)
                                        if ((f.type == RawFrame.HEADERS && f.stream == 1) || f.type == RawFrame.GOAWAY) break
                                    }
                                }
                            }
                        }
                    if (reached) {
                        // before: GOAWAY with last stream 0 and the close, for a preface that had arrived
                        assertTrue(frames.any { it.type == RawFrame.HEADERS && it.stream == 1 }, "the request was answered: $frames")
                        return@serverTest
                    }
                } finally {
                    server.stop(100, 500)
                }
                seconds *= 2
            }
            fail("no run reached the race")
        }
}
