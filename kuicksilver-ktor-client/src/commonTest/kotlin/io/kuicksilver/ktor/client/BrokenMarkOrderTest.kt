// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.client

import io.kuicksilver.quic.KuicksilverLogger
import io.kuicksilver.quic.LogLevel
import kotlinx.coroutines.sync.withLock
import kotlin.concurrent.atomics.AtomicReference
import kotlin.concurrent.atomics.ExperimentalAtomicApi
import kotlin.test.Test
import kotlin.test.assertEquals

/**
 * A broken mark's warning and `altSvcMarkedBroken` event go out after the engine's Alt-Svc lock is released; a network
 * change (or a full clear) that came in between drops them, so they never follow the change's own notice for a mark that
 * is gone.
 */
@OptIn(ExperimentalAtomicApi::class)
class BrokenMarkOrderTest {
    private val seen = AtomicReference(emptyList<String>())

    private fun add(s: String) {
        while (true) {
            val l = seen.load()
            if (seen.compareAndSet(l, l + s)) return
        }
    }

    private fun client() =
        testClient(
            Http3Discovery.Auto,
            engine = {
                observability {
                    logger =
                        object : KuicksilverLogger {
                            override fun isEnabled(level: LogLevel) = level >= LogLevel.Warn

                            override fun log(
                                level: LogLevel,
                                message: String,
                                cause: Throwable?,
                            ) {
                                if (message.startsWith("HTTP/3 to ")) add("warn $message")
                            }
                        }
                    eventListener =
                        object : KuicksilverEventListener() {
                            override fun altSvcMarkedBroken(
                                origin: String,
                                alternative: String,
                            ) = add("event $origin $alternative")
                        }
                }
            },
        )

    @Test fun aMarkReportedAfterANetworkChangeIsDropped() =
        clientTest {
            client().use { c ->
                val engine = c.engine as KuicksilverEngine
                val stale = engine.altSvcLock.withLock { engine.markBrokenLocked("https://a.test", "a.test:443", FallbackReason.Other) }
                engine.altSvcLock.withLock { engine.brokenAltSvc.onNetworkChanged() }
                engine.reportMark("https://a.test", "a.test:443", stale)
                assertEquals(emptyList(), seen.load(), "the mark of the old network is not reported")
                val fresh = engine.altSvcLock.withLock { engine.markBrokenLocked("https://b.test", "b.test:443", FallbackReason.Other) }
                engine.reportMark("https://b.test", "b.test:443", fresh)
                assertEquals(2, seen.load().size, "${seen.load()}")
                assertEquals(true, seen.load()[0].startsWith("warn HTTP/3 to https://b.test failed"), "${seen.load()}")
                assertEquals("event https://b.test b.test:443", seen.load()[1])
            }
        }

    @Test fun negative_aFullClearDropsTheReportButAnOriginClearDoesNot() =
        clientTest {
            client().use { c ->
                val engine = c.engine as KuicksilverEngine
                val stale = engine.altSvcLock.withLock { engine.markBrokenLocked("https://a.test", "a.test:443", FallbackReason.Other) }
                engine.altSvcLock.withLock { engine.brokenAltSvc.clear(null) }
                engine.reportMark("https://a.test", "a.test:443", stale)
                assertEquals(emptyList(), seen.load())
                val kept = engine.altSvcLock.withLock { engine.markBrokenLocked("https://b.test", "b.test:443", FallbackReason.Other) }
                engine.altSvcLock.withLock { engine.brokenAltSvc.clear("https://other.test") }
                engine.reportMark("https://b.test", "b.test:443", kept)
                assertEquals(listOf("event https://b.test b.test:443"), seen.load().filter { it.startsWith("event") })
            }
        }
}
