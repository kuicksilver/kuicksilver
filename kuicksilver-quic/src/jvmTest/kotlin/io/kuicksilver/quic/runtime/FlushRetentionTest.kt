// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.runtime

import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.native.KslLoader
import io.kuicksilver.quic.api.ApiPair
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeout
import kotlinx.coroutines.yield
import java.lang.ref.WeakReference
import kotlin.test.Test
import kotlin.test.assertNull
import kotlin.time.Duration.Companion.seconds

/** The loop's flush keeps no connection past its end: a closed connection is unreachable while its endpoint lives on. */
@OptIn(ExperimentalKuicksilverApi::class)
class FlushRetentionTest {
    /** Connects and closes a pair on [p]; weak references to the client connection and its core, once both sides have retired it. */
    private suspend fun connectAndClose(p: ApiPair): List<WeakReference<Any>> {
        val (c, s) = p.connect()
        val refs = listOf<WeakReference<Any>>(WeakReference(c), WeakReference((c as ConnectionRuntime).core))
        c.close()
        c.closed.await()
        s.closed.await()
        // until the client's loop retired it (it leaves the loop's table at the end of a flush)
        val loop = p.client as EndpointLoop
        while (withContext(loop.dispatcher) { loop.runtimes.containsKey(c.core) }) yield()
        return refs
    }

    @Test fun aClosedConnectionIsNotHeldByTheLoopsFlush() =
        runBlocking {
            KslLoader.ensureLoaded()
            ApiPair.open().use { p ->
                withTimeout(30.seconds) {
                    val refs = withContext(Dispatchers.Default) { connectAndClose(p) } // no frame of this test keeps them
                    repeat(5) { System.gc() }
                    for (r in refs) assertNull(r.get(), "the closed connection is still reachable while its endpoint is open")
                }
            }
        }
}
