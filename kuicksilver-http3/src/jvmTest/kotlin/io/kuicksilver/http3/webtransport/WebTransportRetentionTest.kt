// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)

package io.kuicksilver.http3.webtransport

import io.kuicksilver.http3.H3Pair
import io.kuicksilver.http3.runtime.h3Test
import io.kuicksilver.http3.useScoped
import io.kuicksilver.native.KslLoader
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.withTimeout
import kotlinx.coroutines.withTimeoutOrNull
import java.lang.ref.WeakReference
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertNull
import kotlin.time.Duration.Companion.seconds

/** A closed WebTransport session is unreachable while its connection lives on (a peer cycling sessions grows nothing). */
class WebTransportRetentionTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    /** Opens and closes one session on [p]; weak references to both sides' sessions once both slots are free again. */
    private suspend fun CoroutineScope.openAndClose(p: H3Pair): List<WeakReference<Any>> {
        val (client, server) = sessions(p)
        val refs = listOf<WeakReference<Any>>(WeakReference(client), WeakReference(server))
        client.close(1, "done")
        withTimeout(5.seconds) {
            client.closed.await()
            server.closed.await()
            p.client.session.wtIdle
                .first { it }
            p.server.session.wtIdle
                .first { it }
        }
        return refs
    }

    @Test fun aClosedSessionIsNotHeldByItsConnection() =
        h3Test {
            H3Pair.open(clientSettings = wtOn, serverSettings = wtOn).useScoped { p ->
                val refs = openAndClose(p) // no frame of this test keeps them
                // the coroutines that ended the sessions may still be returning on the connection's threads: collected
                // within a bound, never by a closed session's connection
                withTimeoutOrNull(5.seconds) {
                    while (refs.any { it.get() != null }) {
                        System.gc()
                        delay(10)
                    }
                }
                for ((i, r) in refs.withIndex()) {
                    assertNull(
                        r.get(),
                        "the ${if (i == 0) "client's" else "server's"} closed session is still reachable while its connection is open",
                    )
                }
            }
        }
}
