// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.client

import io.ktor.client.request.get
import io.ktor.client.statement.bodyAsText
import io.ktor.http.HttpProtocolVersion
import io.ktor.util.date.getTimeMillis
import io.kuicksilver.native.KslLoader
import kotlinx.coroutines.coroutineScope
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/** Alt-Svc on responses that came over HTTP/3 (RFC 7838 section 3). */
class ClientAltSvcH3Test {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    /**
     * An `Alt-Svc` header received from the origin replaces its cached alternatives whatever protocol carried it: a `clear`
     * on an HTTP/3 response removes the alternative in use (RFC 7838 section 3). Before, only HTTP/1.1 responses were looked at.
     */
    @Test fun clearOverH3RemovesCachedAlternative() =
        h3Test {
            coroutineScope {
                val ep = h3Origin(listOf("alt-svc" to "clear"))
                try {
                    val port = ep.localAddress.port
                    val origin = "https://127.0.0.1:$port"
                    val store = InMemoryAltSvcStore()
                    store.put(origin, listOf(AltSvcEntry("h3", null, port, getTimeMillis() + 3_600_000, false)))
                    // nothing listens on the TCP port: the race goes to HTTP/3
                    testClient(Http3DiscoveryMode.Auto, engine = { http3 { altSvcStore = store } }).use { c ->
                        val r = c.get("$origin/")
                        assertEquals(HttpProtocolVersion.HTTP_3_0, r.version)
                        assertEquals("h3", r.bodyAsText())
                    }
                    assertTrue(store.get(origin).isEmpty(), "Alt-Svc: clear over HTTP/3 left ${store.get(origin)}")
                } finally {
                    ep.close()
                }
            }
        }

    /** A new list over HTTP/3 replaces the cached one (RFC 7838 section 3). */
    @Test fun newListOverH3ReplacesCachedAlternative() =
        h3Test {
            coroutineScope {
                val ep = h3Origin(listOf("alt-svc" to "h3=\"alt.example:8443\"; ma=60"))
                try {
                    val port = ep.localAddress.port
                    val origin = "https://127.0.0.1:$port"
                    val store = InMemoryAltSvcStore()
                    store.put(origin, listOf(AltSvcEntry("h3", null, port, getTimeMillis() + 3_600_000, false)))
                    testClient(Http3DiscoveryMode.Auto, engine = { http3 { altSvcStore = store } }).use { c ->
                        assertEquals(HttpProtocolVersion.HTTP_3_0, c.get("$origin/").version)
                    }
                    assertEquals(listOf("alt.example:8443"), store.get(origin).map { "${it.host}:${it.port}" })
                } finally {
                    ep.close()
                }
            }
        }
}
