// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.client

import io.ktor.client.request.get
import io.ktor.client.statement.bodyAsText
import io.ktor.http.HttpProtocolVersion
import io.ktor.utils.io.writeStringUtf8
import io.kuicksilver.native.KslLoader
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.time.Duration.Companion.seconds

/** The h3/h1 connection race (RFC 8305 section 5, RFC 7838 section 2.4) against servers whose QUIC side never answers. */
class ClientRaceTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    /**
     * An idle pooled HTTP/1.1 connection the race hands out is a pooled connection: when the server closed it, an
     * idempotent request gets the same one transparent retry as on the plain HTTP/1.1 path (RFC 9112 section 9.3.1).
     * Before, the race's connection counted as fresh and the GET failed.
     */
    @Test fun staleConnectionFromTheRaceIsRetried() =
        clientTest {
            val served = ArrayList<String>()
            tlsH1WithSilentUdp(handler = { index, input, output ->
                served += "$index:${readRequest(input)}"
                output.writeStringUtf8("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
                if (index == 0) {
                    served += "$index:${readRequest(input)}" // the second request on the pooled connection: closed unanswered
                } else {
                    readRequest(input)
                }
            }) { port ->
                // the HTTP/3 setup stays pending (UDP is silent), so the race runs again for the second request
                testClient(Http3DiscoveryMode.Preferred, engine = { connectTimeout = 30.seconds }).use { c ->
                    val r1 = c.get("https://127.0.0.1:$port/1")
                    assertEquals(HttpProtocolVersion.HTTP_1_1, r1.version)
                    assertEquals("ok", r1.bodyAsText())
                    assertEquals("ok", c.get("https://127.0.0.1:$port/2").bodyAsText())
                }
            }
            assertEquals(listOf("0:GET /1 HTTP/1.1", "0:GET /2 HTTP/1.1", "1:GET /2 HTTP/1.1"), served)
        }
}
