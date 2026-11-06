// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.client.dns

import kotlinx.coroutines.test.runTest
import kotlin.random.Random
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertSame
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.seconds

/** SVCB resolution as RFC 9460 section 3 defines it: the endpoint list, its order and its transports. */
@OptIn(kotlinx.coroutines.ExperimentalCoroutinesApi::class)
class SvcbResolutionTest {
    private val all = setOf("h3", "h2", "http/1.1")

    private fun rec(
        owner: String,
        priority: Int,
        target: String,
        vararg alpn: String,
        port: Int? = null,
        noDefaultAlpn: Boolean = false,
    ) = SvcbRecord(priority, target, alpn.toList(), noDefaultAlpn, port, emptyList(), emptyList(), 300, owner)

    private fun resolver(
        answers: Map<String, List<SvcbRecord>?>,
        scope: kotlinx.coroutines.CoroutineScope,
        asked: MutableList<String> = ArrayList(),
    ) = HttpsRecords({ name ->
        asked += name
        if (name in answers) answers[name] else emptyList()
    }, scope, 10.seconds, { 0L })

    @Test fun endpointsInPriorityOrderWithTheirTransports() =
        runTest {
            val rs =
                resolver(
                    mapOf(
                        "a.example" to
                            listOf(
                                rec("a.example", 2, "tcp.example", "h2"),
                                rec("a.example", 1, ".", "h3", port = 8443),
                                rec("a.example", 3, "quic.example", "h3", noDefaultAlpn = true),
                            ),
                    ),
                    backgroundScope,
                )
            val r = assertIs<HttpsResolution.Endpoints>(rs.resolve("a.example", 443, all))
            // section 7.1.2 with the default set "http/1.1" of section 9: h3 offers QUIC and TCP, h2 TCP, h3 with
            // no-default-alpn QUIC only
            assertEquals(
                listOf(
                    HttpsEndpoint("a.example", 8443, quic = true, tcp = true),
                    HttpsEndpoint("tcp.example", 443, quic = false, tcp = true),
                    HttpsEndpoint("quic.example", 443, quic = true, tcp = false),
                ),
                r.endpoints,
            )
        }

    @Test fun endpointWithoutASupportedProtocolIsNotAttempted() =
        runTest {
            // section 7.1.2: SHOULD NOT attempt an endpoint whose SVCB ALPN set has no supported protocol
            val rs = resolver(mapOf("a.example" to listOf(rec("a.example", 1, "x.example", "foo", noDefaultAlpn = true))), backgroundScope)
            assertSame(HttpsResolution.None, rs.resolve("a.example", 443, all))
            val h2Only =
                resolver(mapOf("a.example" to listOf(rec("a.example", 1, "x.example", "h2", noDefaultAlpn = true))), backgroundScope)
            assertSame(HttpsResolution.None, h2Only.resolve("a.example", 443, setOf("h3", "http/1.1")))
        }

    @Test fun equalPrioritiesAreShuffled() =
        runTest {
            // section 2.4.1: SHOULD shuffle within a priority level
            val seen = HashSet<String>()
            repeat(40) { seed ->
                val rs =
                    HttpsRecords({ n ->
                        listOf(
                            rec(n, 1, "b.example", "h2"),
                            rec(n, 1, "c.example", "h2"),
                            rec(n, 2, "z.example", "h2"),
                        )
                    }, backgroundScope, 10.seconds, {
                        0L
                    }, Random(seed))
                val eps = assertIs<HttpsResolution.Endpoints>(rs.resolve("a.example", 443, all)).endpoints
                assertEquals("z.example", eps.last().host)
                seen += eps.first().host
            }
            assertEquals(setOf("b.example", "c.example"), seen)
        }

    @Test fun aliasChainAppendsItsFinalNameAsAnEndpoint() =
        runTest {
            // section 3: SHALL append the final $QNAME, the authority's port and no SvcParams
            val asked = ArrayList<String>()
            val rs =
                resolver(
                    mapOf(
                        "_8443._https.a.example" to listOf(rec("_8443._https.a.example", 0, "cdn.example")),
                        "cdn.example" to listOf(rec("cdn.example", 1, "edge.example", "h3")),
                    ),
                    backgroundScope,
                    asked,
                )
            val r = assertIs<HttpsResolution.Endpoints>(rs.resolve("a.example", 8443, all))
            assertEquals(
                listOf(HttpsEndpoint("edge.example", 8443, true, true), HttpsEndpoint("cdn.example", 8443, quic = false, tcp = true)),
                r.endpoints,
            )
            assertEquals(listOf("_8443._https.a.example", "cdn.example"), asked)
        }

    @Test fun aliasToANameWithoutRecordsStillGivesItsEndpoint() =
        runTest {
            val rs = resolver(mapOf("a.example" to listOf(rec("a.example", 0, "apex.example.net"))), backgroundScope)
            assertEquals(
                listOf(HttpsEndpoint("apex.example.net", 443, quic = false, tcp = true)),
                assertIs<HttpsResolution.Endpoints>(rs.resolve("a.example", 443, all)).endpoints,
            )
        }

    @Test fun negative_aliasLoopOrChainLimitFallsBackToTheAuthority() =
        runTest {
            // section 3.1: MUST fall back to the authority endpoint, as if there were no SVCB record
            val loop =
                resolver(
                    mapOf(
                        "a.example" to listOf(rec("a.example", 0, "b.example")),
                        "b.example" to listOf(rec("b.example", 0, "a.example")),
                    ),
                    backgroundScope,
                )
            assertSame(HttpsResolution.None, loop.resolve("a.example", 443, all))
            val chain = (0..20).associate { i -> "n$i.example" to listOf(rec("n$i.example", 0, "n${i + 1}.example")) }
            assertSame(HttpsResolution.None, resolver(chain, backgroundScope).resolve("n0.example", 443, all))
        }

    @Test fun aliasToDotIsIgnored() =
        runTest {
            // section 12: clients that might be subject to forged "." records SHOULD ignore them
            val rs = resolver(mapOf("a.example" to listOf(rec("a.example", 0, "."))), backgroundScope)
            assertSame(HttpsResolution.None, rs.resolve("a.example", 443, all))
        }

    @Test fun failedLookupIsFailed() =
        runTest {
            val rs = resolver(mapOf("a.example" to null), backgroundScope)
            assertTrue(rs.resolve("a.example", 443, all) is HttpsResolution.Failed)
        }
}
