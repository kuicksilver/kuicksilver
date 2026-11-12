// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.client.dns

import kotlinx.coroutines.launch
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
        (if (name in answers) answers[name] else emptyList())?.let { DnsAnswer(it) }
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
                        DnsAnswer(
                            listOf(
                                rec(n, 1, "b.example", "h2"),
                                rec(n, 1, "c.example", "h2"),
                                rec(n, 2, "z.example", "h2"),
                            ),
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

    @Test fun recordsCarriedByAnEarlierAnswerAreUsedWithoutAQuery() =
        runTest {
            // section 5: the Additional section goes to the cache before any follow-up query
            val asked = ArrayList<String>()
            val prefetched = ArrayList<String>()
            val rs =
                HttpsRecords({ name ->
                    asked += name
                    if (name != "a.example") {
                        DnsAnswer(emptyList())
                    } else {
                        DnsAnswer(
                            listOf(rec("a.example", 0, "cdn.example")),
                            related = mapOf("cdn.example" to listOf(rec("cdn.example", 1, ".", "h3"))),
                            addresses = mapOf("cdn.example" to (listOf(byteArrayOf(192.toByte(), 0, 2, 1)) to 60L)),
                        )
                    }
                }, backgroundScope, 10.seconds, { 0L })
            val r = assertIs<HttpsResolution.Endpoints>(rs.resolve("a.example", 443, all) { prefetched += it })
            assertEquals(listOf("a.example"), asked)
            assertEquals("cdn.example", r.endpoints.first().host)
            assertEquals(listOf(4), r.addresses["cdn.example"]?.map { it.size })
            assertEquals(emptyList(), prefetched) // its addresses came with the answer
        }

    @Test fun aliasTargetThatIsACnameIsUsedWithoutAQuery() =
        runTest {
            // section 5: the alias target svc.example is a CNAME to cdn.example, whose RRset and addresses the answer
            // carried; the target's records are those at the end of its chain ("after following CNAMEs as normal", step 3)
            val alias = SvcbTestEncoder.encode(SvcbRecord(0, "svc.example", emptyList(), false, null, emptyList(), emptyList(), 0, "x"))
            val dot = SvcbTestEncoder.encode(SvcbRecord(1, ".", listOf("h3"), false, null, emptyList(), emptyList(), 0, "x"))
            val msg =
                SvcbTestEncoder
                    .response(
                        "a.example",
                        listOf(
                            SvcbTestEncoder.rr("a.example", 65, 300, alias),
                            SvcbTestEncoder.rr("svc.example", 5, 30, SvcbTestEncoder.name("cdn.example")),
                        ),
                    ).let { it.copyOf().also { m -> m[11] = 3 } } +
                    SvcbTestEncoder.rr("cdn.example", 65, 300, dot) +
                    SvcbTestEncoder.rr("cdn.example", 1, 200, hex("c0000201")) +
                    SvcbTestEncoder.rr("cdn.example", 28, 200, hex("20010db8000000000000000000000001"))
            val asked = ArrayList<String>()
            val rs =
                HttpsRecords({ name ->
                    asked += name
                    if (name == "a.example") DnsMessage.read(msg, name) else DnsAnswer(emptyList())
                }, backgroundScope, 10.seconds, { 0L })
            val r = assertIs<HttpsResolution.Endpoints>(rs.resolve("a.example", 443, all))
            assertEquals(listOf("a.example"), asked)
            assertEquals("cdn.example", r.endpoints.first().host)
            assertEquals(listOf(4, 16), r.addresses["cdn.example"]?.map { it.size })
        }

    @Test fun negative_outOfZoneRecordsAreNotCachedBeyondTheResolution() =
        runTest {
            // a TargetName in another zone: its records from this answer serve this resolution only
            val asked = ArrayList<String>()
            val rs =
                HttpsRecords({ name ->
                    asked += name
                    if (name == "a.example") {
                        DnsAnswer(
                            listOf(rec("a.example", 0, "cdn.other")),
                            related = mapOf("cdn.other" to listOf(rec("cdn.other", 1, ".", "h3"))),
                            chain = setOf("a.example"),
                        )
                    } else {
                        DnsAnswer(listOf(rec(name, 1, ".", "h2")))
                    }
                }, backgroundScope, 10.seconds, { 0L })
            assertEquals("cdn.other", assertIs<HttpsResolution.Endpoints>(rs.resolve("a.example", 443, all)).endpoints.first().host)
            assertEquals(listOf("a.example"), asked) // used for this resolution
            rs.resolve("cdn.other", 443, all)
            assertEquals(listOf("a.example", "cdn.other"), asked) // but not kept: asked for itself
        }

    @Test fun aliasTargetIsPrefetched() =
        runTest {
            // section 5: speculative A/AAAA queries in parallel with each SVCB query
            val prefetched = ArrayList<String>()
            val rs = resolver(mapOf("a.example" to listOf(rec("a.example", 0, "cdn.example"))), backgroundScope)
            rs.resolve("a.example", 443, all) { prefetched += it }
            assertEquals(listOf("cdn.example"), prefetched)
        }

    @Test fun failureAfterAnAliasKeepsTheAliasEndpoint() =
        runTest {
            // section 3: "whether successful or not", the processed AliasMode gives the final $QNAME as an endpoint
            val rs = resolver(mapOf("a.example" to listOf(rec("a.example", 0, "cdn.example")), "cdn.example" to null), backgroundScope)
            val r = assertIs<HttpsResolution.Failed>(rs.resolve("a.example", 443, all))
            assertEquals(HttpsEndpoint("cdn.example", 443, quic = false, tcp = true), r.aliasEndpoint)
        }

    @Test fun progressNamesTheAliasEndpointWhileTheChainRuns() =
        runTest {
            // a resolution cut short (the extra wait) still knows the AliasMode it processed
            val gate = kotlinx.coroutines.CompletableDeferred<Unit>()
            val rs =
                HttpsRecords({ n ->
                    if (n == "cdn.example") gate.await()
                    DnsAnswer(if (n == "a.example") listOf(rec("a.example", 0, "cdn.example")) else emptyList())
                }, backgroundScope, 10.seconds, { 0L })
            val progress = AliasProgress()
            val job = backgroundScope.launch { rs.resolve("a.example", 443, all, progress = progress) }
            testScheduler.runCurrent()
            assertEquals(HttpsEndpoint("cdn.example", 443, quic = false, tcp = true), progress.endpoint)
            job.cancel()
            gate.complete(Unit)
        }

    @Test fun nameThatCannotBeAskedHasNoRecords() =
        runTest {
            // a non-ASCII (not punycoded) host is no DNS name: no records, not a failed lookup (section 3.1)
            var asked = 0
            val rs =
                HttpsRecords({ n ->
                    asked++
                    DnsMessage.query(n)
                    DnsAnswer(emptyList())
                }, backgroundScope, 10.seconds, { 0L })
            assertSame(HttpsResolution.None, rs.resolve("bücher.example", 443, all))
            assertEquals(false, rs.upgradesToHttps("bücher.example", 443, all))
            assertEquals(0, asked)
        }

    @Test fun failedLookupIsFailed() =
        runTest {
            val rs = resolver(mapOf("a.example" to null), backgroundScope)
            assertTrue(rs.resolve("a.example", 443, all) is HttpsResolution.Failed)
        }
}
