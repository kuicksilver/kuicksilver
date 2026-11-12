// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.sample.compose

import io.ktor.client.HttpClient
import io.ktor.client.engine.mock.MockEngine
import io.ktor.client.engine.mock.MockRequestHandleScope
import io.ktor.client.engine.mock.respond
import io.ktor.client.request.HttpRequestData
import io.ktor.client.request.HttpResponseData
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.http.headersOf
import io.ktor.utils.io.ByteReadChannel
import io.ktor.utils.io.writeFully
import io.ktor.utils.io.writer
import io.kuicksilver.ktor.client.FallbackReason
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.runTest
import kotlinx.io.IOException
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** The screen models without UI: downloads with Range resume, the diagnostics text, the statistics of a series. */
class DemoLogicTest {
    private val size = 1000L
    private val url = "https://demo.test/bytes/$size"

    /** The pattern of /bytes from [from] (inclusive) to [to] (exclusive). */
    private fun pattern(
        from: Long,
        to: Long,
    ) = ByteArray((to - from).toInt()) { patternByte(from + it) }

    /**
     * A body that delivers [from] until [to] and then breaks, as a TCP connection does when its network goes away. It
     * breaks once [read] completes (the client has taken the bytes): a channel closed with a cause drops what it still holds.
     */
    private fun breakingBody(
        from: Long,
        to: Long,
        read: CompletableDeferred<Unit>,
    ): ByteReadChannel =
        CoroutineScope(Dispatchers.Default).writer {
            channel.writeFully(pattern(from, to))
            channel.flush()
            read.await()
            throw IOException("Software caused connection abort")
        }.channel

    /** Completes when [n] bytes or more were received: the moment [breakingBody] may break. */
    private class Gate(
        val n: Long = 400,
    ) {
        val read = CompletableDeferred<Unit>()

        fun progress(got: Long) {
            if (got >= n) read.complete(Unit)
        }
    }

    private fun MockRequestHandleScope.full(breakAt: Gate? = null): HttpResponseData =
        respond(
            if (breakAt == null) ByteReadChannel(pattern(0, size)) else breakingBody(0, breakAt.n, breakAt.read),
            HttpStatusCode.OK,
            headersOf(HttpHeaders.ContentLength, size.toString()),
        )

    private fun MockRequestHandleScope.partial(
        from: Long,
        claimed: Long = from,
    ): HttpResponseData =
        respond(
            ByteReadChannel(pattern(from, size)),
            HttpStatusCode.PartialContent,
            headersOf(
                HttpHeaders.ContentRange to listOf("bytes $claimed-${size - 1}/$size"),
                HttpHeaders.ContentLength to listOf((size - from).toString()),
            ),
        )

    /** A client whose answers come from [answers] in order; the Range header of each request goes to [ranges]. */
    private fun client(
        ranges: MutableList<String?>,
        vararg answers: MockRequestHandleScope.(HttpRequestData) -> HttpResponseData,
    ): HttpClient {
        var n = 0
        return HttpClient(
            MockEngine { data ->
                ranges += data.headers[HttpHeaders.Range]
                answers[n++](data)
            },
        )
    }

    @Test fun resumeWithRangeContinuesFromOffset() =
        runTest {
            val ranges = mutableListOf<String?>()
            val progress = mutableListOf<Long>()
            val gate = Gate()
            val c = client(ranges, { full(breakAt = gate) }, { partial(400) })
            val r =
                download(c, url, resume = true, onProgress = { got, _ ->
                    progress += got
                    gate.progress(got)
                })
            assertIs<DownloadResult.Completed>(r)
            assertEquals(size, r.bytes)
            assertEquals(1, r.resumes)
            assertEquals(0, r.restarts)
            assertEquals(listOf(null, "bytes=400-"), ranges)
            assertEquals(size, progress.last())
            assertEquals(progress.sorted(), progress, "progress never goes back")
            assertTrue(400L in progress, "the bytes before the break count once: $progress")
        }

    @Test fun negative_withoutResumeTheBreakIsTheResult() =
        runTest {
            val ranges = mutableListOf<String?>()
            val gate = Gate()
            val r = download(client(ranges, { full(breakAt = gate) }), url, resume = false, onProgress = { got, _ -> gate.progress(got) })
            assertIs<DownloadResult.Failed>(r)
            assertEquals(400, r.bytes)
            assertEquals(listOf<String?>(null), ranges)
            assertTrue("abort" in r.error, r.error)
        }

    @Test fun negative_serverIgnoringRangeRestartsFromZero() =
        runTest {
            val ranges = mutableListOf<String?>()
            val gate = Gate()
            val r = download(client(ranges, { full(breakAt = gate) }, { full() }), url, resume = true, onProgress = { got, _ -> gate.progress(got) })
            assertIs<DownloadResult.Completed>(r)
            assertEquals(size, r.bytes)
            assertEquals(1, r.restarts, "a 200 to a Range request starts over: the honest cost")
            assertEquals(listOf(null, "bytes=400-"), ranges)
        }

    @Test fun negative_contentRangeFromAnotherOffsetIsRefused() =
        runTest {
            val ranges = mutableListOf<String?>()
            val gate = Gate()
            val c = client(ranges, { full(breakAt = gate) }, { partial(400, claimed = 300) })
            val r = download(c, url, resume = true, maxResumes = 1, onProgress = { got, _ -> gate.progress(got) })
            assertIs<DownloadResult.Failed>(r)
            assertTrue("Content-Range" in r.error, r.error)
            assertEquals(400, r.bytes)
        }

    @Test fun negative_corruptBodyIsDetected() =
        runTest {
            val bad = pattern(0, size).also { it[10] = (it[10] + 1).toByte() }
            val c =
                HttpClient(
                    MockEngine { respond(ByteReadChannel(bad), HttpStatusCode.OK, headersOf(HttpHeaders.ContentLength, size.toString())) },
                )
            val r = download(c, url, resume = false)
            assertIs<DownloadResult.Failed>(r)
            assertTrue("offset 10" in r.error, r.error)
        }

    @Test fun parsesContentRange() {
        assertEquals(ContentRange(400, 999, 1000), parseContentRange("bytes 400-999/1000"))
        assertEquals(ContentRange(0, 0, null), parseContentRange("bytes 0-0/*"))
        assertNull(parseContentRange("bytes */1000"))
        assertNull(parseContentRange("items 1-2/3"))
        assertNull(parseContentRange("bytes 5-4/10"))
    }

    @Test fun diagnosticsRenderedForFallback() {
        val lines =
            renderDiagnostics(
                DiagnosticsView(
                    protocol = "HTTP/1.1",
                    reason = "Race",
                    fallback = FallbackReason.HandshakeTimeout,
                    alternative = "demo.test:8443",
                    alternativeSource = "Preferred",
                    raced = true,
                    attempts = 1,
                    h3Failure = "ConnectTimeoutException",
                ),
            )
        val text = lines.joinToString("\n")
        assertEquals("Protocol: HTTP/1.1", lines.first())
        assertTrue("Not HTTP/3 because: HandshakeTimeout" in lines, text)
        assertTrue(lines.any { it.startsWith("What to check:") && "UDP" in it }, text)
        assertTrue("HTTP/3 failure: ConnectTimeoutException" in lines, text)
        assertTrue("Alternative: demo.test:8443 (Preferred)" in lines, text)
    }

    @Test fun diagnosticsRenderedForTheKillSwitch() {
        val lines = renderDiagnostics(DiagnosticsView("HTTP/1.1", "Http3Disabled", FallbackReason.Http3Disabled, null, null, false, 1, null))
        assertTrue(lines.any { it.startsWith("What to check:") && "http3Allowed" in it }, lines.joinToString("\n"))
    }

    @Test fun diagnosticsRenderedForHttp3() {
        val lines = renderDiagnostics(DiagnosticsView("HTTP/3", "ExistingConnection", null, "demo.test:443", "AltSvc", false, 1, null))
        assertEquals("Protocol: HTTP/3", lines.first())
        assertTrue(lines.none { it.startsWith("Not HTTP/3") || it.startsWith("What to check") }, lines.joinToString("\n"))
    }

    @Test fun negative_noDiagnosticsFromAnotherEngine() {
        assertEquals(listOf("No Kuicksilver diagnostics: another engine served this response"), renderDiagnostics(null))
    }

    /** The Migration screen: both lanes in parallel; "resume TCP" resumes the reference lane only, never Kuicksilver's. */
    @Test fun resumeTcpAppliesToTheReferenceLaneOnly() =
        runTest {
            val h3Ranges = mutableListOf<String?>()
            val tcpRanges = mutableListOf<String?>()
            val gates = listOf(Gate(), Gate())
            val model =
                MigrationModel(this) {
                    listOf(
                        Lane("h3", "", client(h3Ranges, { full(breakAt = gates[0]) }), "https://demo.test", isKuicksilver = true),
                        Lane("tcp", "", client(tcpRanges, { full(breakAt = gates[1]) }, { partial(400) }), "https://demo.test", isKuicksilver = false),
                    )
                }
            backgroundScope.launch { model.state.collect { s -> s.lanes.forEachIndexed { i, l -> gates[i].progress(l.received) } } }
            model.network("Wi-Fi")
            model.start("/bytes/$size", resumeTcp = true)
            model.join()
            val s = model.state.value
            assertEquals(false, s.running)
            assertEquals(listOf(LaneStatus.Failed, LaneStatus.Done), s.lanes.map { it.status }, s.toString())
            assertEquals(listOf<String?>(null), h3Ranges, "Kuicksilver's lane is never resumed: it has to survive by itself")
            assertEquals(listOf(null, "bytes=400-"), tcpRanges)
            assertEquals(1, s.lanes[1].resumes)
            assertTrue(s.events.any { "tcp: broke at 400 bytes" in it }, s.events.joinToString("\n"))
        }

    @Test fun negative_withoutResumeTcpTheReferenceLaneFails() =
        runTest {
            val gate = Gate()
            val model =
                MigrationModel(this) {
                    listOf(Lane("tcp", "", client(mutableListOf(), { full(breakAt = gate) }), "https://demo.test", isKuicksilver = false))
                }
            backgroundScope.launch { model.state.collect { s -> s.lanes.forEach { gate.progress(it.received) } } }
            model.start("/bytes/$size", resumeTcp = false)
            model.join()
            val lane = model.state.value.lanes.single()
            assertEquals(LaneStatus.Failed, lane.status)
            assertEquals(400, lane.received)
        }

    @Test fun medianAndP90() {
        val s = seriesStats((1..20).map { it.toDouble() }.shuffled())!!
        assertEquals(20, s.n)
        assertEquals(10.5, s.median)
        assertEquals(18.0, s.p90, "nearest rank: the 18th of 20")
        assertNull(seriesStats(emptyList()))
        assertEquals(7.0, seriesStats(listOf(7.0))!!.p90)
    }
}
