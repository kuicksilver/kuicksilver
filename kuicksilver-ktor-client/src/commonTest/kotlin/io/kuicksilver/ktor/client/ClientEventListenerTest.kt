// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.client

import io.ktor.client.request.HttpRequestData
import io.ktor.client.request.get
import io.ktor.client.statement.bodyAsText
import io.ktor.http.HttpProtocolVersion
import io.ktor.server.response.header
import io.ktor.server.response.respondText
import io.ktor.server.routing.get
import io.ktor.server.routing.routing
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.native.KslLoader
import io.kuicksilver.quic.ConnectionInfo
import io.kuicksilver.quic.ConnectionListener
import io.kuicksilver.quic.KuicksilverLogger
import io.kuicksilver.quic.LogLevel
import io.kuicksilver.quic.QlogSink
import io.kuicksilver.quic.QlogTrace
import io.kuicksilver.quic.quicConfig
import io.kuicksilver.tls.TlsRole
import kotlinx.coroutines.delay
import kotlinx.coroutines.withTimeout
import kotlin.concurrent.atomics.AtomicReference
import kotlin.concurrent.atomics.ExperimentalAtomicApi
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlin.time.Duration
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.seconds

/** The client engine's [KuicksilverEventListener], logger and qlog wiring (docs/guide/ktor.md, "Observability"). */
@OptIn(ExperimentalKuicksilverApi::class, ExperimentalAtomicApi::class)
class ClientEventListenerTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    /** Lines appended from any thread. */
    private class Lines {
        private val ref = AtomicReference<List<String>>(emptyList())
        val all: List<String> get() = ref.load()

        operator fun plusAssign(line: String) {
            while (true) {
                val old = ref.load()
                if (ref.compareAndSet(old, old + line)) return
            }
        }
    }

    /** Every event as one line, the request reduced to its path. */
    private class Recorder : KuicksilverEventListener() {
        val lines = Lines()
        val events: List<String> get() = lines.all

        private val HttpRequestData.p get() = url.encodedPath.ifEmpty { "/" }

        override fun callStart(request: HttpRequestData) {
            lines += "callStart ${request.p}"
        }

        override fun callEnd(
            request: HttpRequestData,
            protocol: HttpProtocolVersion,
            status: Int,
        ) {
            lines += "callEnd ${request.p} $protocol $status"
        }

        override fun callFailed(
            request: HttpRequestData,
            cause: Throwable,
        ) {
            lines += "callFailed ${request.p}"
        }

        override fun protocolSelected(
            request: HttpRequestData,
            protocol: HttpProtocolVersion,
            reason: ProtocolReason,
        ) {
            lines += "selected $protocol $reason"
        }

        override fun raceEnded(
            request: HttpRequestData,
            winner: HttpProtocolVersion,
            headStart: Duration,
            h3Failure: Throwable?,
        ) {
            lines += "race $winner${if (h3Failure != null) " h3 failed" else ""}"
        }

        override fun altSvcUsed(
            request: HttpRequestData,
            alternative: String,
        ) {
            lines += "altSvc $alternative"
        }

        override fun altSvcMarkedBroken(
            origin: String,
            alternative: String,
        ) {
            lines += "broken $alternative"
        }

        override fun fallback(
            request: HttpRequestData,
            cause: Throwable,
        ) {
            lines += "fallback"
        }

        override fun connectionAcquired(
            request: HttpRequestData,
            protocol: HttpProtocolVersion,
            reused: Boolean,
        ) {
            lines += "acquired $protocol reused=$reused"
        }

        override fun connectionReleased(
            request: HttpRequestData,
            protocol: HttpProtocolVersion,
            kept: Boolean,
        ) {
            lines += "released $protocol kept=$kept"
        }
    }

    private suspend fun eventually(cond: () -> Boolean) = withTimeout(5.seconds) { while (!cond()) delay(10) }

    @Test fun h3OnlyCallsReportProtocolAndPoolReuse() =
        h3Test {
            val (server, port) = testServer { routing { get("/") { call.respondText("ok") } } }
            val events = Recorder()
            try {
                testClient(Http3DiscoveryMode.H3Only, engine = { eventListener = events }).use { c ->
                    repeat(2) { assertEquals("ok", c.get("https://127.0.0.1:$port/").bodyAsText()) }
                    eventually { events.events.count { it.startsWith("released") } == 2 }
                    val e = events.events
                    assertEquals(
                        listOf(
                            "callStart /",
                            "selected HTTP/3.0 Configuration",
                            "acquired HTTP/3.0 reused=false",
                            "callEnd / HTTP/3.0 200",
                        ),
                        e.filter { !it.startsWith("released") }.take(4),
                        "$e",
                    )
                    assertTrue("acquired HTTP/3.0 reused=true" in e, "the second call shares the connection: $e")
                    assertTrue(e.filter { it.startsWith("released") }.all { it == "released HTTP/3.0 kept=true" }, "$e")
                }
            } finally {
                server.stop(100, 500)
            }
        }

    @Test fun h1CallsReportPoolAcquireAndRelease() =
        clientTest {
            val (server, port) = testServer { routing { get("/") { call.respondText("ok") } } }
            val events = Recorder()
            try {
                testClient(engine = { eventListener = events }).use { c ->
                    repeat(2) { assertEquals("ok", c.get("https://127.0.0.1:$port/").bodyAsText()) }
                    eventually { events.events.count { it.startsWith("released") } == 2 }
                    val e = events.events
                    assertEquals("selected HTTP/1.1 Configuration", e[1], "$e")
                    assertEquals(
                        listOf("acquired HTTP/1.1 reused=false", "acquired HTTP/1.1 reused=true"),
                        e.filter { it.startsWith("acquired") },
                    )
                    assertEquals(2, e.count { it == "released HTTP/1.1 kept=true" }, "$e")
                    assertEquals(2, e.count { it == "callEnd / HTTP/1.1 200" }, "$e")
                }
            } finally {
                server.stop(100, 500)
            }
        }

    @Test fun aRaceReportsItsWinnerAndAnExistingConnectionIsReused() =
        h3Test {
            val (server, port) = testServer { routing { get("/") { call.respondText("ok") } } }
            val events = Recorder()
            try {
                testClient(Http3DiscoveryMode.Preferred, engine = { eventListener = events }).use { c ->
                    val r = c.get("https://127.0.0.1:$port/")
                    assertEquals("ok", r.bodyAsText())
                    val e = events.events
                    assertTrue("race ${r.version}" in e, "the race's winner carried the call: $e")
                    assertTrue("selected ${r.version} Race" in e, "$e")
                    if (r.version == HttpProtocolVersion.HTTP_3_0) {
                        assertEquals("ok", c.get("https://127.0.0.1:$port/").bodyAsText())
                        assertTrue("selected HTTP/3.0 ExistingConnection" in events.events, "${events.events}")
                    }
                }
            } finally {
                server.stop(100, 500)
            }
        }

    @Test fun aDeadAlternativeReportsAltSvcRaceAndBrokenMark() =
        clientTest {
            val (server, port) =
                testServer(configure = { http3 = false }) {
                    routing {
                        get("/") {
                            call.response.header("Alt-Svc", "h3=\":${call.request.local.localPort}\"")
                            call.respondText("h1")
                        }
                    }
                }
            val events = Recorder()
            try {
                testClient(Http3DiscoveryMode.Auto, engine = {
                    eventListener = events
                    quic = quicConfig { handshakeTimeout = 500.milliseconds }
                }).use { c ->
                    assertEquals("h1", c.get("https://127.0.0.1:$port/").bodyAsText()) // learns the alternative
                    assertTrue("selected HTTP/1.1 NoAlternative" in events.events, "${events.events}")
                    assertEquals(HttpProtocolVersion.HTTP_1_1, c.get("https://127.0.0.1:$port/").version)
                    eventually { "broken 127.0.0.1:$port" in events.events }
                    val e = events.events
                    assertTrue("altSvc 127.0.0.1:$port" in e, "$e")
                    assertTrue(e.any { it.startsWith("race HTTP/1.1") }, "$e")
                    assertEquals(HttpProtocolVersion.HTTP_1_1, c.get("https://127.0.0.1:$port/").version)
                    assertTrue("selected HTTP/1.1 BrokenAlternative" in events.events, "${events.events}")
                }
            } finally {
                server.stop(100, 500)
            }
        }

    @Test fun aThrowingListenerNeverFailsTheCall() =
        clientTest {
            val (server, port) = testServer { routing { get("/") { call.respondText("ok") } } }
            val warnings = Lines()
            val logger =
                object : KuicksilverLogger {
                    override fun isEnabled(level: LogLevel) = level >= LogLevel.Warn

                    override fun log(
                        level: LogLevel,
                        message: String,
                        cause: Throwable?,
                    ) {
                        warnings += message
                    }
                }
            val throwing =
                object : KuicksilverEventListener() {
                    override fun callStart(request: HttpRequestData): Unit = throw IllegalStateException("listener bug")
                }
            try {
                testClient(engine = {
                    eventListener = throwing
                    this.logger = logger
                }).use { c ->
                    assertEquals("ok", c.get("https://127.0.0.1:$port/").bodyAsText())
                    assertEquals(listOf("event listener failed in callStart"), warnings.all)
                }
            } finally {
                server.stop(100, 500)
            }
        }

    @Test fun aListenerThrowingCancellationNeverFailsTheCall() =
        h3Test {
            // the callbacks are not suspending: a CancellationException out of one is the listener's bug, not the call's cancellation
            val (server, port) = testServer { routing { get("/") { call.respondText("ok") } } }
            val throwing =
                object : KuicksilverEventListener() {
                    private fun bug(): Nothing = throw kotlinx.coroutines.CancellationException("listener bug")

                    override fun callStart(request: HttpRequestData): Unit = bug()

                    override fun callEnd(
                        request: HttpRequestData,
                        protocol: HttpProtocolVersion,
                        status: Int,
                    ): Unit = bug()

                    override fun protocolSelected(
                        request: HttpRequestData,
                        protocol: HttpProtocolVersion,
                        reason: ProtocolReason,
                    ): Unit = bug()

                    override fun connectionAcquired(
                        request: HttpRequestData,
                        protocol: HttpProtocolVersion,
                        reused: Boolean,
                    ): Unit = bug()

                    override fun connectionReleased(
                        request: HttpRequestData,
                        protocol: HttpProtocolVersion,
                        kept: Boolean,
                    ): Unit = bug()
                }
            try {
                for (mode in listOf(Http3DiscoveryMode.H1Only, Http3DiscoveryMode.H3Only)) {
                    testClient(mode, engine = {
                        eventListener = throwing
                        logger = KuicksilverLogger.None
                    }).use { c ->
                        repeat(2) { assertEquals("ok", c.get("https://127.0.0.1:$port/").bodyAsText(), "$mode") }
                    }
                }
            } finally {
                server.stop(100, 500)
            }
        }

    @Test fun loggerQlogAndConnectionListenerReachTheQuicEndpoint() =
        h3Test {
            val (server, port) = testServer { routing { get("/") { call.respondText("ok") } } }
            val lines = Lines()
            val logger =
                object : KuicksilverLogger {
                    override fun isEnabled(level: LogLevel) = true

                    override fun log(
                        level: LogLevel,
                        message: String,
                        cause: Throwable?,
                    ) {
                        lines += message
                    }
                }
            val traces = Lines()
            val qlog =
                object : QlogSink {
                    override fun open(
                        odcidHex: String,
                        role: TlsRole,
                    ): QlogTrace? {
                        traces += "$odcidHex $role"
                        return null
                    }
                }
            val opened = Lines()
            val listener =
                object : ConnectionListener {
                    override fun onOpened(connection: ConnectionInfo) {
                        opened += connection.id
                    }
                }
            try {
                testClient(Http3DiscoveryMode.H3Only, engine = {
                    this.logger = logger
                    http3 {
                        this.qlog = qlog
                        connectionListener = listener
                    }
                }).use { c ->
                    assertEquals("ok", c.get("https://127.0.0.1:$port/").bodyAsText())
                    assertEquals(1, opened.all.size)
                    assertEquals(listOf("${opened.all[0]} Client"), traces.all, "the trace is named after the connection")
                    assertTrue(lines.all.any { "handshake complete" in it }, "${lines.all}")
                }
            } finally {
                server.stop(100, 500)
            }
        }
}
