// Copyright 2014-2025 JetBrains s.r.o and contributors. Use of this source code is governed by the Apache 2.0 license.
// Modifications Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
// The parts of Ktor 3.6.0 ktor-client-test-base (ClientLoader, CommonClientTestUtils) and ktor-test-server (ClientTestServer)
// the vendored tests use, re-implemented over the Kuicksilver engine: every test runs once over HTTP/1.1 and once over HTTP/3.
package io.kuicksilver.ktor.client.contract

import io.ktor.client.HttpClient
import io.ktor.client.HttpClientConfig
import io.ktor.client.engine.HttpClientEngineConfig
import io.ktor.http.ContentType
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.server.application.Application
import io.ktor.server.application.ApplicationCall
import io.ktor.server.application.install
import io.ktor.server.engine.connector
import io.ktor.server.engine.embeddedServer
import io.ktor.server.request.header
import io.ktor.server.request.receiveText
import io.ktor.server.response.respond
import io.ktor.server.response.respondBytes
import io.ktor.server.response.respondText
import io.ktor.server.routing.delete
import io.ktor.server.routing.get
import io.ktor.server.routing.post
import io.ktor.server.routing.routing
import io.ktor.server.websocket.WebSockets
import io.kuicksilver.ktor.client.Http3DiscoveryMode
import io.kuicksilver.ktor.client.Kuicksilver
import io.kuicksilver.ktor.client.KuicksilverEngineConfig
import io.kuicksilver.ktor.client.TestCerts
import io.kuicksilver.tls.Certificate
import io.kuicksilver.tls.TlsIdentity
import io.kuicksilver.tls.TrustConfig
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeout
import kotlin.time.Duration
import kotlin.time.Duration.Companion.minutes
import io.kuicksilver.ktor.server.Kuicksilver as KuicksilverServer

/** One way of running the contract: the protocol and the URLs the tests see. */
internal enum class ContractMode(
    val engineName: String,
    val discovery: Http3DiscoveryMode,
) {
    H1("Kuicksilver-h1", Http3DiscoveryMode.H1Only),
    H3("Kuicksilver-h3", Http3DiscoveryMode.H3Only),
}

/** The shared test server: the vendored routes of ktor-test-server on the Kuicksilver server engine, cleartext and TLS (+ HTTP/3). */
internal object ContractServer {
    val ports: Pair<Int, Int> by lazy {
        val server =
            embeddedServer(KuicksilverServer, configure = {
                connector {
                    host = "127.0.0.1"
                    port = 0
                }
                tlsConnector(TlsIdentity.fromDer(listOf(TestCerts.server), TestCerts.serverKey.copyOf())) {
                    host = "127.0.0.1"
                    port = 0
                }
            }, module = Application::contractTests)
        runBlocking {
            server.startSuspend(false)
            val c = server.engine.resolvedConnectors()
            c[0].port to c[1].port
        }
    }

    @Volatile var mode: ContractMode = ContractMode.H1
}

val TEST_SERVER: String get() =
    if (ContractServer.mode ==
        ContractMode.H3
    ) {
        "https://127.0.0.1:${ContractServer.ports.second}"
    } else {
        "http://127.0.0.1:${ContractServer.ports.first}"
    }
val TEST_SERVER_TLS: String get() = "https://127.0.0.1:${ContractServer.ports.second}"
val TEST_WEBSOCKET_SERVER: String get() =
    if (ContractServer.mode ==
        ContractMode.H3
    ) {
        "wss://127.0.0.1:${ContractServer.ports.second}"
    } else {
        "ws://127.0.0.1:${ContractServer.ports.first}"
    }

/** From ktor-test-server ClientTestServer.kt: the routes the vendored client tests call (WebSocket deflate and StatusPages left out: no new dependencies). */
internal fun Application.contractTests() {
    install(WebSockets) { maxFrameSize = 4 * 1024L }
    echoTest()
    contentTestServer()
    redirectTest()
    webSockets()
    headersTestServer()
    timeoutTest()
    downloadTest()
    uploadTest()
    routing {
        get("/") { call.respondText("Hello, world!") }
        post("/echo") { call.respond(call.receiveText()) }
        get("/echo_query") {
            call.respondText(
                call.request.queryParameters
                    .entries()
                    .joinToString { "${it.key}=${it.value}" },
            )
        }
        post("/echo-with-content-type") {
            val r = call.receiveText()
            call.respondBytes(r.toByteArray(), call.request.header(HttpHeaders.ContentType)?.let { ContentType.parse(it) })
        }
        get("/bytes") { call.respondBytes(makeArray(call.request.queryParameters["size"]!!.toInt())) }
        post("/content-type") { call.respondText(call.request.header(HttpHeaders.ContentType) ?: "") }
        delete("/delete") { call.respondText("OK ${call.receiveText()}") }
    }
}

internal suspend fun ApplicationCall.fail(text: String): Nothing {
    respondText(text, status = HttpStatusCode(400, text))
    error(text)
}

fun interface EngineSelectionRule {
    fun shouldRun(engineName: String): Boolean
}

private val platformName = "jvm"

private fun matches(
    pattern: String,
    engineName: String,
): Boolean {
    val parts = pattern.lowercase().split(":").map { it.takeIf { p -> p != "*" } }
    val (platform, engine) = if (parts.size == 1) null to parts[0] else parts[0] to parts[1]
    // our engine runs as "Kuicksilver-h1"/"Kuicksilver-h3"; a rule naming "Kuicksilver" covers both
    val engineOk = engine == null || engineName.lowercase() == engine || engineName.lowercase().substringBefore('-') == engine
    return engineOk && (platform == null || platformName.startsWith(platform))
}

/** Ktor's ClientLoader, reduced: the engines to test are the two modes of Kuicksilver. */
abstract class ClientLoader(
    private val rule: EngineSelectionRule = EngineSelectionRule { true },
    private val timeout: Duration = 1.minutes,
) {
    fun clientTests(
        rule: EngineSelectionRule = EngineSelectionRule { true },
        retries: Int = 0,
        timeout: Duration = this.timeout,
        block: suspend TestClientBuilder<HttpClientEngineConfig>.() -> Unit,
    ) {
        val failures = ArrayList<Pair<ContractMode, Throwable>>()
        for (mode in ContractMode.entries) {
            if (!this.rule.shouldRun(mode.engineName) || !rule.shouldRun(mode.engineName)) continue
            ContractServer.ports
            ContractServer.mode = mode
            var last: Throwable? = null
            for (attempt in 0..retries) {
                last =
                    runCatching {
                        runBlocking {
                            withTimeout(timeout) { withContext(Dispatchers.Default.limitedParallelism(1)) { performTest(mode, block) } }
                        }
                    }.exceptionOrNull()
                if (last == null) break
            }
            last?.let { failures += mode to it }
        }
        if (failures.isNotEmpty()) {
            throw AssertionError(
                failures.joinToString(
                    "\n",
                ) { (m, e) -> "Test failed for engine '${m.engineName}' with:\n${e.stackTraceToString().prependIndent("  ")}" },
                failures.first().second,
            )
        }
    }

    @Suppress("UNCHECKED_CAST")
    private suspend fun performTest(
        mode: ContractMode,
        block: suspend TestClientBuilder<HttpClientEngineConfig>.() -> Unit,
    ) {
        val builder = TestClientBuilder<HttpClientEngineConfig>().apply { block() }
        repeat(builder.repeatCount) {
            val client =
                HttpClient(Kuicksilver) {
                    engine {
                        trust = TrustConfig.AnchoredCa(listOf(Certificate(TestCerts.testCa)))
                        http3 { discovery = mode.discovery }
                    }
                    (builder.config as HttpClientConfig<KuicksilverEngineConfig>.() -> Unit)(this)
                }
            try {
                client.use { c -> coroutineScope { builder.test(this, c) } }
            } finally {
                builder.after(client)
            }
        }
    }
}

fun only(vararg engines: String): EngineSelectionRule = EngineSelectionRule { e -> engines.any { matches(it, e) } }

fun only(engineList: List<String>): EngineSelectionRule = only(*engineList.toTypedArray())

fun except(vararg engines: String): EngineSelectionRule = EngineSelectionRule { e -> engines.none { matches(it, e) } }

fun except(
    engineList: List<String>,
    vararg engines: String,
): EngineSelectionRule = except(*(engineList + engines.asList()).toTypedArray())

class TestClientBuilder<out T : HttpClientEngineConfig>(
    var config: HttpClientConfig<@UnsafeVariance T>.() -> Unit = {},
    var test: suspend CoroutineScope.(client: HttpClient) -> Unit = {},
    var after: suspend (client: HttpClient) -> Unit = {},
    var repeatCount: Int = 1,
    var dumpAfterDelay: Long = -1,
    var concurrency: Int = 1,
)

fun <T : HttpClientEngineConfig> TestClientBuilder<T>.config(block: HttpClientConfig<T>.() -> Unit) {
    config = block
}

fun TestClientBuilder<*>.test(block: suspend CoroutineScope.(client: HttpClient) -> Unit) {
    test = block
}

fun TestClientBuilder<*>.after(block: suspend (client: HttpClient) -> Unit) {
    after = block
}
