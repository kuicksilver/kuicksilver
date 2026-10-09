// Copyright 2014-2025 JetBrains s.r.o and contributors. Use of this source code is governed by the Apache 2.0 license.
// Modifications Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
// Adapted from Ktor 3.6.0 ktor-server/ktor-server-test-base (BaseTest, EngineTestBase, EngineTestBaseJvm): the server under test
// is embeddedServer(Kuicksilver) with a cleartext and a TLS connector (HTTP/1.1 + HTTP/3 on the TLS port); the client is
// HttpClient(Kuicksilver) with the test CA, over HTTP/1.1 (cleartext and TLS) or HTTP/3 depending on [protocol].
package io.kuicksilver.ktor.server.contract

import io.ktor.client.HttpClient
import io.ktor.client.plugins.HttpTimeout
import io.ktor.client.request.HttpRequestBuilder
import io.ktor.client.request.prepareRequest
import io.ktor.client.statement.HttpResponse
import io.ktor.http.takeFrom
import io.ktor.server.application.Application
import io.ktor.server.application.install
import io.ktor.server.application.serverConfig
import io.ktor.server.engine.ApplicationEngine
import io.ktor.server.engine.ApplicationEngineFactory
import io.ktor.server.engine.EmbeddedServer
import io.ktor.server.engine.applicationEnvironment
import io.ktor.server.engine.connector
import io.ktor.server.engine.embeddedServer
import io.ktor.server.routing.Route
import io.ktor.server.routing.RoutingRoot
import io.ktor.util.logging.KtorSimpleLogger
import io.ktor.util.logging.Logger
import io.kuicksilver.ktor.client.Http3DiscoveryMode
import io.kuicksilver.ktor.server.KuicksilverApplicationEngine
import io.kuicksilver.ktor.server.TestCerts
import io.kuicksilver.tls.Certificate
import io.kuicksilver.tls.TlsIdentity
import io.kuicksilver.tls.TrustConfig
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeout
import org.junit.jupiter.api.Assumptions.assumeTrue
import java.net.InetSocketAddress
import java.net.Socket
import java.util.Collections
import kotlin.coroutines.CoroutineContext
import kotlin.coroutines.EmptyCoroutineContext
import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.time.Duration
import kotlin.time.Duration.Companion.seconds
import io.kuicksilver.ktor.client.Kuicksilver as KuicksilverClient

/** How the suite talks to the server. */
enum class ContractProtocol { H1, H3 }

/** Thrown on purpose by a test route; not reported as an unhandled failure (Ktor's `ExpectedTestException`). */
class ExpectedTestException(
    message: String,
) : Throwable(message)

val DEFAULT_TEST_TIMEOUT: Duration = 1.seconds * 60
const val DEFAULT_RETRIES: Int = 1

abstract class EngineTestBase<TEngine : ApplicationEngine, TConfiguration : ApplicationEngine.Configuration>(
    val applicationEngineFactory: ApplicationEngineFactory<TEngine, TConfiguration>,
) : CoroutineScope {
    /** The protocol of [withUrl]; HTTP/3 suites override it. */
    protected open val protocol: ContractProtocol = ContractProtocol.H1

    private val testJob = Job()
    override val coroutineContext: CoroutineContext get() = testJob + Dispatchers.IO.limitedParallelism(32)

    @Target(AnnotationTarget.FUNCTION)
    @Retention
    protected annotation class Http2Only

    @Target(AnnotationTarget.FUNCTION)
    @Retention
    protected annotation class Http1Only

    protected var port: Int = 0
    protected var sslPort: Int = 0
    protected var server: EmbeddedServer<TEngine, TConfiguration>? = null
    protected var enableHttp2: Boolean = false
    protected var enableSsl: Boolean = true
    protected var enableCertVerify: Boolean = false
    val testLog: Logger = KtorSimpleLogger("io.kuicksilver.test.EngineTestBase")
    open val timeout: Duration = DEFAULT_TEST_TIMEOUT

    private val unhandled = Collections.synchronizedList(ArrayList<Throwable>())

    fun collectUnhandledException(error: Throwable) {
        unhandled += error
    }

    @BeforeTest open fun beforeTest() {}

    @AfterTest open fun afterTest() {
        try {
            server?.stop(0, 500)
        } finally {
            testJob.cancel()
        }
    }

    /** Ktor's `runTest`: real time, a timeout, retries; skips `@Http2Only` and, over HTTP/3, `@Http1Only` tests. */
    fun runTest(
        timeout: Duration = this.timeout,
        retries: Int = DEFAULT_RETRIES,
        block: suspend CoroutineScope.() -> Unit,
    ) {
        val method = currentTestMethod()
        if (method?.isAnnotationPresent(Http2Only::class.java) == true) assumeTrue(false, "HTTP/2 is not offered by Kuicksilver")
        if (method?.isAnnotationPresent(Http1Only::class.java) == true) assumeTrue(protocol == ContractProtocol.H1, "HTTP/1.1-only test")
        var last: Throwable? = null
        for (attempt in 0..retries) {
            unhandled.clear()
            last = runCatching { runBlocking { withTimeout(timeout) { withContext(Dispatchers.IO) { block() } } } }.exceptionOrNull()
                ?: unhandled.firstOrNull()?.let { AssertionError("unhandled server exception", it) }
            if (last == null) return
            server?.stop(0, 500)
            server = null
        }
        throw last!!
    }

    private fun currentTestMethod(): java.lang.reflect.Method? {
        val names =
            Thread
                .currentThread()
                .stackTrace
                .map { it.methodName }
                .toSet()
        return generateSequence<Class<*>>(javaClass) { it.superclass }
            .flatMap { it.declaredMethods.asSequence() }
            .firstOrNull { it.name in names && it.isAnnotationPresent(kotlin.test.Test::class.java) }
    }

    protected open fun createServer(
        log: Logger? = null,
        parent: CoroutineContext = EmptyCoroutineContext,
        module: Application.() -> Unit,
    ): EmbeddedServer<TEngine, TConfiguration> {
        val environment =
            applicationEnvironment {
                val delegate = KtorSimpleLogger("io.kuicksilver.test")
                this.log = log ?: object : Logger by delegate {
                    override fun error(
                        message: String,
                        cause: Throwable,
                    ) {
                        if (cause is ExpectedTestException) return
                        collectUnhandledException(cause)
                        delegate.error(message, cause)
                    }
                }
            }
        val properties =
            serverConfig(environment) {
                parentCoroutineContext = parent
                module(module)
            }
        return embeddedServer(applicationEngineFactory, properties) {
            shutdownGracePeriod = 1000
            shutdownTimeout = 1000
            connector {
                host = "127.0.0.1"
                port = 0
            }
            if (enableSsl) {
                (this as KuicksilverApplicationEngine.Configuration).tlsConnector(
                    TlsIdentity.fromDer(listOf(TestCerts.server), TestCerts.serverKey.copyOf()),
                ) {
                    host =
                        "127.0.0.1"
                    ; port = 0
                }
            }
            configure(this)
        }
    }

    protected open fun configure(configuration: TConfiguration) {}

    protected open fun plugins(
        application: Application,
        routingConfig: Route.() -> Unit,
    ) {
        application.install(RoutingRoot, routingConfig)
    }

    protected suspend fun createAndStartServer(
        log: Logger? = null,
        parent: CoroutineContext = EmptyCoroutineContext,
        routingConfigurer: Route.() -> Unit,
    ): EmbeddedServer<TEngine, TConfiguration> {
        val server = createServer(log, parent) { plugins(this, routingConfigurer) }
        val failures = startServer(server)
        if (failures.isNotEmpty()) {
            server.stop(1, 1)
            throw AssertionError("server failed to start", failures.first())
        }
        return server
    }

    protected suspend fun startServer(server: EmbeddedServer<TEngine, TConfiguration>): List<Throwable> {
        this.server = server
        return try {
            server.startSuspend(wait = false)
            val connectors = server.engine.resolvedConnectors()
            port = connectors[0].port
            if (connectors.size > 1) sslPort = connectors[1].port
            emptyList()
        } catch (t: Throwable) {
            listOf(t)
        }
    }

    private fun client(discovery: Http3DiscoveryMode): HttpClient =
        HttpClient(KuicksilverClient) {
            followRedirects = false
            expectSuccess = false
            install(HttpTimeout) { requestTimeoutMillis = 30_000 }
            engine {
                trust = TrustConfig.AnchoredCa(listOf(Certificate(TestCerts.testCa)))
                http3 { this.discovery = discovery }
            }
        }

    /** Over HTTP/1.1: cleartext, then TLS (as Ktor does with `enableSsl`); over HTTP/3: the TLS port only. */
    protected suspend fun withUrl(
        path: String,
        builder: suspend HttpRequestBuilder.() -> Unit = {},
        block: suspend HttpResponse.(Int) -> Unit,
    ) {
        if (protocol ==
            ContractProtocol.H3
        ) {
            request(Http3DiscoveryMode.H3Only, "https://127.0.0.1:$sslPort$path", sslPort, builder, block)
            return
        }
        request(Http3DiscoveryMode.H1Only, "http://127.0.0.1:$port$path", port, builder, block)
        if (enableSsl) request(Http3DiscoveryMode.H1Only, "https://127.0.0.1:$sslPort$path", sslPort, builder, block)
    }

    private suspend fun request(
        mode: Http3DiscoveryMode,
        url: String,
        port: Int,
        builder: suspend HttpRequestBuilder.() -> Unit,
        block: suspend HttpResponse.(Int) -> Unit,
    ) {
        client(mode).use { c ->
            c
                .prepareRequest {
                    this.url.takeFrom(url)
                    builder()
                }.execute { block(it, port) }
        }
    }

    protected inline fun socket(block: Socket.() -> Unit) {
        Socket().use { socket ->
            socket.tcpNoDelay = true
            socket.soTimeout = timeout.inWholeMilliseconds.toInt()
            socket.connect(InetSocketAddress("127.0.0.1", port))
            block(socket)
        }
    }
}
