// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(ExperimentalForeignApi::class)

package io.kuicksilver.ktor.client

import io.ktor.client.request.get
import io.ktor.client.statement.bodyAsText
import io.ktor.http.HttpProtocolVersion
import io.ktor.network.selector.SelectorManager
import io.ktor.network.sockets.InetSocketAddress
import io.ktor.network.sockets.aSocket
import io.ktor.network.sockets.openReadChannel
import io.ktor.network.sockets.openWriteChannel
import io.ktor.utils.io.LineEnding
import io.ktor.utils.io.readLine
import io.ktor.utils.io.writeStringUtf8
import io.kuicksilver.native.KslLoader
import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.cinterop.toKString
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import platform.posix.getenv
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.time.Duration.Companion.seconds

/**
 * The simulator against a peer on the host (`./gradlew :kuicksilver-ktor-client:iosHostInteropTest` starts it and passes its
 * control port as `SIMCTL_CHILD_KSL_PEER_PORT`): Ktor over HTTP/3 and HTTP/1.1, raw QUIC, and the reverse direction with the
 * server on iOS, each over IPv4 and IPv6 loopback. Without the variable (a plain `iosSimulatorArm64Test`) every test passes
 * without doing anything.
 */
class HostInteropTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    private val controlPort: Int? = getenv(HostInterop.PORT_ENV)?.toKString()?.toIntOrNull()

    private val hosts = listOf("127.0.0.1", "::1")

    /** Runs [block] against the host peer when there is one; otherwise says so and passes. */
    private fun withPeer(block: suspend (Map<String, Int>) -> Unit) =
        runBlocking {
            val port = controlPort
            if (port == null) {
                println("HostInteropTest: ${HostInterop.PORT_ENV} not set, skipped (run iosHostInteropTest)")
                return@runBlocking
            }
            withTimeout(90.seconds) {
                val ports =
                    control(port, "PORTS")
                        .split(' ')
                        .associate { it.substringBefore('=') to it.substringAfter('=').toInt() }
                block(ports)
            }
        }

    /** One request on the host peer's control port, its answer line. */
    private suspend fun control(
        port: Int,
        request: String,
    ): String {
        val selector = SelectorManager(Dispatchers.Default)
        try {
            aSocket(selector).tcp().connect("127.0.0.1", port).use { s ->
                val write = s.openWriteChannel(autoFlush = true)
                val read = s.openReadChannel()
                write.writeStringUtf8(request + "\n")
                return read.readLine(LineEnding.Lenient) ?: error("the host peer closed the control connection")
            }
        } finally {
            selector.close()
        }
    }

    private fun url(
        host: String,
        port: Int,
    ) = if (host.contains(':')) "https://[$host]:$port/hello" else "https://$host:$port/hello"

    @Test fun ktorH3ToTheHost() =
        withPeer { ports ->
            for (host in hosts) {
                val port = ports.getValue(if (host.contains(':')) "http6" else "http4")
                testClient(Http3DiscoveryMode.H3Only).use { c ->
                    val r = c.get(url(host, port))
                    assertEquals(HttpProtocolVersion.HTTP_3_0, r.version, host)
                    assertEquals("hello over HTTP/3", r.bodyAsText(), host)
                }
            }
        }

    @Test fun ktorH1ToTheHost() =
        withPeer { ports ->
            for (host in hosts) {
                val port = ports.getValue(if (host.contains(':')) "http6" else "http4")
                testClient(Http3DiscoveryMode.H1Only).use { c ->
                    val r = c.get(url(host, port))
                    assertEquals(HttpProtocolVersion.HTTP_1_1, r.version, host)
                    assertEquals("hello over HTTP/1.1", r.bodyAsText(), host)
                }
            }
        }

    @Test fun rawQuicEchoToTheHost() =
        withPeer { ports ->
            for (host in hosts) {
                val port = ports.getValue(if (host.contains(':')) "echo6" else "echo4")
                val payload = "from the simulator over $host".encodeToByteArray()
                assertEquals(payload.decodeToString(), HostInterop.echo(InetSocketAddress(host, port), payload).decodeToString())
            }
        }

    @Test fun hostJvmClientToAServerOnIos() =
        withPeer { _ ->
            val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
            try {
                for (host in hosts) {
                    val server = HostInterop.echoServer(InetSocketAddress(host, 0), scope)
                    try {
                        assertEquals("OK from the host JVM", control(controlPort!!, "DIAL $host ${server.localAddress.port}"), host)
                    } finally {
                        server.close()
                    }
                }
            } finally {
                scope.cancel()
            }
        }
}
