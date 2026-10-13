// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:JvmName("HostPeerMain")

package io.kuicksilver.ktor.client

import io.ktor.network.sockets.InetSocketAddress
import io.ktor.server.engine.embeddedServer
import io.ktor.server.response.respondText
import io.ktor.server.routing.get
import io.ktor.server.routing.routing
import io.kuicksilver.native.KslLoader
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import java.io.File
import java.net.InetAddress
import java.net.ServerSocket
import kotlin.concurrent.thread
import kotlin.time.Duration.Companion.seconds
import io.kuicksilver.ktor.server.Kuicksilver as KuicksilverServer

/**
 * The host side of `iosHostInteropTest` (the Gradle task starts it before the simulator tests and stops it after): a Kuicksilver
 * Ktor server (HTTP/1.1 and HTTP/3 on one port) and a raw QUIC echo server, each on 127.0.0.1 and on ::1, and a line-based
 * control port on 127.0.0.1 whose number goes to `args[0]` once everything listens. The simulator shares the host's network
 * stack, so its loopback reaches these sockets and the host reaches the simulator's.
 *
 * Control protocol, one request per line, one answer line:
 * - `PORTS` answers `http4=<p> http6=<p> echo4=<p> echo6=<p>`;
 * - `DIAL <host> <port>` runs a JVM QUIC client against the simulator's echo server there and answers `OK <echo>` or
 *   `ERR <reason>` (the reverse direction: a server on iOS, a client on the host).
 */
fun main(args: Array<String>) {
    KslLoader.ensureLoaded()
    val portFile = File(args.single())
    val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
    val ports =
        runBlocking {
            val http =
                listOf("127.0.0.1", "::1").map { host ->
                    val server =
                        embeddedServer(KuicksilverServer, configure = {
                            tlsConnector(ClientFixtures.identity()) {
                                this.host = host
                                port = 0
                            }
                        }) {
                            routing { get("/hello") { call.respondText("hello over ${call.request.local.version}") } }
                        }
                    server.startSuspend(false)
                    server.engine
                        .resolvedConnectors()
                        .first()
                        .port
                }
            val echo = listOf("127.0.0.1", "::1").map { HostInterop.echoServer(InetSocketAddress(it, 0), scope).localAddress.port }
            "http4=${http[0]} http6=${http[1]} echo4=${echo[0]} echo6=${echo[1]}"
        }
    val control = ServerSocket(0, 16, InetAddress.getByName("127.0.0.1"))
    val tmp = File(portFile.path + ".tmp")
    tmp.writeText(control.localPort.toString())
    tmp.renameTo(portFile) // the task polls for the file: it appears whole
    println("kuicksilver host peer: control ${control.localPort}, $ports")
    while (true) {
        val socket = control.accept()
        thread(isDaemon = true) {
            socket.use { s ->
                val input = s.getInputStream().bufferedReader()
                val output = s.getOutputStream().bufferedWriter()
                while (true) {
                    val line = input.readLine() ?: break
                    val words = line.trim().split(' ')
                    val answer =
                        when (words[0]) {
                            "PORTS" -> {
                                ports
                            }

                            "DIAL" -> {
                                try {
                                    val echoed =
                                        runBlocking {
                                            withTimeout(30.seconds) {
                                                HostInterop.echo(
                                                    InetSocketAddress(words[1], words[2].toInt()),
                                                    "from the host JVM".encodeToByteArray(),
                                                )
                                            }
                                        }
                                    "OK ${echoed.decodeToString()}"
                                } catch (e: Exception) {
                                    "ERR ${e::class.simpleName}: ${e.message}".replace('\n', ' ')
                                }
                            }

                            else -> {
                                "ERR unknown command"
                            }
                        }
                    println("$line -> $answer") // the task's log (build/host-peer/host-peer.log) shows what the simulator asked
                    output.write(answer + "\n")
                    output.flush()
                }
            }
        }
    }
}
