// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:JvmName("AndroidMigrationPeerMain")

package io.kuicksilver.ktor.client

import io.ktor.server.engine.embeddedServer
import io.ktor.server.request.httpVersion
import io.ktor.server.response.respondBytesWriter
import io.ktor.server.response.respondText
import io.ktor.server.routing.get
import io.ktor.server.routing.routing
import io.ktor.utils.io.writeFully
import io.kuicksilver.native.KslLoader
import kotlinx.coroutines.awaitCancellation
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.runBlocking
import java.io.File
import io.kuicksilver.ktor.server.Kuicksilver as KuicksilverServer

/**
 * The host side of `androidMigrationDeviceTest` (the Gradle task starts it before `ClientMigrationAndroidTest` and stops it
 * after): a Kuicksilver Ktor server (HTTP/1.1 and HTTP/3) on the host's 127.0.0.1, which an emulator reaches as 10.0.2.2
 * through its own network (Wi-Fi or mobile), unlike a server inside the device, whose loopback never leaves the device.
 * The port goes to `args[0]` once it listens.
 *
 * - `/big`: 8 MiB; over HTTP/3 it stops after 2 MiB until a `/resume` arrives (the device switches networks meanwhile);
 * - `/resume`: lets the waiting `/big` go on (each `/big` first drops a `/resume` left over from an earlier one);
 * - `/version`: the request's HTTP version.
 */
fun main(args: Array<String>) {
    KslLoader.ensureLoaded()
    val portFile = File(args.single())
    val resumes = Channel<Unit>(Channel.UNLIMITED)
    runBlocking {
        val server =
            embeddedServer(KuicksilverServer, configure = {
                tlsConnector(ClientFixtures.identity()) {
                    host = "127.0.0.1"
                    port = 0
                    // the emulator reaches this peer as 10.0.2.2, a host its test certificate (server.test) does not name:
                    // without this, every request is a misdirected one (421, RFC 9110 section 7.4)
                    trustedGateway = true
                }
            }) {
                routing {
                    get("/big") {
                        // a /resume left over from an earlier download (one that failed before its pause) must not let this one through
                        while (resumes.tryReceive().isSuccess) {
                            // drain
                        }
                        call.respondBytesWriter {
                            val chunk = ByteArray(64 * 1024) { 7 }
                            var sent = 0
                            while (sent < 8 * 1024 * 1024) {
                                if (sent == 2 * 1024 * 1024 && call.request.httpVersion == "HTTP/3") resumes.receive()
                                writeFully(chunk)
                                sent += chunk.size
                            }
                        }
                    }
                    get("/resume") {
                        resumes.send(Unit)
                        call.respondText(call.request.httpVersion)
                    }
                    get("/version") { call.respondText(call.request.httpVersion) }
                }
            }
        server.startSuspend(false)
        val port =
            server.engine
                .resolvedConnectors()
                .first()
                .port
        val tmp = File(portFile.path + ".tmp")
        tmp.writeText(port.toString())
        tmp.renameTo(portFile) // the task polls for the file: it appears whole
        println("kuicksilver android migration peer: https://127.0.0.1:$port (10.0.2.2:$port from an emulator)")
        awaitCancellation()
    }
}
