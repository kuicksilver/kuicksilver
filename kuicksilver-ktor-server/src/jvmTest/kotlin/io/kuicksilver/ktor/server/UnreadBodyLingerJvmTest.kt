// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.server

import io.ktor.server.engine.connector
import io.ktor.server.engine.embeddedServer
import io.ktor.server.response.respondText
import io.ktor.server.routing.post
import io.ktor.server.routing.routing
import io.kuicksilver.native.KslLoader
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeout
import java.net.Socket
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.seconds

/**
 * A client of the common kind that writes its whole request, body included, before it reads the response (a blocking
 * `java.net.Socket`, as curl without `Expect` or most HTTP/1.1 libraries). The handler ignores a 32 MiB body: the server
 * answers, ends the connection, and must keep reading and dropping the body for a while (Go's `closeWriteAndWait`,
 * nginx `lingering_close`); closing over the unread body sends a reset, and the client's write fails with "connection
 * reset" before it ever reads the answer. JVM only (the blocking socket); run it on Linux too, where the reset is sent
 * reliably (tools/ci/docker-jvm.sh).
 */
class UnreadBodyLingerJvmTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    @Test fun negative_clientWritingItsWholeBodyGetsTheResponse() =
        serverTest {
            val server =
                embeddedServer(Kuicksilver, configure = {
                    connector {
                        host = "127.0.0.1"
                        port = 0
                    }
                }) { routing { post("/ignore") { call.respondText("ignored") } } }
            server.startSuspend(false)
            try {
                val port =
                    server.engine
                        .resolvedConnectors()
                        .first()
                        .port
                val size = 32 * 1024 * 1024
                val text =
                    withTimeout(20.seconds) {
                        withContext(Dispatchers.IO) {
                            Socket("127.0.0.1", port).use { s ->
                                val out = s.getOutputStream()
                                out.write("POST /ignore HTTP/1.1\r\nHost: s\r\nContent-Length: $size\r\n\r\n".encodeToByteArray())
                                val chunk = ByteArray(64 * 1024) { 'b'.code.toByte() }
                                repeat(size / chunk.size) { out.write(chunk) } // blocks while the server does not read
                                out.flush()
                                s.getInputStream().readBytes().decodeToString()
                            }
                        }
                    }
                assertTrue(text.startsWith("HTTP/1.1 200 "), text.take(200))
                assertTrue(text.contains("\r\nConnection: close\r\n"), text.take(200))
                assertTrue(text.endsWith("\r\n\r\nignored"), text.take(300))
            } finally {
                server.stop(100, 500)
            }
        }
}
