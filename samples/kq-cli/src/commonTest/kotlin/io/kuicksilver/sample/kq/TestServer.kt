// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.sample.kq

import io.ktor.http.ContentType
import io.ktor.http.HttpStatusCode
import io.ktor.server.application.Application
import io.ktor.server.engine.EmbeddedServer
import io.ktor.server.engine.embeddedServer
import io.ktor.server.request.httpVersion
import io.ktor.server.response.respond
import io.ktor.server.response.respondText
import io.ktor.server.routing.get
import io.ktor.server.routing.head
import io.ktor.server.routing.routing
import io.kuicksilver.ktor.server.Kuicksilver
import io.kuicksilver.ktor.server.KuicksilverApplicationEngine
import io.kuicksilver.tls.TlsIdentity
import kotlinx.io.buffered
import kotlinx.io.files.Path
import kotlinx.io.files.SystemFileSystem
import kotlinx.io.files.SystemTemporaryDirectory
import kotlinx.io.writeString
import kotlin.random.Random

typealias KqServer = EmbeddedServer<KuicksilverApplicationEngine, KuicksilverApplicationEngine.Configuration>

/**
 * A Kuicksilver server with the sample's test certificate on 127.0.0.1: HTTP/1.1 and HTTP/2 over TLS on TCP and HTTP/3 on
 * UDP, one port ([port], 0: a free one); responses over TCP carry `Alt-Svc: h3=":<port>"`. It accepts 0-RTT for GET.
 * Returns the started server and its port.
 */
suspend fun startServer(
    port: Int = 0,
    host: String = "127.0.0.1",
): Pair<KqServer, Int> {
    val server =
        embeddedServer(Kuicksilver, configure = {
            tlsConnector {
                tls { identity = TlsIdentity.fromPem(SampleCerts.serverChainPem, SampleCerts.serverKeyPem.toCharArray()) }
                this.host = host
                this.port = port
            }
            http3 { earlyData { enabled = true } } // session tickets for QUIC, GET runs in 0-RTT
        }, module = Application::kqTestModule)
    server.startSuspend(false)
    return server to server.engine.resolvedConnectors().first().port
}

/** `/` answers which protocol the request came over (HEAD too); `/bytes/<n>` sends n bytes; `/clear` sends `Alt-Svc: clear`. */
fun Application.kqTestModule() {
    routing {
        get("/") { call.respondText("hello over ${call.request.httpVersion}\n") }
        head("/") { call.respond(HttpStatusCode.OK) }
        get("/clear") {
            call.response.headers.append("Alt-Svc", "clear") // the application's own Alt-Svc: the engine adds none
            call.respondText("cleared\n")
        }
        get("/bytes/{n}") {
            val n = call.parameters["n"]!!.toInt().coerceIn(0, 1 shl 20)
            call.respondText("x".repeat(n), ContentType.Application.OctetStream)
        }
    }
}

/** A new file name in the temporary directory (not created). */
fun tempPath(name: String): Path = Path(SystemTemporaryDirectory, "kq-test-${Random.nextLong().toULong()}-$name")

/** Deletes [p] (a file, or a directory with the files in it) if it is there. */
fun deleteTree(p: Path) {
    if (!SystemFileSystem.exists(p)) return
    if (SystemFileSystem.metadataOrNull(p)?.isDirectory == true) SystemFileSystem.list(p).forEach { deleteTree(it) }
    SystemFileSystem.delete(p, mustExist = false)
}

/** Writes [text] to a new temporary file and returns its path. */
fun tempFile(
    name: String,
    text: String,
): Path {
    val p = tempPath(name)
    SystemFileSystem.sink(p).buffered().use { it.writeString(text) }
    return p
}
