// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.sample.compose.server

import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.server.application.ApplicationCall
import io.ktor.server.engine.connector
import io.ktor.server.engine.embeddedServer
import io.ktor.server.request.header
import io.ktor.server.request.httpVersion
import io.ktor.server.response.header
import io.ktor.server.response.respondBytesWriter
import io.ktor.server.response.respondText
import io.ktor.server.routing.get
import io.ktor.server.routing.routing
import io.ktor.utils.io.ByteWriteChannel
import io.ktor.utils.io.writeFully
import io.kuicksilver.ktor.server.Kuicksilver
import io.kuicksilver.tls.TlsIdentity
import kotlinx.coroutines.delay
import kotlin.time.Duration.Companion.seconds
import kotlin.time.TimeSource

/** The largest body `/bytes/{n}` serves. */
private const val MAX_BYTES: Long = 1L shl 30

/** Byte [offset] of every body: the pattern the app checks, so a body resumed with Range is proven whole. */
private fun patternByte(offset: Long): Byte = (offset % 251).toByte()

/** The options of the demo server; see [USAGE]. */
internal data class Options(
    val host: String = "0.0.0.0",
    val httpsPort: Int = 8443,
    val httpPort: Int = 8080,
    val altSvc: Boolean = true,
)

private const val USAGE = """usage: server [--host 0.0.0.0] [--https-port 8443] [--http-port 8080] [--no-alt-svc]
  https://<host>:<https-port>  HTTP/1.1 over TLS and HTTP/3 on UDP (the sample CA of certs/gen.sh)
  http://<host>:<http-port>    plain HTTP/1.1 (Ktor's CIO engine on iOS, which has no TLS on Kotlin/Native)
  --no-alt-svc                 no Alt-Svc header: URLSession (Ktor's Darwin engine) then stays on TCP
endpoints:
  /bytes/{n}[?rate=<bytes per second>]    n bytes of a fixed pattern; Range: bytes=<first>-[<last>] answers 206
  /stream[?seconds=30][&rate=1048576]     the same pattern without a length, for that long
  /                                       this text and the request's HTTP version"""

internal fun parseOptions(args: Array<String>): Options {
    var o = Options()
    var i = 0
    while (i < args.size) {
        fun value(): String = args.getOrNull(++i) ?: throw IllegalArgumentException("${args[i - 1]} needs a value")
        o =
            when (args[i]) {
                "--host" -> o.copy(host = value())
                "--https-port" -> o.copy(httpsPort = value().toInt())
                "--http-port" -> o.copy(httpPort = value().toInt())
                "--no-alt-svc" -> o.copy(altSvc = false)
                else -> throw IllegalArgumentException("unknown option ${args[i]}")
            }
        i++
    }
    return o
}

/** `bytes=first-` or `bytes=first-last` against a body of [size]; null when absent, unparsable or several ranges (then 200). */
internal fun parseRange(
    header: String?,
    size: Long,
): LongRange? {
    val spec = header?.trim()?.removePrefix("bytes=")?.takeIf { it != header.trim() && ',' !in it } ?: return null
    val first = spec.substringBefore('-').toLongOrNull() ?: return null
    val last = spec.substringAfter('-').let { if (it.isEmpty()) size - 1 else it.toLongOrNull() ?: return null }
    return first..minOf(last, size - 1)
}

/**
 * Writes the pattern from [from] to [until] (exclusive), at most [rate] bytes per second when set (the demo's downloads
 * must last long enough to switch a network by hand), or until [deadline] has passed.
 */
private suspend fun ByteWriteChannel.pattern(
    from: Long,
    until: Long,
    rate: Long?,
    deadline: kotlin.time.Duration? = null,
) {
    val start = TimeSource.Monotonic.markNow()
    val chunk = ByteArray(16 * 1024)
    var at = from
    while (at < until && (deadline == null || start.elapsedNow() < deadline)) {
        val n = minOf(chunk.size.toLong(), until - at).toInt()
        for (k in 0 until n) chunk[k] = patternByte(at + k)
        writeFully(chunk, 0, n)
        at += n
        if (rate != null) {
            // pacing, not synchronization: the body leaves at the configured rate
            val due = (at - from) * 1000 / rate
            val ahead = due - start.elapsedNow().inWholeMilliseconds
            if (ahead > 0) {
                flush()
                delay(ahead)
            }
        }
    }
}

private fun ApplicationCall.rate(): Long? = request.queryParameters["rate"]?.toLongOrNull()?.takeIf { it > 0 }

/**
 * The server of the Compose demo: Kuicksilver's Ktor engine with HTTP/1.1 over TLS and HTTP/3 on [Options.httpsPort], and
 * plain HTTP/1.1 on [Options.httpPort]. `./gradlew -p samples/compose-demo :server:run`.
 */
fun main(args: Array<String>) {
    if ("--help" in args || "-h" in args) return println(USAGE)
    val o = parseOptions(args)
    val server =
        embeddedServer(Kuicksilver, configure = {
            tlsConnector(TlsIdentity.fromPem(DemoServerCerts.chainPem, DemoServerCerts.keyPem.toCharArray())) {
                host = o.host
                port = o.httpsPort
            }
            connector {
                host = o.host
                port = o.httpPort
            }
            altSvc = o.altSvc
        }) {
            routing {
                get("/") { call.respondText("${call.request.httpVersion}\n$USAGE\n") }
                get("/bytes/{n}") {
                    val size = call.parameters["n"]?.toLongOrNull()?.takeIf { it in 0..MAX_BYTES }
                    if (size == null) return@get call.respondText("n must be 0..$MAX_BYTES", status = HttpStatusCode.BadRequest)
                    val range = parseRange(call.request.header(HttpHeaders.Range), size)
                    call.response.header(HttpHeaders.AcceptRanges, "bytes")
                    when {
                        range == null -> {
                            call.respondBytesWriter(status = HttpStatusCode.OK, contentLength = size) { pattern(0, size, call.rate()) }
                        }

                        range.first >= size || range.isEmpty() -> {
                            call.response.header(HttpHeaders.ContentRange, "bytes */$size")
                            call.respondText("", status = HttpStatusCode.RequestedRangeNotSatisfiable)
                        }

                        else -> {
                            val length = range.last - range.first + 1
                            call.response.header(HttpHeaders.ContentRange, "bytes ${range.first}-${range.last}/$size")
                            call.respondBytesWriter(status = HttpStatusCode.PartialContent, contentLength = length) {
                                pattern(range.first, range.last + 1, call.rate())
                            }
                        }
                    }
                }
                get("/stream") {
                    val seconds = call.request.queryParameters["seconds"]?.toLongOrNull()?.coerceIn(1, 3600) ?: 30
                    val rate = call.rate() ?: (1L shl 20)
                    call.respondBytesWriter { pattern(0, Long.MAX_VALUE, rate, seconds.seconds) }
                }
            }
        }
    println("compose demo server: https://${o.host}:${o.httpsPort} (HTTP/1.1 and HTTP/3), http://${o.host}:${o.httpPort} (HTTP/1.1)")
    server.start(wait = true)
}
