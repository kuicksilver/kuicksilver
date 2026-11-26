// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.sample.kq

import io.ktor.client.HttpClient
import io.ktor.client.request.header
import io.ktor.client.request.prepareRequest
import io.ktor.client.statement.HttpResponse
import io.ktor.client.statement.bodyAsChannel
import io.ktor.http.HttpMethod
import io.ktor.http.HttpProtocolVersion
import io.ktor.utils.io.readAvailable
import io.kuicksilver.ktor.client.FileAltSvcStore
import io.kuicksilver.ktor.client.Http3DiscoveryMode
import io.kuicksilver.ktor.client.InMemoryAltSvcStore
import io.kuicksilver.ktor.client.Kuicksilver
import io.kuicksilver.ktor.client.closeHttp3Connections
import io.kuicksilver.ktor.client.kuicksilverDiagnostics
import io.kuicksilver.quic.VersionProfile
import io.kuicksilver.quic.qlog.AsyncQlogSink
import io.kuicksilver.quic.qlog.DirectoryQlogSink
import io.kuicksilver.tls.Certificate
import io.kuicksilver.tls.TrustConfig
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.isActive
import kotlinx.coroutines.withTimeoutOrNull
import kotlinx.io.Sink
import kotlinx.io.buffered
import kotlinx.io.files.Path
import kotlinx.io.files.SystemFileSystem
import kotlinx.io.readString
import kotlin.time.Duration.Companion.seconds
import kotlin.time.TimeSource

/** Where kq writes: the body to [out], everything else (verbose lines, errors) to [err], one line per call. */
interface Console {
    fun out(
        bytes: ByteArray,
        offset: Int,
        length: Int,
    )

    fun err(line: String)

    /** Flushes [out]; false when a write to it failed (a closed pipe, a full disk), now or before. */
    fun flush(): Boolean
}

/** Runs kq with [args] (without the program name) and returns its exit code: 0 done, 1 a request failed, 2 a usage error. */
suspend fun kq(
    args: List<String>,
    stdio: Console,
): Int {
    // every stderr line kq prints, a usage error's included, goes through redact()
    val console: Console = RedactingConsole(stdio)
    return when (val p = parseArgs(args)) {
        Parsed.Help -> {
            console.text(USAGE + "\n")
            if (console.flush()) 0 else 1
        }

        Parsed.Version -> {
            console.text("kq, a Kuicksilver sample on its Ktor client engine (not published; built from this repository)\n")
            if (console.flush()) 0 else 1
        }

        is Parsed.Error -> {
            console.err("kq: ${p.message}")
            console.err("try 'kq --help'")
            2
        }

        is Parsed.Run -> run(p.options, console)
    }
}

private fun Console.text(s: String) {
    val b = s.encodeToByteArray()
    out(b, 0, b.size)
}

/** Every stderr line through [redact]: no line kq prints carries a URL's userinfo, whatever put the URL there. */
private class RedactingConsole(
    private val inner: Console,
) : Console by inner {
    override fun err(line: String) = inner.err(redact(line))
}

private suspend fun run(
    o: Options,
    console: Console,
): Int {
    val shown = redact(o.url.toString())
    val trust =
        o.caCert?.let { file ->
            val certs =
                try {
                    Certificate.parsePem(SystemFileSystem.source(Path(file)).buffered().use { it.readString() })
                } catch (e: Exception) {
                    console.err("kq: --cacert $file: ${e.message ?: e::class.simpleName}")
                    return 2
                }
            if (certs.isEmpty()) {
                console.err("kq: --cacert $file: no certificate in it")
                return 2
            }
            TrustConfig.AnchoredCa(certs)
        }
    // -o truncates the file at once; a request that fails later leaves what arrived before the failure
    val output: Sink? =
        o.output?.takeIf { it != "-" }?.let { file ->
            try {
                SystemFileSystem.sink(Path(file)).buffered()
            } catch (e: Exception) {
                console.err("kq: -o $file: ${e.message ?: e::class.simpleName}")
                return 1
            }
        }
    val observer = QuicObserver()
    val store = o.altSvcFile?.let { FileAltSvcStore(Path(it)) } ?: InMemoryAltSvcStore()
    // the files are written off the endpoint loop (AsyncQlogSink); the counter, in front of it, sees the endpoint open and
    // close each trace, so once it reads 0 every record and close is queued, and async.flush() waits until they are written
    val qlog = o.qlogDir?.let { AsyncQlogSink(DirectoryQlogSink(it)).let { async -> async to CountingQlogSink(async) } }
    var offered: List<VersionProfile> = emptyList()
    var exit = 0
    var client: HttpClient? = null
    try {
        client =
            HttpClient(Kuicksilver) {
                expectSuccess = false
                followRedirects = false // as curl without -L: a redirect is the answer
                engine {
                    trust?.let { this.trust = it }
                    o.connectTimeout?.let { connectTimeout = it }
                    offered = listOf(VersionProfile.V1) // the engine's QUIC versions: the default
                    http3 {
                        discovery =
                            when (o.mode) {
                                Mode.Auto -> Http3DiscoveryMode.Auto
                                Mode.Http3 -> Http3DiscoveryMode.Preferred
                                Mode.Http3Only -> Http3DiscoveryMode.H3Only
                                Mode.Http2, Mode.Http11 -> Http3DiscoveryMode.H1Only
                            }
                        altSvcStore = store
                        connectionListener = observer
                        earlyData = o.zeroRtt
                        qlog?.let { this.qlog = it.second }
                    }
                    if (o.mode == Mode.Http11) http2 { enabled = false }
                }
            }
        val write: (ByteArray, Int, Int) -> Unit =
            if (output != null) { b, off, n -> output.write(b, off, off + n) } else console::out
        for (i in 1..o.repeat) {
            val start = TimeSource.Monotonic.markNow()
            try {
                // a new HTTP/3 connection for each repeat resumes the session: the request then goes in 0-RTT
                if (i > 1 && o.zeroRtt) client.closeHttp3Connections()
                client
                    .prepareRequest(o.url) {
                        method = HttpMethod.parse(o.method)
                        o.headers.forEach { (n, v) -> header(n, v) }
                    }.execute { response ->
                        val head = start.elapsedNow()
                        if (o.includeHeaders) {
                            val s = statusAndHeaders(response).encodeToByteArray()
                            write(s, 0, s.size)
                        }
                        val bytes = copyBody(response, write)
                        val total = start.elapsedNow()
                        if (o.verbose) {
                            val req = Request(o.method, shown, i, o.repeat)
                            val timing = Timing(response.status.value, head, total, bytes)
                            report(req, response.kuicksilverDiagnostics, observer, offered, o.zeroRtt, timing)
                                .forEach(console::err)
                            altSvcLines(response.headers.getAll("Alt-Svc")).forEach(console::err)
                        }
                    }
            } catch (e: CancellationException) {
                // a timeout of the engine's own (TimeoutCancellationException) while kq itself goes on is the call's failure
                if (!currentCoroutineContext().isActive) throw e
                failed(console, o.method, shown, o.url, e)
                exit = 1
                break
            } catch (e: Exception) {
                failed(console, o.method, shown, o.url, e)
                exit = 1
                break
            }
        }
    } catch (e: CancellationException) {
        throw e
    } catch (e: Exception) {
        // the client could not be made (an engine configuration it refused), or something else outside a request
        console.err("kq: ${e::class.simpleName}: ${e.message ?: ""}")
        exit = 1
    } finally {
        if (output != null) {
            try {
                output.close()
            } catch (e: Exception) {
                console.err("kq: -o ${o.output}: ${e.message ?: e::class.simpleName}")
                exit = 1
            }
        }
        if (!console.flush()) {
            console.err("kq: writing to stdout failed")
            exit = 1
        }
        client?.let { c ->
            try {
                // HTTP/3 connections end with GOAWAY and H3_NO_ERROR rather than vanishing with the client
                withTimeoutOrNull(5.seconds) { c.closeHttp3Connections() }
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                console.err("kq: closing the HTTP/3 connections: ${e::class.simpleName}: ${e.message ?: ""}")
                exit = 1
            }
            c.close()
        }
        qlog?.let { (async, traces) ->
            // a trace ends when its connection is released, after the client closed
            if (!traces.awaitAllClosed(5.seconds)) console.err("kq: a qlog trace was still open at exit; it may be incomplete")
            if (withTimeoutOrNull(5.seconds) { async.flush() } == null) console.err("kq: the qlog writer did not finish in 5 s; traces may be incomplete")
            async.close()
            if (o.verbose && (async.dropped > 0 || async.failures > 0)) {
                console.err("* qlog: ${async.dropped} record(s) dropped (queue full), ${async.failures} write failure(s)")
            }
        }
    }
    return exit
}

private fun failed(
    console: Console,
    method: String,
    shown: String,
    url: io.ktor.http.Url,
    e: Throwable,
) {
    // Ktor's messages name the URL with its userinfo: the console redacts every line, this keeps the URL readable
    val message = (e.message ?: "").replace(url.toString(), shown)
    console.err("kq: $method $shown failed: ${e::class.simpleName}: $message")
    failureLines(e.kuicksilverDiagnostics).forEach { console.err("kq: $it") }
}

/** Copies the response body to [write]; returns its length. */
private suspend fun copyBody(
    response: HttpResponse,
    write: (ByteArray, Int, Int) -> Unit,
): Long {
    val channel = response.bodyAsChannel()
    val buf = ByteArray(16 * 1024)
    var total = 0L
    while (true) {
        val n = channel.readAvailable(buf, 0, buf.size)
        if (n == -1) break
        if (n > 0) {
            write(buf, 0, n)
            total += n
        }
    }
    return total
}

/** `HTTP/3 200` and the header fields, as curl -i prints them. */
fun statusAndHeaders(response: HttpResponse): String =
    buildString {
        append(protocolName(response.version)).append(' ').append(response.status.value)
        if (response.status.description.isNotEmpty()) append(' ').append(response.status.description)
        append("\r\n")
        response.headers.forEach { name, values -> values.forEach { append(name).append(": ").append(it).append("\r\n") } }
        append("\r\n")
    }

/** `HTTP/3`, `HTTP/2` or `HTTP/1.1`. */
fun protocolName(v: HttpProtocolVersion): String =
    when {
        v.major == 3 -> "HTTP/3"
        v.major == 2 -> "HTTP/2"
        else -> "HTTP/${v.major}.${v.minor}"
    }
