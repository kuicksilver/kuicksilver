// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.sample.compose

import io.ktor.client.HttpClient
import io.ktor.client.request.header
import io.ktor.client.request.prepareGet
import io.ktor.client.statement.HttpResponse
import io.ktor.client.statement.bodyAsChannel
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.http.contentLength
import io.ktor.utils.io.readAvailable
import io.kuicksilver.ktor.client.kuicksilverDiagnostics
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.delay
import kotlinx.coroutines.ensureActive
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.TimeSource

/** Byte [offset] of every `/bytes/{n}` body of the demo server: a pattern the client checks, so a resumed body is proven whole. */
fun patternByte(offset: Long): Byte = (offset % 251).toByte()

/** How a download ended. */
sealed interface DownloadResult {
    /** The bytes of the body received and checked, the resumed parts included. */
    val bytes: Long

    /** The whole body arrived; [resumes] Range requests after breaks, [restarts] of them answered from byte 0. */
    data class Completed(
        override val bytes: Long,
        val elapsedMs: Long,
        val protocol: String,
        val resumes: Int,
        val restarts: Int,
    ) : DownloadResult

    /** The download stopped at [bytes] with [error]. */
    data class Failed(
        override val bytes: Long,
        val elapsedMs: Long,
        val error: String,
        val resumes: Int,
    ) : DownloadResult
}

/** A parsed `Content-Range: bytes first-last/complete` (RFC 9110 section 14.4); [complete] is null for `*`. */
data class ContentRange(
    val first: Long,
    val last: Long,
    val complete: Long?,
)

/** `bytes first-last/complete`, the complete length may be `*`; null for anything else, the 416 form (no first-last) included. */
fun parseContentRange(value: String): ContentRange? {
    val spec = value.trim().takeIf { it.startsWith("bytes ") }?.removePrefix("bytes ")?.trim() ?: return null
    val range = spec.substringBefore('/')
    val first = range.substringBefore('-', "").toLongOrNull() ?: return null
    val last = range.substringAfter('-', "").toLongOrNull() ?: return null
    val complete = spec.substringAfter('/', "").let { if (it == "*") null else it.toLongOrNull() ?: return null }
    if (first < 0 || last < first || (complete != null && last >= complete)) return null
    return ContentRange(first, last, complete)
}

/** What [download] reports as the protocol of a response: Kuicksilver's diagnostics, else the engine's own version. */
fun HttpResponse.protocolText(): String = kuicksilverDiagnostics?.toString() ?: version.toString()

/** The body did not continue where the request asked, or did not match the pattern: never retried. */
private class BodyMismatch(
    message: String,
) : Exception(message)

/**
 * GET [url] (a `/bytes/{n}` URL of the demo server) and read its body, checking every byte against [patternByte]. When the
 * body breaks and [resume] is set, the download goes on with `Range: bytes=<received>-` up to [maxResumes] times — what
 * an app does with a TCP download after a network change, at the cost of a new connection; a server that answers the
 * Range request with the whole body (200) makes it start over from byte 0 ([DownloadResult.Completed.restarts]).
 * [onHead] gets each response's protocol and the time to its head since the start, [onProgress] the bytes received so
 * far and the body's size when known, [onEvent] one line per break and resume.
 */
suspend fun download(
    client: HttpClient,
    url: String,
    resume: Boolean,
    maxResumes: Int = 3,
    onHead: (protocol: String, elapsedMs: Long) -> Unit = { _, _ -> },
    onProgress: (received: Long, total: Long?) -> Unit = { _, _ -> },
    onEvent: (String) -> Unit = {},
): DownloadResult {
    val start = TimeSource.Monotonic.markNow()
    var received = 0L
    var total: Long? = null
    var resumes = 0
    var restarts = 0
    var protocol = "?"
    while (true) {
        val from = received
        try {
            client
                .prepareGet(url) {
                    if (from > 0) header(HttpHeaders.Range, "bytes=$from-")
                }.execute { r ->
                    protocol = r.protocolText()
                    when {
                        from > 0 && r.status == HttpStatusCode.PartialContent -> {
                            val cr =
                                r.headers[HttpHeaders.ContentRange]?.let(::parseContentRange)
                                    ?: throw BodyMismatch("206 without a usable Content-Range")
                            if (cr.first != from) throw BodyMismatch("asked for byte $from, Content-Range starts at ${cr.first}")
                            total = cr.complete ?: total
                        }

                        r.status == HttpStatusCode.OK -> {
                            if (from > 0) {
                                restarts++
                                received = 0
                                onEvent("the server ignored Range: starting over from byte 0")
                            }
                            total = r.contentLength() ?: total
                        }

                        else -> {
                            throw BodyMismatch("HTTP ${r.status.value}")
                        }
                    }
                    onHead(protocol, start.elapsedNow().inWholeMilliseconds)
                    onProgress(received, total)
                    val body = r.bodyAsChannel()
                    val buf = ByteArray(64 * 1024)
                    while (true) {
                        val n = body.readAvailable(buf, 0, buf.size)
                        if (n < 0) break
                        for (k in 0 until n) {
                            if (buf[k] != patternByte(received + k)) throw BodyMismatch("the body differs at offset ${received + k}")
                        }
                        received += n
                        onProgress(received, total)
                    }
                    body.closedCause?.let { throw it }
                }
            total?.let { if (received < it) throw BodyMismatch("the body ended at $received of $it bytes") }
            return DownloadResult.Completed(received, start.elapsedNow().inWholeMilliseconds, protocol, resumes, restarts)
        } catch (e: CancellationException) {
            // this download was cancelled (Stop, the screen closed): rethrown. Any other CancellationException is a
            // failure of the call (an engine that cancels its own job, a timeout in the transport): a result like any other
            currentCoroutineContext().ensureActive()
            return DownloadResult.Failed(received, start.elapsedNow().inWholeMilliseconds, describe(e), resumes)
        } catch (e: Throwable) {
            val error = describe(e)
            if (e is BodyMismatch || !resume || resumes >= maxResumes) {
                return DownloadResult.Failed(received, start.elapsedNow().inWholeMilliseconds, error, resumes)
            }
            resumes++
            onEvent("broke at $received bytes ($error); resuming with Range, attempt $resumes")
            // a back-off before the new connection: a network that just changed may not route yet
            delay((250 * resumes).milliseconds)
        }
    }
}

/** `Type: message (Cause: message)`, one line. */
fun describe(e: Throwable): String =
    buildString {
        append(e::class.simpleName ?: "Error")
        e.message?.let { append(": ").append(it) }
        e.cause?.takeIf { it !== e }?.let { c ->
            append(" (").append(c::class.simpleName)
            c.message?.let { append(": ").append(it) }
            append(')')
        }
    }
