// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(
    kotlinx.cinterop.ExperimentalForeignApi::class,
    io.kuicksilver.annotations.ExperimentalKuicksilverApi::class,
    kotlin.concurrent.atomics.ExperimentalAtomicApi::class,
)

package io.kuicksilver.ktor.client.pac

import io.ktor.client.HttpClient
import io.ktor.client.request.prepareGet
import io.ktor.client.statement.bodyAsChannel
import io.ktor.http.Url
import io.ktor.http.contentLength
import io.ktor.http.decodeURLPart
import io.ktor.utils.io.readBuffer
import io.kuicksilver.ktor.client.Http3DiscoveryMode
import io.kuicksilver.ktor.client.Kuicksilver
import io.kuicksilver.ktor.client.PAC_TIMEOUT_MILLIS
import io.kuicksilver.ktor.client.ProxyResolvers
import io.kuicksilver.ktor.client.h1.monotonicMillis
import kotlinx.cinterop.ByteVar
import kotlinx.cinterop.allocArray
import kotlinx.cinterop.convert
import kotlinx.cinterop.memScoped
import kotlinx.cinterop.readBytes
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Deferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.GlobalScope
import kotlinx.coroutines.IO
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.async
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull
import kotlinx.io.readByteArray
import platform.posix.fclose
import platform.posix.fopen
import platform.posix.fread
import kotlin.concurrent.atomics.AtomicInt
import kotlin.concurrent.atomics.incrementAndFetch
import kotlin.time.Duration.Companion.seconds

/** The most bytes a PAC script may have; a larger one is refused (Chromium's limit is 1 MiB too). */
internal const val PAC_MAX_SCRIPT_BYTES: Int = 1 shl 20

/**
 * PAC scripts by source, downloaded by the engine itself and kept: a script for [SCRIPT_TTL_MILLIS], a failed or
 * timed-out download for [FAILURE_TTL_MILLIS] (so a missing or hanging script costs one attempt a minute, not one per
 * request). Lookups of a URL whose download is under way wait for that download (one per URL at a time). `http:` and
 * `https:` URLs are fetched directly, never through a proxy (as browsers fetch them), with the engine's TLS and the
 * platform's trust, redirects followed, and the body read only up to [PAC_MAX_SCRIPT_BYTES] (a larger Content-Length is
 * refused before the body); `file:` URLs are read from the file system when [script]'s `allowFile`; anything else, or a
 * larger script, is a failure.
 */
internal object PacScripts {
    const val SCRIPT_TTL_MILLIS: Long = 30 * 60 * 1000L
    const val FAILURE_TTL_MILLIS: Long = 60 * 1000L

    private class Entry(
        val script: String?,
        val until: Long,
    )

    /** A download under way and the lookups waiting for it. */
    private class Flight {
        lateinit var job: Deferred<String?>
        var waiters = 0
    }

    private val clock = monotonicMillis()
    private val lock = Mutex()
    private val cache = HashMap<String, Entry>()
    private val inFlight = HashMap<String, Flight>()
    private val downloadCount = AtomicInt(0)
    private val waiting = MutableStateFlow(0)

    /** Lookups waiting for a download (tests). */
    val waitingForTest: StateFlow<Int> get() = waiting

    /** Tests: whether a script (true) or a failure (false) is cached for [url], null when nothing is. */
    suspend fun cachedForTest(url: String): Boolean? = lock.withLock { cache[url]?.takeIf { it.until > now() }?.let { it.script != null } }

    /** Tests: replaces the clock reading; null for the real one. */
    var nowForTest: (() -> Long)? = null

    private fun now(): Long = nowForTest?.invoke() ?: clock()

    /** Downloads started (tests). */
    val downloads: Int get() = downloadCount.load()

    private val client by lazy {
        HttpClient(Kuicksilver) {
            expectSuccess = false
            followRedirects = true
            engine {
                proxyResolver = ProxyResolvers.None // a PAC script is fetched directly
                http3 { discovery = Http3DiscoveryMode.H1Only }
                connectTimeout = (PAC_TIMEOUT_MILLIS / 1000).seconds
            }
        }
    }

    /**
     * The script at [url], from the cache or downloaded within [timeoutMillis]; null when it cannot be had. Lookups of a
     * URL whose download is under way wait for that one. The download records its own outcome: a script, or a failure
     * when it failed or ran out of the first lookup's time. A lookup that runs out of its own time stops waiting, and
     * when it was the last one waiting gives the download up and records a failure (a script that hangs costs one
     * attempt a minute). A lookup that is cancelled only stops waiting (the last one gives the download up) and records
     * nothing; a lookup whose shared download was given up gets null.
     */
    @OptIn(kotlinx.coroutines.DelicateCoroutinesApi::class)
    suspend fun script(
        url: String,
        timeoutMillis: Long,
        allowFile: Boolean = true,
    ): String? {
        if (!allowFile && !url.startsWith("http://", ignoreCase = true) && !url.startsWith("https://", ignoreCase = true)) return null
        val flight =
            lock.withLock {
                cache[url]?.takeIf { it.until > now() }?.let { return it.script }
                (
                    inFlight[url] ?: Flight().also { f ->
                        f.job =
                            GlobalScope.async(Dispatchers.IO) {
                                val script = withTimeoutOrNull(timeoutMillis) { download(url) }
                                // a download given up (cancelled) records nothing; one that ended or timed out does
                                withContext(NonCancellable) {
                                    lock.withLock {
                                        record(url, script)
                                        if (inFlight[url] === f) inFlight.remove(url)
                                    }
                                }
                                script
                            }
                        inFlight[url] = f
                        downloadCount.incrementAndFetch()
                    }
                ).also { it.waiters++ }
            }
        waiting.update { it + 1 }
        var timedOut = false
        try {
            val answer = withTimeoutOrNull(timeoutMillis) { flight.job.await() }
            if (answer == null && !flight.job.isCompleted) timedOut = true
            return answer
        } catch (e: CancellationException) {
            currentCoroutineContext().ensureActive() // this lookup was cancelled: it stops
            return null // the shared download was given up: no script
        } finally {
            waiting.update { it - 1 }
            withContext(NonCancellable) {
                lock.withLock {
                    flight.waiters--
                    if (flight.waiters == 0 && !flight.job.isCompleted) {
                        flight.job.cancel()
                        if (inFlight[url] === flight) inFlight.remove(url)
                        if (timedOut) record(url, null)
                    }
                }
            }
        }
    }

    /** Under [lock]: [script], or a failure when null, for [url]. */
    private fun record(
        url: String,
        script: String?,
    ) {
        cache[url] = Entry(script, now() + if (script != null) SCRIPT_TTL_MILLIS else FAILURE_TTL_MILLIS)
        if (cache.size > 64) cache.remove(cache.keys.first())
    }

    /** Tests: forget every script. */
    suspend fun clearForTest() {
        lock.withLock {
            cache.clear()
            inFlight.clear()
        }
        downloadCount.store(0)
    }

    private suspend fun download(url: String): String? {
        val u = runCatching { Url(url) }.getOrNull() ?: return null
        return when (u.protocol.name) {
            "file" -> {
                readFile(u.encodedPath.decodeURLPart())
            }

            "http", "https" -> {
                try {
                    client.prepareGet(u).execute { r ->
                        if (r.status.value != 200) return@execute null
                        // a declared length above the cap is refused before the body is read
                        if ((r.contentLength() ?: 0L) > PAC_MAX_SCRIPT_BYTES) return@execute null
                        val bytes = r.bodyAsChannel().readBuffer(PAC_MAX_SCRIPT_BYTES + 1L).readByteArray()
                        if (bytes.size > PAC_MAX_SCRIPT_BYTES) null else bytes.decodeToString()
                    }
                } catch (e: CancellationException) {
                    throw e
                } catch (e: Exception) {
                    null
                }
            }

            else -> {
                null
            }
        }
    }

    private fun readFile(path: String): String? {
        val f = fopen(path, "rb") ?: return null
        try {
            memScoped {
                val buf = allocArray<ByteVar>(PAC_MAX_SCRIPT_BYTES + 1)
                val n = fread(buf, 1u, (PAC_MAX_SCRIPT_BYTES + 1).convert(), f).toInt()
                if (n > PAC_MAX_SCRIPT_BYTES) return null
                return buf.readBytes(n).decodeToString()
            }
        } finally {
            fclose(f)
        }
    }
}
