// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(kotlinx.cinterop.ExperimentalForeignApi::class, io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)

package io.kuicksilver.ktor.client.pac

import io.ktor.client.HttpClient
import io.ktor.client.request.get
import io.ktor.client.statement.bodyAsChannel
import io.ktor.http.Url
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
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.IO
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull
import kotlinx.io.readByteArray
import platform.posix.fclose
import platform.posix.fopen
import platform.posix.fread
import kotlin.time.Duration.Companion.seconds

/** The most bytes a PAC script may have; a larger one is refused (Chromium's limit is 1 MiB too). */
internal const val PAC_MAX_SCRIPT_BYTES: Int = 1 shl 20

/**
 * PAC scripts by source, downloaded by the engine itself and kept: a script for [SCRIPT_TTL_MILLIS], a failed download
 * for [FAILURE_TTL_MILLIS] (so a missing script costs one attempt a minute, not one per request). `http:` and `https:`
 * URLs are fetched directly, never through a proxy (as browsers fetch them), with the engine's TLS and the platform's
 * trust, redirects followed; `file:` URLs are read from the file system; anything else, or a script larger than
 * [PAC_MAX_SCRIPT_BYTES], is a failure.
 */
internal object PacScripts {
    const val SCRIPT_TTL_MILLIS: Long = 30 * 60 * 1000L
    const val FAILURE_TTL_MILLIS: Long = 60 * 1000L

    private class Entry(
        val script: String?,
        val until: Long,
    )

    private val clock = monotonicMillis()
    private val lock = Mutex()
    private val cache = HashMap<String, Entry>()

    /** Tests: replaces the clock reading; null for the real one. */
    var nowForTest: (() -> Long)? = null

    private fun now(): Long = nowForTest?.invoke() ?: clock()

    /** Downloads made (tests). */
    var downloads: Int = 0
        private set

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

    /** The script at [url], from the cache or downloaded within [timeoutMillis]; null when it cannot be had. */
    suspend fun script(
        url: String,
        timeoutMillis: Long,
    ): String? {
        lock.withLock { cache[url]?.takeIf { it.until > now() }?.let { return it.script } }
        val script = withTimeoutOrNull(timeoutMillis) { download(url) }
        lock.withLock {
            cache[url] = Entry(script, now() + if (script != null) SCRIPT_TTL_MILLIS else FAILURE_TTL_MILLIS)
            if (cache.size > 64) cache.remove(cache.keys.first())
        }
        return script
    }

    /** Tests: forget every script. */
    suspend fun clearForTest() {
        lock.withLock { cache.clear() }
        downloads = 0
    }

    private suspend fun download(url: String): String? {
        downloads++
        val u = runCatching { Url(url) }.getOrNull() ?: return null
        return when (u.protocol.name) {
            "file" -> {
                withContext(Dispatchers.IO) { readFile(u.encodedPath.decodeURLPart()) }
            }

            "http", "https" -> {
                runCatching {
                    val r = client.get(u)
                    if (r.status.value != 200) return null
                    val bytes = r.bodyAsChannel().readBuffer(PAC_MAX_SCRIPT_BYTES + 1L).readByteArray()
                    if (bytes.size > PAC_MAX_SCRIPT_BYTES) null else bytes.decodeToString()
                }.getOrNull()
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
