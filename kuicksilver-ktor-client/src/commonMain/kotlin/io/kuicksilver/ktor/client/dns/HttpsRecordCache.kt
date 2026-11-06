// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.client.dns

import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Deferred
import kotlinx.coroutines.Job
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.async
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull
import kotlin.random.Random
import kotlin.time.Duration

/**
 * The HTTPS records of query names, by the records' TTL: at most [MAX_NAMES] names, the least recently used dropped
 * first; a TTL is clamped to [MIN_TTL_S]..[MAX_TTL_S] seconds, and a name without records (NXDOMAIN, NODATA) is
 * remembered for [NEGATIVE_TTL_S] seconds. A failed lookup is never stored. Not thread-safe: [HttpsRecords] locks it.
 */
internal class HttpsRecordCache(
    private val nowMillis: () -> Long,
) {
    private class Entry(
        val records: List<SvcbRecord>,
        val expiresAt: Long,
    )

    private val map = LinkedHashMap<String, Entry>()

    val size: Int get() = map.size

    /** The fresh records of [name] (empty: known to have none), or null when nothing fresh is stored. */
    fun get(name: String): List<SvcbRecord>? {
        val e = map.remove(name) ?: return null
        if (nowMillis() >= e.expiresAt) return null
        map[name] = e
        return e.records
    }

    fun put(
        name: String,
        records: List<SvcbRecord>,
    ) {
        val ttl = if (records.isEmpty()) NEGATIVE_TTL_S else records.minOf { it.ttlSeconds }.coerceIn(MIN_TTL_S, MAX_TTL_S)
        map.remove(name)
        map[name] = Entry(records, nowMillis() + ttl * 1000)
        while (map.size > MAX_NAMES) map.remove(map.keys.first())
    }

    fun clear() = map.clear()

    companion object {
        const val MAX_NAMES = 1000
        const val MIN_TTL_S = 60L
        const val MAX_TTL_S = 86_400L
        const val NEGATIVE_TTL_S = 300L
    }
}

/** The outcome of SVCB resolution for one service (RFC 9460 section 3). */
internal sealed interface HttpsResolution {
    /** The endpoints to try in order (section 3, steps 4 and the appended AliasMode endpoint); never empty. */
    data class Endpoints(
        val endpoints: List<HttpsEndpoint>,
    ) : HttpsResolution

    /**
     * Connect as if the service had no SVCB record: there is none, none usable, an AliasMode "." (ignored, section 12),
     * a malformed RRset (section 2.2), or the chain-length limit or a loop was hit (section 3.1, MUST).
     */
    data object None : HttpsResolution

    /** A lookup failed (an error answer, a transport error or a timeout): section 3.1 decides what that means. */
    data object Failed : HttpsResolution
}

/**
 * The engine's HTTPS record lookups (RFC 9460 section 3, as an SVCB-optional client): [lookup] answers one name (null for
 * a failed lookup), each run in [scope] so an answer that comes after the request gave up is still cached for the next
 * one, bounded by [queryTimeout], and at most one per name at a time.
 */
internal class HttpsRecords(
    private val lookup: suspend (String) -> List<SvcbRecord>?,
    parent: CoroutineScope,
    private val queryTimeout: Duration,
    nowMillis: () -> Long,
    private val random: Random = Random,
) {
    /** The lookups' own job under [parent]: [close] cancels the ones still running, so they do not hold up a closing engine. */
    private val job = SupervisorJob(parent.coroutineContext[Job])
    private val scope = CoroutineScope(parent.coroutineContext + job)

    /** Cancels the lookups still running; callers waiting for them get no records. */
    fun close() = job.cancel()

    private val lock = Mutex()
    private val cache = HttpsRecordCache(nowMillis)
    private val inFlight = HashMap<String, Deferred<List<SvcbRecord>?>>()
    private var generation = 0L

    /** Called once a lookup's answer is settled (stored or not), with the name (tests). */
    internal var settledForTest: ((String) -> Unit)? = null

    /** Forgets every answer and drops the answers of lookups still running: they belong to the old network. */
    suspend fun onNetworkChanged() =
        lock.withLock {
            generation++
            cache.clear()
            inFlight.clear()
        }

    suspend fun cachedNames(): Int = lock.withLock { cache.size }

    /** The records of [name]: cached, or from a lookup (shared with other callers of the same name); null when it failed. */
    suspend fun records(name: String): List<SvcbRecord>? {
        val pending =
            lock.withLock {
                cache.get(name)?.let { return it }
                inFlight.getOrPut(name) { start(name, generation) }
            }
        return try {
            pending.await()
        } catch (e: CancellationException) {
            currentCoroutineContext().ensureActive() // the caller's own cancellation; else the engine's scope ended
            null
        }
    }

    private fun start(
        name: String,
        gen: Long,
    ): Deferred<List<SvcbRecord>?> =
        scope.async {
            var answer: List<SvcbRecord>? = null
            try {
                answer = withTimeoutOrNull(queryTimeout) { lookup(name) }
            } catch (e: CancellationException) {
                throw e
            } catch (_: Exception) {
                // a failed lookup: not stored, the next request asks again
            } finally {
                // also when cancelled (a timeout thrown inside the lookup, the engine closing): the name may be asked again
                withContext(NonCancellable) {
                    lock.withLock {
                        if (gen == generation) {
                            inFlight.remove(name)
                            answer?.let { cache.put(name, it) }
                        }
                    }
                }
                settledForTest?.invoke(name)
            }
            answer
        }

    /**
     * SVCB resolution of `https://host:port` (RFC 9460 sections 3 and 9.1) for a client that speaks [supported]:
     * $QNAME is [httpsQueryName]; an AliasMode record sets $QNAME to its TargetName, without prefix labels, and asks again
     * (step 3; one picked at random among several, section 2.4.2); the compatible ServiceMode records of the final RRset
     * become the endpoints ([serviceEndpoints]). When at least one AliasMode record was processed, the final $QNAME with
     * [port] and no SvcParams is appended (section 3, SHALL); without SvcParams its ALPN set is the default `http/1.1`
     * (section 9), so that endpoint is TCP only. An AliasMode "." is ignored (section 12, SHOULD). More than
     * [MAX_ALIASES] AliasMode steps or a name seen twice falls back to the authority as if there were no record
     * (section 3.1, MUST): [HttpsResolution.None].
     */
    suspend fun resolve(
        host: String,
        port: Int,
        supported: Set<String>,
    ): HttpsResolution {
        var name = httpsQueryName(host, port)
        val seen = hashSetOf(name)
        var aliased = false
        var aliases = 0
        while (true) {
            val rs = records(name) ?: return HttpsResolution.Failed
            val alias = aliasTarget(rs, random)
            if (alias == null || !isHostName(alias)) {
                // no AliasMode record, or one to "." (ignored): this RRset's ServiceMode records, if any (section 3, step 4)
                val endpoints = if (alias == null) serviceEndpoints(rs, port, supported, random) else emptyList()
                val all =
                    if (aliased) {
                        endpoints +
                            HttpsEndpoint(
                                name,
                                port,
                                quic = false,
                                tcp = HTTPS_DEFAULT_ALPN in supported,
                            )
                    } else {
                        endpoints
                    }
                val usable = all.filter { it.quic || it.tcp }
                return if (usable.isEmpty()) HttpsResolution.None else HttpsResolution.Endpoints(usable)
            }
            if (++aliases > MAX_ALIASES || !seen.add(alias)) return HttpsResolution.None
            aliased = true
            name = alias
        }
    }

    companion object {
        /** AliasMode steps followed at most (RFC 9460 sections 2.4.2 and 3.1: a limit, not zero, and loop detection). */
        const val MAX_ALIASES = 8
    }
}
