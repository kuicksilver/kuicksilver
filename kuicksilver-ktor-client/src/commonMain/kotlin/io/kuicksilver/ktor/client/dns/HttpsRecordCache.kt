// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.client.dns

import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Deferred
import kotlinx.coroutines.NonCancellable
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

/** An HTTP/3 endpoint from an HTTPS record: [host] (a DNS name) and the UDP [port]. */
internal data class HttpsEndpoint(
    val host: String,
    val port: Int,
)

/**
 * The engine's HTTPS record lookups (RFC 9460 section 3, as an SVCB-optional client): [lookup] answers one name (null for
 * a failed lookup), each run in [scope] so an answer that comes after the request gave up is still cached for the next
 * one, bounded by [queryTimeout], and at most one per name at a time.
 */
internal class HttpsRecords(
    private val lookup: suspend (String) -> List<SvcbRecord>?,
    private val scope: CoroutineScope,
    private val queryTimeout: Duration,
    nowMillis: () -> Long,
    private val random: Random = Random,
) {
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
     * The h3 endpoint the HTTPS records of `https://host:port` give (RFC 9460 sections 3 and 9.1): AliasMode records are
     * followed to their TargetName (at most [MAX_ALIASES] steps, a name seen twice ends the chain), then the ServiceMode
     * record [pickH3] chooses gives the endpoint, its `port` or [port]. Null when there is none, the chain ends in ".",
     * or a lookup failed.
     */
    suspend fun h3Endpoint(
        host: String,
        port: Int,
    ): HttpsEndpoint? {
        var name = httpsQueryName(host, port)
        val seen = HashSet<String>()
        var aliases = 0
        while (seen.add(name)) {
            val rs = records(name) ?: return null
            val alias = aliasTarget(rs, random)
            if (alias == null) {
                val r = pickH3(rs) ?: return null
                return HttpsEndpoint(r.serviceHost, r.port ?: port)
            }
            if (!isHostName(alias) || ++aliases > MAX_ALIASES) return null
            name = alias // the TargetName without prefix labels (section 3)
        }
        return null
    }

    companion object {
        /** AliasMode steps followed at most (RFC 9460 section 3.1 asks for a bound and loop detection). */
        const val MAX_ALIASES = 8
    }
}
