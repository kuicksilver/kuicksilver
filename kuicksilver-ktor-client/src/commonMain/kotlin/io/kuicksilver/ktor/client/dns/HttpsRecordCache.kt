// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.client.dns

import io.kuicksilver.ktor.client.ExpiryClock
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Deferred
import kotlinx.coroutines.Job
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.async
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull
import kotlin.random.Random
import kotlin.time.Duration

/**
 * The HTTPS records of query names, and addresses of names, by their TTL (RFC 1035 section 3.2.1: the TTL "specifies the
 * time interval that the resource record may be cached"; capped at [MAX_TTL_S]), counted on an [ExpiryClock], so neither a
 * wall clock stepped back nor a device that slept keeps an entry longer. At most [MAX_NAMES] names and about [MAX_BYTES] bytes
 * each for records and addresses, the least recently used dropped first, and no RRset or address list over [MAX_RECORDS]:
 * the answers come over an untrusted channel (RFC 9460 section 9.2.2). A name without records (NXDOMAIN, NODATA) is remembered for the SOA's negative TTL (RFC 2308 section 5), and not
 * at all without one ("Negative responses without SOA records SHOULD NOT be cached"). A failed lookup is never stored.
 * Not thread-safe: [HttpsRecords] locks it.
 */
internal class HttpsRecordCache(
    private val clock: ExpiryClock,
) {
    private class Entry<T>(
        val value: T,
        val stored: ExpiryClock.Mark,
        val ttlMillis: Long,
        val bytes: Long,
    )

    /** One map of entries with the bytes they hold, least recently used first. */
    private class Store<T> {
        val map = LinkedHashMap<String, Entry<T>>()
        var bytes = 0L

        fun remove(name: String): Entry<T>? = map.remove(name)?.also { bytes -= it.bytes }

        fun put(
            name: String,
            e: Entry<T>,
        ) {
            remove(name)
            map[name] = e
            bytes += e.bytes
        }

        fun clear() {
            map.clear()
            bytes = 0
        }
    }

    private val records = Store<List<SvcbRecord>>()
    private val addresses = Store<List<ByteArray>>()

    val size: Int get() = records.map.size

    /** The bytes the entries hold, by [bytesOf] (tests). */
    internal val bytesForTest: Long get() = records.bytes + addresses.bytes

    /** The fresh records of [name] (empty: known to have none), or null when nothing fresh is stored. */
    fun get(name: String): List<SvcbRecord>? = records.fresh(name)

    /** The fresh A/AAAA addresses of [name] from an earlier answer's sections (RFC 9460 section 5), or null. */
    fun addressesOf(name: String): List<ByteArray>? = addresses.fresh(name)

    /**
     * Stores [records] for [name]; not an RRset over [MAX_RECORDS] records (a later request asks again: no more than
     * [MAX_ENDPOINTS] of it would be used anyway).
     */
    fun put(
        name: String,
        records: List<SvcbRecord>,
        negativeTtl: Long?,
    ) {
        if (records.size > MAX_RECORDS) {
            this.records.remove(name) // the answer is newer than what is stored
            return
        }
        val ttl = if (records.isEmpty()) negativeTtl ?: return else records.minOf { it.ttlSeconds }
        this.records.store(name, records, ttl, name.length + records.sumOf { bytesOf(it) })
    }

    /** Stores [list] for [name]; not over [MAX_RECORDS] addresses. */
    fun putAddresses(
        name: String,
        list: List<ByteArray>,
        ttl: Long,
    ) {
        if (list.size > MAX_RECORDS) {
            addresses.remove(name)
            return
        }
        addresses.store(name, list, ttl, name.length + list.sumOf { it.size.toLong() + ENTRY_OVERHEAD })
    }

    fun clear() {
        records.clear()
        addresses.clear()
    }

    private fun <T> Store<T>.fresh(name: String): T? {
        val e = remove(name) ?: return null
        if (clock.elapsedMillis(e.stored) >= e.ttlMillis) return null
        put(name, e)
        return e.value
    }

    private fun <T> Store<T>.store(
        name: String,
        value: T,
        ttlSeconds: Long,
        bytes: Long,
    ) {
        val ttl = ttlSeconds.coerceAtMost(MAX_TTL_S)
        remove(name)
        if (ttl <= 0) return
        put(name, Entry(value, clock.mark(), ttl * 1000, bytes))
        while (map.size > MAX_NAMES || this.bytes > MAX_BYTES) remove(map.keys.first())
    }

    companion object {
        const val MAX_NAMES = 1000
        const val MAX_TTL_S = 86_400L

        /** Records (or addresses) of one name stored at most: twice what a resolution uses ([MAX_ENDPOINTS]). */
        const val MAX_RECORDS = 2 * MAX_ENDPOINTS

        /**
         * Bytes the records, and the addresses, hold at most each, by the estimate of [bytesOf] (the objects' real overhead
         * is larger, so about this much); the least recently used go first.
         */
        const val MAX_BYTES = 1L shl 20

        /** What one record or address costs beyond its content: the objects that hold it. */
        private const val ENTRY_OVERHEAD = 64L

        /** About what [r] holds in memory: its strings, ALPN ids and hints, and [ENTRY_OVERHEAD]. */
        fun bytesOf(r: SvcbRecord): Long =
            ENTRY_OVERHEAD + r.target.length + r.owner.length + r.alpn.sumOf { it.length + 16L } +
                r.ipv4Hints.size * (4 + 16L) + r.ipv6Hints.size * (16 + 16L)
    }
}

/** How far a running resolution got: the endpoint RFC 9460 section 3 appends after an AliasMode record, if any. */
internal class AliasProgress {
    @kotlin.concurrent.Volatile
    var endpoint: HttpsEndpoint? = null
}

/** The outcome of SVCB resolution for one service (RFC 9460 section 3). */
internal sealed interface HttpsResolution {
    /** The endpoints to try in order (section 3, steps 4 and the appended AliasMode endpoint); never empty. */
    data class Endpoints(
        val endpoints: List<HttpsEndpoint>,
        /** A/AAAA addresses of endpoint names that came with the answers (RFC 9460 section 5), 4 or 16 bytes each. */
        val addresses: Map<String, List<ByteArray>> = emptyMap(),
    ) : HttpsResolution

    /**
     * Connect as if the service had no SVCB record: there is none, none usable, an AliasMode "." (ignored, section 12),
     * a malformed RRset (section 2.2), or the chain-length limit or a loop was hit (section 3.1, MUST).
     */
    data object None : HttpsResolution

    /**
     * A lookup failed (an error answer, a transport error or a timeout): section 3.1 decides what that means. When an
     * AliasMode record was processed before it, [aliasEndpoint] is the final $QNAME with the authority's port, which
     * section 3 appends "whether successful or not".
     */
    data class Failed(
        val aliasEndpoint: HttpsEndpoint? = null,
    ) : HttpsResolution
}

/**
 * The engine's HTTPS record lookups (RFC 9460 section 3, as an SVCB-optional client): [lookup] answers one name (null for
 * a failed lookup), each run in [scope] so an answer that comes after the request gave up is still cached for the next
 * one, bounded by [queryTimeout], and at most one per name at a time.
 */
internal class HttpsRecords(
    private val lookup: suspend (String) -> DnsAnswer?,
    parent: CoroutineScope,
    private val queryTimeout: Duration,
    /** The clock of the TTLs. */
    internal val clock: ExpiryClock,
    private val random: Random = Random,
    /**
     * Whether answers are kept by TTL: only where a network change is seen ([onNetworkChanged]), since RFC 9460 section 12
     * says "Clients MUST ensure that their DNS cache is partitioned for each local network, or flushed on network changes".
     * Without it every request asks the source (one lookup per name at a time still).
     */
    caching: Boolean = true,
) {
    /** [caching], until [stopCaching]; read and written under [lock]. */
    private var caching = caching

    /** The lookups' own job under [parent]: [close] cancels the ones still running, so they do not hold up a closing engine. */
    private val job = SupervisorJob(parent.coroutineContext[Job])
    private val scope = CoroutineScope(parent.coroutineContext + job)

    /** Cancels the lookups still running; callers waiting for them get no records. */
    fun close() = job.cancel()

    /**
     * Runs [block] in the lookups' scope: the address lookups that go with the records (the origin's, an alias target's),
     * which outlive the request's wait and end with [close] instead of holding up a closing engine.
     */
    fun background(block: suspend () -> Unit): Job = scope.launch { block() }

    private val lock = Mutex()
    private val cache = HttpsRecordCache(clock)
    private val inFlight = HashMap<String, Deferred<DnsAnswer?>>()
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

    /**
     * Drops the answers kept and keeps none from now on: the engine no longer sees network changes (the network source of
     * `connectionMigration` failed or ended), so RFC 9460 section 12 allows no cache.
     */
    suspend fun stopCaching() =
        lock.withLock {
            caching = false
            generation++
            cache.clear()
            inFlight.clear()
        }

    suspend fun cachedNames(): Int = lock.withLock { cache.size }

    private suspend fun cachedAddresses(name: String): List<ByteArray>? = lock.withLock { cache.addressesOf(name) }

    /** The records of [name]: cached, or from a lookup (shared with other callers of the same name); null when it failed. */
    suspend fun records(name: String): List<SvcbRecord>? = answer(name)?.records

    /** [records] with the rest of the answer ([DnsAnswer]); a cached answer has its records only. */
    private suspend fun answer(name: String): DnsAnswer? {
        val pending =
            lock.withLock {
                cache.get(name)?.let { return DnsAnswer(it) }
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
    ): Deferred<DnsAnswer?> =
        scope.async {
            var answer: DnsAnswer? = null
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
                            val a = answer
                            if (caching && a != null) {
                                cache.put(name, a.records, a.negativeTtl)
                                // RFC 9460 section 5: other RRsets and addresses of the answer go to the cache as well, those
                                // in the query's bailiwick only: another zone's data serves this resolution, not later ones
                                for ((owner, rs) in a.related) if (rs.isNotEmpty() && a.inBailiwick(owner)) cache.put(owner, rs, null)
                                for ((owner, ad) in a.addresses) if (a.inBailiwick(owner)) cache.putAddresses(owner, ad.first, ad.second)
                            }
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
        // the endpoint section 3 appends, as far as the chain got: for a resolution that is cut short (the extra wait)
        progress: AliasProgress = AliasProgress(),
        // a name the next query will ask for, whose A/AAAA may be looked up meanwhile (section 5, speculative queries)
        prefetch: (String) -> Unit = {},
    ): HttpsResolution {
        var name = httpsQueryName(host, port)
        // a name that cannot be asked (a Unicode host) has no SVCB resolution at all: as without records, and no failed
        // lookup either, which a secure source would turn into an abandoned request (section 3.1)
        if (!DnsMessage.isAskable(name)) return HttpsResolution.None
        val seen = hashSetOf(name)
        var aliased = false
        var aliases = 0
        // what earlier answers of this resolution carried, used before any follow-up query (section 5)
        val related = HashMap<String, List<SvcbRecord>>()
        val addresses = HashMap<String, List<ByteArray>>()
        while (true) {
            val a =
                related[name]?.let { DnsAnswer(it) } ?: answer(name) ?: return HttpsResolution.Failed(progress.endpoint)
            for ((owner, rs) in a.related) if (rs.isNotEmpty()) related.getOrPut(owner) { rs }
            for ((owner, ad) in a.addresses) addresses.getOrPut(owner) { ad.first }
            val rs = a.records
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
                if (usable.isEmpty()) return HttpsResolution.None
                val known =
                    usable
                        .map { it.host }
                        .distinct()
                        .mapNotNull { h ->
                            (addresses[h] ?: cachedAddresses(h))?.let { h to it }
                        }.toMap()
                return HttpsResolution.Endpoints(usable, known)
            }
            if (++aliases > MAX_ALIASES || !seen.add(alias)) {
                progress.endpoint = null // section 3.1: the chain limit falls back to the authority, as if there were no record
                return HttpsResolution.None
            }
            aliased = true
            name = alias
            progress.endpoint = HttpsEndpoint(name, port, quic = false, tcp = HTTPS_DEFAULT_ALPN in supported).takeIf { it.tcp }
            // the alias target is the likely TargetName ("." in its ServiceMode records) and the appended endpoint's name
            if (name !in addresses) prefetch(name)
        }
    }

    /**
     * Whether an `http` request must go to `https://host:port` instead (RFC 9460 section 9.5): the HTTPS RRset of that
     * URL's query name has an AliasMode record (one to "." is ignored, section 12) or a compatible ServiceMode record
     * (section 8; one whose ALPN set has nothing in [supported] cannot be connected to, so it is not compatible). Null
     * when the lookup failed.
     */
    suspend fun upgradesToHttps(
        host: String,
        port: Int,
        supported: Set<String>,
    ): Boolean? {
        val name = httpsQueryName(host, port)
        if (!DnsMessage.isAskable(name)) return false // as in [resolve]
        val rs = records(name) ?: return null
        val alias = aliasTarget(rs, random)
        return if (alias != null) isHostName(alias) else serviceEndpoints(rs, port, supported, random).isNotEmpty()
    }

    companion object {
        /** AliasMode steps followed at most (RFC 9460 sections 2.4.2 and 3.1: a limit, not zero, and loop detection). */
        const val MAX_ALIASES = 8
    }
}
