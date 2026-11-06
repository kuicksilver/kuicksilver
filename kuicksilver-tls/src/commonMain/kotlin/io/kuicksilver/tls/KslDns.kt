// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(InternalKuicksilverApi::class)

package io.kuicksilver.tls

import io.kuicksilver.annotations.InternalKuicksilverApi
import io.kuicksilver.native.Ksl
import io.kuicksilver.native.KslConst
import io.kuicksilver.native.KslLoader
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.IO
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.async
import kotlinx.coroutines.sync.Semaphore
import kotlinx.coroutines.withTimeoutOrNull
import kotlin.time.Duration

/** An answer of [KslDns.query]. */
@InternalKuicksilverApi
public sealed interface KslDnsAnswer {
    /** The whole DNS response, as the resolver received it (Linux). */
    public class Message(
        /** The message in wire format (RFC 1035 section 4.1). */
        public val bytes: ByteArray,
    ) : KslDnsAnswer

    /** The records of the answer, without the message around them (Apple, Windows); empty for NXDOMAIN and NODATA. */
    public class Records(
        /** The records, in the resolver's order. */
        public val records: List<Record>,
    ) : KslDnsAnswer

    /** One resource record of [Records]. */
    public class Record(
        /** The owner name in presentation format, without a final dot (after CNAMEs, the name the record belongs to). */
        public val owner: String,
        /** The record's TTL in seconds. */
        public val ttlSeconds: Long,
        /** The RDATA in wire format. */
        public val rdata: ByteArray,
    )
}

/**
 * The operating system's resolver for one record type (`ksl_dns_query`): `res_nquery` on Linux, `DNSServiceQueryRecord`
 * on Apple platforms, `DnsQuery_W` on Windows. Not on Android (`DnsResolver` is asked there): every query answers null.
 * At most [MAX_CONCURRENT] lookups run at once in the process; a caller beyond that waits for one to end, so a resolver
 * that hangs ties up at most that many threads.
 */
@InternalKuicksilverApi
public object KslDns {
    /** Lookups running at once, at most. */
    public const val MAX_CONCURRENT: Int = 4

    private val slots = Semaphore(MAX_CONCURRENT)
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

    /** Replaces the native call (tests): the same arguments and answer as `Ksl.dnsQuery`. */
    internal var queryForTest: ((name: String, type: Int, server: ByteArray?, timeoutMs: Int) -> ByteArray?)? = null

    /**
     * The records of type [type] of [name] within [timeout]: [KslDnsAnswer.Records] empty when there are none, null when the
     * lookup failed, timed out or cannot be made here. [server] (`KslConst.UDP_ADDR_LEN` bytes) asks that resolver instead of
     * the system's (tests; Linux IPv4, Windows IPv4 on port 53). The blocking call runs on [Dispatchers.IO]; a caller that
     * stops waiting (its timeout, its cancellation) leaves it to end on its own (Windows takes no timeout), still counted
     * against [MAX_CONCURRENT].
     */
    public suspend fun query(
        name: String,
        type: Int,
        timeout: Duration,
        server: ByteArray? = null,
    ): KslDnsAnswer? {
        val ms = timeout.inWholeMilliseconds.coerceIn(1, Int.MAX_VALUE.toLong()).toInt()
        val call = queryForTest ?: { n, t, s, m -> KslLoader.ensureLoaded().let { Ksl.dnsQuery(n, t, s, m) } }
        slots.acquire()
        // no suspension between acquire and async: the permit always goes back when the lookup ends
        val lookup =
            scope.async {
                try {
                    call(name, type, server, ms)
                } catch (e: Throwable) {
                    // the native library could not be loaded, or is one without the call (UnsatisfiedLinkError): no answer
                    if (e !is Exception && !isLinkageError(e)) throw e
                    null
                } finally {
                    slots.release()
                }
            }
        val raw = withTimeoutOrNull(timeout) { lookup.await() } ?: return null
        return decode(raw)
    }

    /** The lookups running now (tests). */
    internal val inFlightForTest: Int get() = MAX_CONCURRENT - slots.availablePermits

    internal fun decode(raw: ByteArray): KslDnsAnswer? {
        if (raw.isEmpty()) return KslDnsAnswer.Records(emptyList())
        return when (raw[0].toInt()) {
            KslConst.DNS_MESSAGE -> {
                KslDnsAnswer.Message(raw.copyOfRange(1, raw.size))
            }

            KslConst.DNS_RECORDS -> {
                val out = ArrayList<KslDnsAnswer.Record>()
                var p = 1
                while (p < raw.size) {
                    if (raw.size - p < 5) return null
                    val ttl = (0 until 4).fold(0L) { v, i -> v shl 8 or (raw[p + i].toLong() and 0xff) }
                    val ol = raw[p + 4].toInt() and 0xff
                    p += 5
                    if (raw.size - p < ol + 2) return null
                    val owner = CharArray(ol) { (raw[p + it].toInt() and 0xff).toChar() }.concatToString()
                    p += ol
                    val rl = (raw[p].toInt() and 0xff) shl 8 or (raw[p + 1].toInt() and 0xff)
                    p += 2
                    if (raw.size - p < rl) return null
                    out += KslDnsAnswer.Record(owner, ttl, raw.copyOfRange(p, p + rl))
                    p += rl
                }
                KslDnsAnswer.Records(out)
            }

            else -> {
                null
            }
        }
    }
}

/** Whether [e] says native code could not be linked (the JVM's LinkageError: UnsatisfiedLinkError and the like). */
internal expect fun isLinkageError(e: Throwable): Boolean
