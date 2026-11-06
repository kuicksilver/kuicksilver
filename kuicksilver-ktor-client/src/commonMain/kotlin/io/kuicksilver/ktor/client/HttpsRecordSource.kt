// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.client

import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.ktor.client.dns.DnsException
import io.kuicksilver.ktor.client.dns.DnsMessage
import io.kuicksilver.ktor.client.dns.SvcbMalformedException
import io.kuicksilver.ktor.client.dns.SvcbRecord
import kotlinx.coroutines.CancellationException
import kotlin.time.Duration

/**
 * Where the client engine looks up HTTPS resource records (RFC 9460) for an origin in [Http3DiscoveryMode.Auto]
 * ([Http3ClientConfig.httpsRecords]; docs/guide/ktor.md, "HTTPS records"). A record that names `h3` in its `alpn` lets the
 * first request to the origin race HTTP/3 against TCP at once, without waiting for an `Alt-Svc` header. The engine is an
 * SVCB-optional client (RFC 9460 section 3): a lookup that fails or answers late leaves the request on the path it would
 * have taken without records.
 */
@ExperimentalKuicksilverApi
public sealed interface HttpsRecordSource {
    /** No lookups (the default): HTTP/3 is learned from `Alt-Svc` only, as before 0.3.0. */
    public data object Off : HttpsRecordSource

    /**
     * The operating system's resolver, so the lookups follow the system's DNS settings (Private DNS on Android, the
     * scoped resolvers of macOS and iOS). Android asks `DnsResolver.rawQuery` from API 29; below API 29, and on platforms
     * where the system resolver cannot be asked for HTTPS records yet, every lookup counts as failed and requests behave as
     * with [Off] (docs/guide/ktor.md lists the platforms).
     */
    public data object System : HttpsRecordSource

    /**
     * Lookups through [exchange]: it gets a DNS query in wire format (RFC 1035 section 4.1, ID 0 and RD set, as RFC 8484
     * section 4.1 asks for DNS over HTTPS) and returns the response in wire format, for example the body of a POST to a
     * DoH server with `Content-Type: application/dns-message`. The engine has no DoH client of its own. An exchange that
     * throws, or returns something that is not the response to the query, counts as a failed lookup.
     */
    public class Exchange(
        /**
         * Whether the exchange's answers are cryptographically protected (DNS over HTTPS or TLS, or DNSSEC-validated). Then
         * a resolution that fails (an error answer such as SERVFAIL, a transport error, a timeout) abandons the request
         * instead of going on without records, as RFC 9460 section 3.1 asks, so an active attacker who drops the answers
         * cannot downgrade the connection; the request also waits for the answer (up to the connect timeout, 30 s at most)
         * instead of [Http3ClientConfig.httpsRecordExtraWait]. False (the default) treats failures as "no records".
         */
        public val secure: Boolean = false,
        /** Sends one DNS query and returns its response. */
        public val exchange: suspend (query: ByteArray) -> ByteArray,
    ) : HttpsRecordSource
}

/** Tests: lookups answered by [fn] (null for a failed lookup, empty for none). */
@OptIn(ExperimentalKuicksilverApi::class)
internal class HttpsRecordsForTest(
    val fn: suspend (name: String) -> List<SvcbRecord>?,
) : HttpsRecordSource

/**
 * The HTTPS records of [name] from the system resolver within [timeout]: empty when there are none (NXDOMAIN, NODATA),
 * null when the lookup failed or this platform cannot ask for them.
 */
internal expect suspend fun platformHttpsQuery(
    name: String,
    timeout: Duration,
): List<SvcbRecord>?

/** Whether this source's answers are cryptographically protected (RFC 9460 section 3.1). */
@OptIn(ExperimentalKuicksilverApi::class)
internal val HttpsRecordSource.secure: Boolean get() = this is HttpsRecordSource.Exchange && secure

/** The lookup function of this source, or null for [HttpsRecordSource.Off]: null from it is a failed lookup. */
@OptIn(ExperimentalKuicksilverApi::class)
internal fun HttpsRecordSource.lookup(timeout: Duration): (suspend (String) -> List<SvcbRecord>?)? =
    when (this) {
        HttpsRecordSource.Off -> {
            null
        }

        HttpsRecordSource.System -> {
            { platformHttpsQuery(it, timeout) }
        }

        is HttpsRecordSource.Exchange -> {
            { name ->
                try {
                    DnsMessage.answers(exchange(DnsMessage.query(name)), name)
                } catch (e: CancellationException) {
                    throw e
                } catch (_: SvcbMalformedException) {
                    emptyList() // RFC 9460 section 2.2: the RRset is rejected, the connection goes on without SVCB
                } catch (_: DnsException) {
                    null
                } catch (_: Exception) {
                    null // the application's exchange failed: a failed lookup, as a resolver error would be
                }
            }
        }

        is HttpsRecordsForTest -> {
            fn
        }
    }
