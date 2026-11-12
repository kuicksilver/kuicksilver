// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.client

import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.ktor.client.dns.DnsAnswer
import io.kuicksilver.ktor.client.dns.DnsException
import io.kuicksilver.ktor.client.dns.DnsMessage
import io.kuicksilver.ktor.client.dns.SvcbMalformedException
import io.kuicksilver.ktor.client.dns.SvcbRecord
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
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
     * The operating system's resolver, as [System], whose answers are cryptographically protected whenever [isProtected][HttpsRecordSource.ProtectedSystem.isProtected]
     * says so: then a failed lookup abandons the request (RFC 9460 section 3.1), as with `Exchange(secure = true)`.
     * Called once per request, on the call's coroutine; it must be quick, and one that throws counts as false. On Android
     * `HttpsRecordSource.followingPrivateDns(connectivity)` builds one that reports Android's strict Private DNS (DNS over
     * TLS with a configured server). On Apple platforms, Linux and Windows no public API tells whether the system's DNS is
     * encrypted: give a check of your own (an MDM profile you deploy, say) or use [System].
     */
    public class ProtectedSystem(
        /** Whether the system resolver's answers are cryptographically protected now. */
        public val isProtected: () -> Boolean,
    ) : HttpsRecordSource

    /**
     * Lookups through [exchange][HttpsRecordSource.Exchange.exchange]: it gets a DNS query in wire format (RFC 1035 section 4.1, ID 0 and RD set, as RFC 8484
     * section 4.1 asks for DNS over HTTPS) and returns the response in wire format, for example the body of a POST to a
     * DoH server with `Content-Type: application/dns-message`. The engine has no DoH client of its own. An exchange that
     * throws, or returns something that is not the response to the query, counts as a failed lookup; so does a response
     * over 65535 bytes (RFC 8484 section 6: "This media type restricts the maximum size of the DNS message to 65535
     * bytes").
     *
     * The engine checks that the response answers the question it asked, but not its ID: every query has ID 0, so the
     * exchange must tie a response to its query itself, which is what the ID is for: it "can be used by the requester to
     * match up replies to outstanding queries" (RFC 1035 section 4.1.1). DNS over HTTPS does (the response is the one to its HTTP
     * request), and so does DNS over TLS that matches responses to queries. An exchange over plain UDP or TCP must not
     * send ID 0 as is: it sets a random ID of its own in the query (bytes 0 and 1), accepts only a response with that
     * ID from the server it asked, and may hand it back with either ID; otherwise an off-path attacker who guesses the
     * question can forge the answer.
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

    /** Builders of sources; on Android also `followingPrivateDns`. */
    public companion object
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
): DnsAnswer?

/** Whether this source's answers are cryptographically protected now (RFC 9460 section 3.1); read once per request. */
@OptIn(ExperimentalKuicksilverApi::class)
internal fun HttpsRecordSource.isSecure(): Boolean =
    when (this) {
        is HttpsRecordSource.Exchange -> {
            secure
        }

        is HttpsRecordSource.ProtectedSystem -> {
            try {
                isProtected()
            } catch (e: CancellationException) {
                throw e
            } catch (_: Exception) {
                false
            }
        }

        else -> {
            false
        }
    }

/** The lookup function of this source, or null for [HttpsRecordSource.Off]: null from it is a failed lookup. */
@OptIn(ExperimentalKuicksilverApi::class)
internal fun HttpsRecordSource.lookup(timeout: Duration): (suspend (String) -> DnsAnswer?)? =
    when (this) {
        HttpsRecordSource.Off -> {
            null
        }

        HttpsRecordSource.System, is HttpsRecordSource.ProtectedSystem -> {
            { platformHttpsQuery(it, timeout) }
        }

        is HttpsRecordSource.Exchange -> {
            { name ->
                try {
                    val response = exchange(DnsMessage.query(name))
                    // the read checks the coroutine: the lookup's timeout stops it, however long the answer
                    val context = currentCoroutineContext()
                    DnsMessage.read(response, name) { context.ensureActive() }
                } catch (e: CancellationException) {
                    throw e
                } catch (_: SvcbMalformedException) {
                    DnsAnswer(emptyList()) // RFC 9460 section 2.2: the RRset is rejected, the connection goes on without SVCB
                } catch (_: DnsException) {
                    null
                } catch (_: Exception) {
                    null // the application's exchange failed: a failed lookup, as a resolver error would be
                }
            }
        }

        is HttpsRecordsForTest -> {
            { name -> fn(name)?.let { DnsAnswer(it) } }
        }
    }
