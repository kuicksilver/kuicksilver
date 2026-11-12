// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.client

import io.kuicksilver.ktor.client.dns.DnsAnswer
import io.kuicksilver.ktor.client.dns.DnsMessage
import io.kuicksilver.ktor.client.dns.httpsRecordsOf
import io.kuicksilver.tls.KslDns
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlin.time.Duration

/** The OS resolver through ksl (`ksl_dns_query`): res_nquery on Linux, DNSServiceQueryRecord on Apple, DnsQuery_W on Windows. */
@OptIn(io.kuicksilver.annotations.InternalKuicksilverApi::class)
internal actual suspend fun platformHttpsQuery(
    name: String,
    timeout: Duration,
): DnsAnswer? {
    val answer = KslDns.query(name, DnsMessage.TYPE_HTTPS, timeout) ?: return null
    val context = currentCoroutineContext()
    return httpsRecordsOf(answer, name) { context.ensureActive() } // a timeout or cancellation stops the read
}

/** RFC 7050 discovery through the OS resolver (`ksl_dns_query`), with the records' TTLs. */
@OptIn(io.kuicksilver.annotations.InternalKuicksilverApi::class)
internal actual suspend fun platformAddressQuery(
    name: String,
    type: Int,
    timeout: Duration,
): AddressRecords? = KslDns.query(name, type, timeout)?.let { addressRecordsOf(it, name, type) }
