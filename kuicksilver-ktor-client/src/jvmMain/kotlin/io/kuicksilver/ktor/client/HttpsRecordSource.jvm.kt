// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.client

import io.kuicksilver.ktor.client.dns.DnsAnswer
import io.kuicksilver.ktor.client.dns.DnsMessage
import io.kuicksilver.ktor.client.dns.httpsRecordsOf
import io.kuicksilver.tls.KslDns
import kotlin.time.Duration

/** The OS resolver through ksl (`ksl_dns_query`): res_nquery on Linux, DNSServiceQueryRecord on Apple, DnsQuery_W on Windows. */
@OptIn(io.kuicksilver.annotations.InternalKuicksilverApi::class)
internal actual suspend fun platformHttpsQuery(
    name: String,
    timeout: Duration,
): DnsAnswer? = KslDns.query(name, DnsMessage.TYPE_HTTPS, timeout)?.let { httpsRecordsOf(it, name) }
