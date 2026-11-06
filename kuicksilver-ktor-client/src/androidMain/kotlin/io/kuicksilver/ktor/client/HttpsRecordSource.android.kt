// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.client

import android.annotation.TargetApi
import android.net.DnsResolver
import android.os.Build
import android.os.CancellationSignal
import io.kuicksilver.ktor.client.dns.DnsException
import io.kuicksilver.ktor.client.dns.DnsMessage
import io.kuicksilver.ktor.client.dns.SvcbRecord
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.withTimeoutOrNull
import java.util.concurrent.Executor
import kotlin.coroutines.resume
import kotlin.time.Duration

/**
 * Android: `DnsResolver.rawQuery` on the default network (API 29 and up), so the lookup goes through the system's resolver
 * and its Private DNS setting. Below API 29 there is no public way to ask for a record type, and a resolver of our own
 * reading `LinkProperties.dnsServers` would bypass Private DNS: every lookup counts as failed there.
 */
internal actual suspend fun platformHttpsQuery(
    name: String,
    timeout: Duration,
): List<SvcbRecord>? = if (Build.VERSION.SDK_INT < 29) null else withTimeoutOrNull(timeout) { rawQuery(name) }

/** The callback runs on the resolver's own thread: parsing an answer is short and needs no other executor. */
private val direct = Executor { it.run() }

@TargetApi(29)
private suspend fun rawQuery(name: String): List<SvcbRecord>? =
    suspendCancellableCoroutine { cont ->
        val cancel = CancellationSignal()
        cont.invokeOnCancellation { cancel.cancel() }
        DnsResolver.getInstance().rawQuery(
            null, // the default network
            name,
            DnsResolver.CLASS_IN,
            DnsMessage.TYPE_HTTPS,
            DnsResolver.FLAG_EMPTY,
            direct,
            cancel,
            object : DnsResolver.Callback<ByteArray> {
                override fun onAnswer(
                    answer: ByteArray,
                    rcode: Int,
                ) {
                    val records =
                        try {
                            DnsMessage.answers(answer, name)
                        } catch (_: DnsException) {
                            null
                        }
                    if (cont.isActive) cont.resume(records)
                }

                override fun onError(error: DnsResolver.DnsException) {
                    if (cont.isActive) cont.resume(null)
                }
            },
        )
    }
