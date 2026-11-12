// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.client

import android.annotation.TargetApi
import android.net.DnsResolver
import android.os.Build
import android.os.CancellationSignal
import io.kuicksilver.ktor.client.dns.DnsAnswer
import io.kuicksilver.ktor.client.dns.DnsMessage
import io.kuicksilver.ktor.client.dns.httpsRecordsOf
import io.kuicksilver.tls.KslDnsAnswer
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.asExecutor
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
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
@OptIn(io.kuicksilver.annotations.InternalKuicksilverApi::class)
internal actual suspend fun platformHttpsQuery(
    name: String,
    timeout: Duration,
): DnsAnswer? =
    if (Build.VERSION.SDK_INT < 29) {
        null
    } else {
        withTimeoutOrNull(timeout) {
            val answer = rawQuery(name) ?: return@withTimeoutOrNull null
            // read here, not in the callback: the read checks this coroutine, so the timeout stops it however long the answer
            val context = currentCoroutineContext()
            httpsRecordsOf(KslDnsAnswer.Message(answer), name) { context.ensureActive() }
        }
    }

/**
 * Where DnsResolver runs the callback, which hands the answer on: a background thread. DnsResolver posts its callbacks
 * from the main Looper, so a direct executor would run it there, and a main thread blocked waiting for the call (a
 * `runBlocking` caller) would never see the answer.
 */
private val callbackExecutor: Executor = Dispatchers.IO.asExecutor()

/** The response message of the system resolver to [name]'s HTTPS query, or null when the lookup failed. */
@TargetApi(29)
private suspend fun rawQuery(name: String): ByteArray? =
    suspendCancellableCoroutine { cont ->
        val cancel = CancellationSignal()
        cont.invokeOnCancellation { cancel.cancel() }
        DnsResolver.getInstance().rawQuery(
            null, // the default network
            name,
            DnsResolver.CLASS_IN,
            DnsMessage.TYPE_HTTPS,
            DnsResolver.FLAG_EMPTY,
            callbackExecutor,
            cancel,
            object : DnsResolver.Callback<ByteArray> {
                override fun onAnswer(
                    answer: ByteArray,
                    rcode: Int,
                ) {
                    if (cont.isActive) cont.resume(answer)
                }

                override fun onError(error: DnsResolver.DnsException) {
                    if (cont.isActive) cont.resume(null)
                }
            },
        )
    }
