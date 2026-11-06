// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.client

import android.annotation.TargetApi
import android.net.DnsResolver
import android.os.Build
import android.os.CancellationSignal
import io.kuicksilver.ktor.client.dns.DnsAnswer
import io.kuicksilver.ktor.client.dns.DnsException
import io.kuicksilver.ktor.client.dns.DnsMessage
import io.kuicksilver.ktor.client.dns.SvcbMalformedException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.asExecutor
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
): DnsAnswer? = if (Build.VERSION.SDK_INT < 29) null else withTimeoutOrNull(timeout) { rawQuery(name) }

/**
 * Where DnsResolver runs the callback, which parses the answer: a background thread. DnsResolver posts its callbacks
 * from the main Looper, so a direct executor would parse there, and a main thread blocked waiting for the call (a
 * `runBlocking` caller) would never see the answer.
 */
private val callbackExecutor: Executor = Dispatchers.IO.asExecutor()

@TargetApi(29)
private suspend fun rawQuery(name: String): DnsAnswer? =
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
                    val records =
                        try {
                            DnsMessage.read(answer, name)
                        } catch (_: SvcbMalformedException) {
                            DnsAnswer(emptyList()) // RFC 9460 section 2.2: rejected, the connection goes on without SVCB
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
