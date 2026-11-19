// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(ExperimentalAtomicApi::class, InternalKuicksilverApi::class, ExperimentalCoroutinesApi::class)

package io.kuicksilver.http3.connectudp

import io.ktor.network.sockets.InetSocketAddress
import io.kuicksilver.annotations.InternalKuicksilverApi
import io.kuicksilver.tls.KslNet
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.IO
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.async
import kotlin.concurrent.atomics.AtomicInt
import kotlin.concurrent.atomics.ExperimentalAtomicApi
import kotlin.concurrent.atomics.decrementAndFetch
import kotlin.concurrent.atomics.incrementAndFetch

/** The system resolver has [SystemResolver.MAX_IN_FLIGHT] lookups running already: the request is refused, not queued. */
internal class ResolverBusyException : Exception("the system resolver has too many lookups running")

/**
 * [io.kuicksilver.http3.UdpProxyResolver.System]: every address of a name (IPv4 first, then IPv6), from the operating
 * system's resolver (`ksl_resolve`, `getaddrinfo` one family at a time; ktor's single lookup where the native library is
 * missing). A lookup blocks a thread and no deadline interrupts it, so a client that names slow names could hold every
 * thread of `Dispatchers.IO`: the lookups run on a dispatcher of [MAX_IN_FLIGHT] threads of their own, the caller waits
 * cancellably (its `resolveTimeout` returns at once), and a lookup counts until its blocking call has returned, given up
 * or not; one more than [MAX_IN_FLIGHT], or than [MAX_PER_CLIENT] of one client, fails at once with
 * [ResolverBusyException]. A resolver of the application's (the
 * engine's pluggable DNS, say) replaces it through [io.kuicksilver.http3.UdpProxyConfig.resolver].
 */
internal object SystemResolver {
    const val MAX_IN_FLIGHT = 16

    /** Lookups one client may have running at once, so one cannot take every thread (a lookup counts until it returns). */
    const val MAX_PER_CLIENT = 4
    private val inFlight = AtomicInt(0)
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO.limitedParallelism(MAX_IN_FLIGHT))

    /** Lookups whose blocking call has not returned yet (tests). */
    internal val inFlightNow: Int get() = inFlight.load()

    /** Replaces the blocking lookup (tests: one that never returns on its own). */
    internal var lookupForTest: ((String) -> List<ByteArray>)? = null

    /** [host]'s addresses. */
    suspend fun resolve(host: String): List<ByteArray> = resolveFor(host, null)

    /** [host]'s addresses; [owner], when given, counts the client's lookups up to [MAX_PER_CLIENT] until each returns. */
    suspend fun resolveFor(
        host: String,
        owner: AtomicInt?,
    ): List<ByteArray> {
        if (owner != null && owner.incrementAndFetch() > MAX_PER_CLIENT) {
            owner.decrementAndFetch()
            throw ResolverBusyException()
        }
        if (inFlight.incrementAndFetch() > MAX_IN_FLIGHT) {
            inFlight.decrementAndFetch()
            owner?.decrementAndFetch()
            throw ResolverBusyException()
        }
        val lookup =
            try {
                scope.async {
                    try {
                        (lookupForTest ?: ::blockingLookup)(host)
                    } finally {
                        inFlight.decrementAndFetch()
                        owner?.decrementAndFetch()
                    }
                }
            } catch (e: Throwable) {
                inFlight.decrementAndFetch()
                owner?.decrementAndFetch()
                throw e
            }
        return lookup.await() // cancellable: the caller's deadline ends the wait, not the lookup
    }

    private fun blockingLookup(host: String): List<ByteArray> {
        if (!KslNet.available()) return listOfNotNull(InetSocketAddress(host, 0).resolveAddress())
        val v4 = KslNet.resolve(host, ipv6 = false)
        val v6 = KslNet.resolve(host, ipv6 = true)
        if (v4 == null && v6 == null) throw IllegalStateException("the lookup of the name failed")
        return v4.orEmpty().map { it.bytes } + v6.orEmpty().filter { it.scopeId == 0 }.map { it.bytes }
    }
}
