// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(io.kuicksilver.annotations.InternalKuicksilverApi::class)

package io.kuicksilver.ktor.client

import io.kuicksilver.ktor.network.TcpAddress
import io.kuicksilver.ktor.network.resolveTcp
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull
import kotlin.time.Duration
import kotlin.time.Duration.Companion.milliseconds

/**
 * The name resolution of one request: each host is looked up once and its answer, or its failure, reused for the rest of
 * the request, so the two sides of the h3/h1 race (and a fallback after it) connect to what one lookup returned and a
 * name that does not resolve is not asked again. Different names are looked up in parallel (one pending answer per
 * name; RFC 9460 section 5 relies on that). A lookup runs under the caller's deadline; a caller cancelled while it runs
 * leaves no answer behind, and a caller waiting for the same name then looks it up itself.
 */
internal class RequestDns private constructor(
    private val resolve: suspend (String, Int) -> List<TcpAddress>,
    private val lock: Mutex,
    private val answers: HashMap<String, CompletableDeferred<Result<List<TcpAddress>>>>,
    /** Addresses of one family an HTTPS answer carried, by name ([seed]); the lookup adds the other family. */
    private val partial: HashMap<String, List<TcpAddress>>,
    /** Every lookup goes to this host and port instead (an HTTPS record's endpoint, [connectTo]). */
    private val endpoint: Pair<String, Int>?,
    /** Which family goes first in the lists [seed] assembles; told the order of every lookup's answer. */
    private val order: AddressFamilyOrder,
) {
    constructor(
        order: AddressFamilyOrder = AddressFamilyOrder.system,
        resolve: suspend (String, Int) -> List<TcpAddress>,
    ) : this(resolve, Mutex(), HashMap(), HashMap(), null, order)

    /** The lock over the answers (tests). */
    internal val lockForTest: Mutex get() = lock

    /**
     * A view of this resolution whose every lookup resolves [host] and answers with [port]: the TCP side of a connection to
     * an endpoint of the origin's HTTPS records (RFC 9460 section 3: the client resolves the TargetName and uses the
     * endpoint's port; TLS and the request still name the origin). It shares the answers, so a name is still asked once.
     */
    fun connectTo(
        host: String,
        port: Int,
    ): RequestDns = RequestDns(resolve, lock, answers, partial, host to port, order)

    /**
     * Takes [addresses] (4 or 16 bytes each), the A/AAAA records an HTTPS answer carried, for [host] unless it was looked
     * up already (RFC 9460 section 5: they "SHOULD be placed in cache before performing any follow-up queries"). With both
     * families they are the answer, in the family order of the system ([AddressFamilyOrder]), and no lookup follows. With
     * one family they are used too, but the answer may have
     * left the other out (section 5.2), and section 3 has the client resolve "AAAA and/or A records": the lookup of
     * [host] then still runs, and adds the other family's addresses when they come within [RESOLUTION_DELAY].
     */
    suspend fun seed(
        host: String,
        addresses: List<ByteArray>,
    ) {
        if (addresses.isEmpty()) return
        val list = addresses.map { TcpAddress(it, 0) }
        val name = socketHost(host)
        lock.withLock {
            if (list.any { it.isIpv6 } && list.any { !it.isIpv6 }) {
                answers.getOrPut(name) { CompletableDeferred(Result.success(order.sort(list))) }
            } else if (name !in answers) {
                partial.getOrPut(name) { list }
            }
        }
    }

    /** The addresses of [host] with [port]; [host] is a URL host, an IPv6 literal with or without its brackets. */
    suspend fun lookup(
        host: String,
        port: Int,
    ): List<TcpAddress> {
        if (endpoint != null) return RequestDns(resolve, lock, answers, partial, null, order).lookup(endpoint.first, endpoint.second)
        val name = socketHost(host)
        while (true) {
            var mine = false
            var seeded: List<TcpAddress>? = null
            val pending =
                lock.withLock {
                    seeded = partial[name]
                    // a cancelled entry is one whose looker-up went away: replace it, so no waiter spins on it
                    answers[name]?.takeUnless { it.isCancelled } ?: CompletableDeferred<Result<List<TcpAddress>>>().also {
                        mine = true
                        answers[name] = it
                    }
                }
            if (mine) {
                val result =
                    try {
                        Result.success(seeded?.let { withOtherFamily(it, name, port) } ?: resolve(name, port).also(order::observe))
                    } catch (e: CancellationException) {
                        // this caller goes: no answer is left behind, and a caller waiting for it asks again. Cancel first,
                        // then remove without being cancellable: a busy lock must not leave the entry behind
                        pending.cancel()
                        withContext(NonCancellable) { lock.withLock { if (answers[name] === pending) answers.remove(name) } }
                        throw e
                    } catch (e: Throwable) {
                        Result.failure(e)
                    }
                pending.complete(result)
            }
            val found =
                try {
                    pending.await()
                } catch (e: CancellationException) {
                    currentCoroutineContext().ensureActive() // our own cancellation; else the looker-up was cancelled
                    continue
                }
            return found.getOrThrow().map { it.withPort(port) }
        }
    }

    /**
     * [seeded] (one family) and the other family's addresses from a lookup of [name] when it answers within
     * [RESOLUTION_DELAY], the family that lookup put first leading (the platform resolver sorts its answer by RFC 6724, as
     * RFC 8305 section 4 says: "First, the client MUST sort the addresses received up to this point using Destination
     * Address Selection ([RFC6724], Section 6)"); without its answer, [AddressFamilyOrder] decides. A lookup that fails,
     * finds none of the other family or answers later leaves [seeded] alone. The wait applies to a seeded AAAA too: the
     * list is fixed once returned, so a later answer could not join the race, where RFC 8305 section 3 has "the newly
     * received IPv6 addresses are incorporated into the list of available candidate addresses" (the resolvers here answer
     * once, docs/spec/rfc/8305.md).
     */
    private suspend fun withOtherFamily(
        seeded: List<TcpAddress>,
        name: String,
        port: Int,
    ): List<TcpAddress> =
        coroutineScope {
            val v6 = seeded.first().isIpv6
            val lookup =
                async {
                    try {
                        resolve(name, port)
                    } catch (e: CancellationException) {
                        throw e
                    } catch (_: Throwable) {
                        emptyList()
                    }
                }
            val answer = withTimeoutOrNull(RESOLUTION_DELAY) { lookup.await() }.orEmpty()
            lookup.cancel()
            order.observe(answer)
            val other = answer.filter { it.isIpv6 != v6 }
            order.sort(seeded + other, answer.firstOrNull()?.isIpv6 ?: order.ipv6First())
        }

    companion object {
        /**
         * How long the addresses of one family an HTTPS answer carried wait for the other family's lookup: the Resolution
         * Delay of Happy Eyeballs, for which RFC 8305 section 3 has the client "wait a short time for the AAAA response to
         * ensure that preference is given to IPv6": "The recommended value for the Resolution Delay is 50 milliseconds."
         */
        val RESOLUTION_DELAY: Duration = 50.milliseconds
    }
}

/** A fresh [RequestDns] with this configuration's resolver. */
internal fun KuicksilverEngineConfig.newRequestDns(): RequestDns =
    resolverForTest?.let { RequestDns(AddressFamilyOrder.dualStackForTest(), it) } ?: RequestDns(AddressFamilyOrder.system, ::resolveTcp)
