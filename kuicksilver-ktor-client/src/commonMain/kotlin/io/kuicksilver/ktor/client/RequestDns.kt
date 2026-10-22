// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(io.kuicksilver.annotations.InternalKuicksilverApi::class)

package io.kuicksilver.ktor.client

import io.kuicksilver.ktor.network.TcpAddress
import io.kuicksilver.ktor.network.resolveTcp
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock

/**
 * The name resolution of one request: each host is looked up once and its answer, or its failure, reused for the rest of
 * the request, so the two sides of the h3/h1 race (and a fallback after it) connect to what one lookup returned and a
 * name that does not resolve is not asked again. A lookup runs under the caller's deadline; a caller cancelled while it
 * runs leaves no answer behind, and the next caller looks the name up itself.
 */
internal class RequestDns(
    private val resolve: suspend (String, Int) -> List<TcpAddress>,
) {
    private val lock = Mutex()
    private val answers = HashMap<String, Result<List<TcpAddress>>>()

    /** The addresses of [host] with [port]; [host] is a URL host, an IPv6 literal with or without its brackets. */
    suspend fun lookup(
        host: String,
        port: Int,
    ): List<TcpAddress> {
        val name = socketHost(host)
        val found =
            lock.withLock {
                answers[name] ?: try {
                    Result.success(resolve(name, port))
                } catch (e: CancellationException) {
                    throw e
                } catch (e: Throwable) {
                    Result.failure(e)
                }.also { answers[name] = it }
            }
        return found.getOrThrow().map { it.withPort(port) }
    }
}

/** A fresh [RequestDns] with this configuration's resolver. */
internal fun KuicksilverEngineConfig.newRequestDns(): RequestDns = RequestDns(resolverForTest ?: ::resolveTcp)
