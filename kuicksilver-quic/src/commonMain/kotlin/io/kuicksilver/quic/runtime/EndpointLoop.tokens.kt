// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(ExperimentalKuicksilverApi::class, ExperimentalAtomicApi::class, InternalKuicksilverApi::class)

package io.kuicksilver.quic.runtime

import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.annotations.InternalKuicksilverApi
import io.kuicksilver.quic.ConnectionCore
import io.kuicksilver.quic.LogLevel
import io.kuicksilver.quic.emit
import io.kuicksilver.quic.runtime.EndpointLoop.Companion.TOKEN_STORE_TIMEOUT
import io.kuicksilver.tls.QuicSessionTicket
import io.kuicksilver.tls.TlsConfig
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withTimeoutOrNull
import kotlin.concurrent.atomics.ExperimentalAtomicApi

// Session tickets and address-validation tokens handed to the user's stores (RFC 9000 section 8.1.3, RFC 9001 section 4.6.1).

/** A client connection received a ticket: kept for a later 0-RTT connection with the same TLS configuration. */
@OptIn(kotlinx.coroutines.DelicateCoroutinesApi::class)
internal fun EndpointLoop.storeTicket(
    tls: TlsConfig,
    ticket: QuicSessionTicket,
) {
    if (closing) {
        ticket.close()
        return
    }
    // started even when the scope is cancelled meanwhile: putQuic then releases the ticket instead of dropping it
    scope.launch(start = kotlinx.coroutines.CoroutineStart.ATOMIC) { sessions.putQuic(tls, ticket) }
}

/**
 * A client connection received a NEW_TOKEN token: handed to the configured store (RFC 9000 section 8.1.3). The store runs
 * in a coroutine of the loop's scope; what it throws is logged, never the connection's failure.
 */
@OptIn(kotlinx.coroutines.DelicateCoroutinesApi::class)
internal fun EndpointLoop.storeToken(
    store: io.kuicksilver.quic.QuicTokenStore,
    key: String,
    token: ByteArray,
) {
    if (closing) return
    // started even when the scope is cancelled meanwhile, like storeTicket: a token that arrived is still offered to the store
    scope.launch(start = kotlinx.coroutines.CoroutineStart.ATOMIC) {
        try {
            // bounded like take: a store that hangs must not keep coroutines (and tokens) around for good
            var done = false
            withTimeoutOrNull(TOKEN_STORE_TIMEOUT) {
                store.put(key, token)
                done = true
            }
            if (!done) tokenStoreSlow("put", key)
        } catch (e: Throwable) {
            // the loop's own cancellation goes on; anything else, a CancellationException of the store's included, is its failure
            if (e is CancellationException) currentCoroutineContext().ensureActive()
            observer.logger.emit(LogLevel.Warn, e) { "token store put failed for $key; the token is dropped" }
        }
    }
}

/** A token store call ran past [TOKEN_STORE_TIMEOUT]: the connection goes on without it; logged once per endpoint loop. */
internal fun EndpointLoop.tokenStoreSlow(
    call: String,
    key: String,
) {
    if (!tokenStoreSlowLogged.compareAndSet(0, 1)) return
    observer.logger.emit(LogLevel.Warn) {
        "token store $call for $key took more than $TOKEN_STORE_TIMEOUT; going on without it (logged once per endpoint loop)"
    }
}

/**
 * A token for the next connection to [key] from the configured store (in the caller's coroutine), or null: a store that fails
 * or takes longer than [TOKEN_STORE_TIMEOUT] is logged and the connection goes on without a token.
 */
internal suspend fun EndpointLoop.takeToken(
    store: io.kuicksilver.quic.QuicTokenStore,
    key: String,
): ByteArray? =
    try {
        var done = false
        val token =
            withTimeoutOrNull(TOKEN_STORE_TIMEOUT) {
                store.take(key).also { done = true }
            }
        if (!done) tokenStoreSlow("take", key)
        token?.takeIf { it.isNotEmpty() && it.size <= ConnectionCore.MAX_KEPT_TOKEN }
    } catch (e: Throwable) {
        if (e is CancellationException) currentCoroutineContext().ensureActive() // the caller's cancellation goes on
        observer.logger.emit(LogLevel.Warn, e) { "token store take failed for $key; connecting without a token" }
        null
    }
