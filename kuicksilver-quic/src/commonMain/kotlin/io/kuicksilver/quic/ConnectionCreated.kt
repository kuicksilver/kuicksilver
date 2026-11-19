// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic

import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.annotations.InternalKuicksilverApi
import kotlin.coroutines.AbstractCoroutineContextElement
import kotlin.coroutines.CoroutineContext

/**
 * For the library's own modules: in the coroutine context of a `connect` or `connectEarly` call, [onCreated] hears the
 * [ConnectionInfo] of the connection that very call creates, on the endpoint loop, before the handshake goes out. It ties
 * a connection to the call that made it by identity (the Ktor client's setup attempts), where an endpoint listener only
 * sees the address. It must return at once and never throw (what it throws is dropped).
 */
@InternalKuicksilverApi
@OptIn(ExperimentalKuicksilverApi::class)
public class ConnectionCreated(
    public val onCreated: (ConnectionInfo) -> Unit,
) : AbstractCoroutineContextElement(Key) {
    /** The context key. */
    public companion object Key : CoroutineContext.Key<ConnectionCreated>
}
