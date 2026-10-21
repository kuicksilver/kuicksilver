// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.network

import io.ktor.network.selector.SelectorManager
import io.kuicksilver.annotations.InternalKuicksilverApi
import kotlin.coroutines.CoroutineContext

/**
 * The engines' ktor-network `SelectorManager`: a socket closed on it is released at once, also when nothing else waits on
 * the selector. On the JVM and Android, ktor-network 3.6.0 left such a socket open: NIO defers the close of a channel
 * registered with a selector until that selector's next select, and an `ActorSelectorManager` with no interest pending
 * waits for a new interest instead of selecting, so the descriptor stayed open, half-closed, with its unread data, until
 * some other socket of the selector did something; the peer, writing into a zero window, never saw the connection end
 * (Ktor issue KTOR-10016). Here the selector always has one interest pending (a pipe nobody
 * writes to), so it keeps selecting and every select flushes the deferred closes. Kotlin/Native's selector closes the
 * descriptor itself: nothing is added there.
 */
@InternalKuicksilverApi
public fun engineSelector(context: CoroutineContext): SelectorManager = SelectorManager(context).also { keepSelecting(it) }

/** Keeps [selector] selecting for as long as it is open (see [engineSelector]). */
internal expect fun keepSelecting(selector: SelectorManager)
