// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(kotlinx.cinterop.ExperimentalForeignApi::class, kotlin.concurrent.atomics.ExperimentalAtomicApi::class)

package io.kuicksilver.interop

import kotlinx.cinterop.staticCFunction
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.DelicateCoroutinesApi
import kotlinx.coroutines.GlobalScope
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import platform.posix.SIGINT
import platform.posix.SIGTERM
import platform.posix.signal
import kotlin.concurrent.atomics.AtomicInt

/** Set by the signal handler, which does nothing else (no allocation, no lock: whatever thread the signal interrupts). */
private val stopRequested = AtomicInt(0)

// SIGTERM and SIGINT set a flag that a coroutine polls every 20 ms; the handler is the process's, so a signal taken by any thread
// (the runtime's own threads exist before main: blocking the signals there is not possible) reaches it. The endpoint then closes its
// endpoints and exits on its own (serveUntilStopped, exitWith), instead of being ended by the signal with its qlog traces still in
// their buffers; [closed] is not waited for here, the main thread exits once the close finished or STOP_GRACE passed.
@OptIn(DelicateCoroutinesApi::class)
@Suppress("UNUSED_PARAMETER")
internal actual fun installStopSignal(stop: CompletableDeferred<Unit>, closed: CompletableDeferred<Unit>) {
    stopRequested.store(0) // initialized before a handler can read it
    val handler = staticCFunction { _: Int -> stopRequested.store(1) }
    signal(SIGTERM, handler)
    signal(SIGINT, handler)
    GlobalScope.launch {
        while (stopRequested.load() == 0) delay(20)
        stop.complete(Unit)
    }
}
