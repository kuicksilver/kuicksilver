// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(kotlinx.cinterop.ExperimentalForeignApi::class)

package io.kuicksilver.interop

import io.kuicksilver.interop.stopsignal.ksl_interop_install_stop
import io.kuicksilver.interop.stopsignal.ksl_interop_stop_requested
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.DelicateCoroutinesApi
import kotlinx.coroutines.GlobalScope
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch

/** How often the stop flag is read: a stop is noticed within this, well inside STOP_GRACE. */
private const val STOP_POLL_MS = 20L

// SIGTERM and SIGINT run a handler written in C (stopsignal.def) that only stores to a lock-free atomic_int and restores the
// default action of the signals it handles (SIGINT ignored on entry stays ignored): nothing of Kotlin runs in signal context, so the
// signal may land on any thread, one the runtime knows or not (the runtime's own threads exist before main, so blocking the signals
// cannot cover them all), and a second signal ends a process whose stop hangs. A coroutine reads the flag every STOP_POLL_MS and
// requests the stop; the endpoint then closes its endpoints and exits on its own (serveUntilStopped, exitWith 0) instead of being
// ended by the signal with its qlog traces still in their buffers. [closed] is not waited for here: the main thread exits once the
// close finished or STOP_GRACE passed.
@OptIn(DelicateCoroutinesApi::class)
@Suppress("UNUSED_PARAMETER")
internal actual fun installStopSignal(stop: CompletableDeferred<Unit>, closed: CompletableDeferred<Unit>) {
    val rc = ksl_interop_install_stop()
    if (rc != 0) {
        Files.log("no SIGTERM/SIGINT handler ($rc): a stop ends the process at once")
        return
    }
    GlobalScope.launch {
        while (ksl_interop_stop_requested() == 0) delay(STOP_POLL_MS)
        stop.complete(Unit)
    }
}
