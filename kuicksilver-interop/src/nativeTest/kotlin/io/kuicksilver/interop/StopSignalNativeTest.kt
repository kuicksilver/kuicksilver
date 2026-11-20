// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(kotlinx.cinterop.ExperimentalForeignApi::class)

package io.kuicksilver.interop

import io.kuicksilver.interop.stopsignal.ksl_interop_raise_stop
import kotlinx.cinterop.CPointer
import kotlinx.cinterop.CFunction
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import platform.posix.SIGINT
import platform.posix.SIGTERM
import platform.posix.SIG_DFL
import platform.posix.SIG_IGN
import platform.posix.signal
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.time.Duration.Companion.seconds

class StopSignalNativeTest {
    /**
     * The runner's SIGTERM requests the stop through the C handler (nothing of Kotlin runs in signal context), and the handler puts
     * SIGTERM and SIGINT back to their default action, so a second signal ends a process whose stop hangs.
     */
    @Test fun sigtermRequestsTheStopAndASecondSignalIsTheDefault() = runBlocking {
        val stop = CompletableDeferred<Unit>()
        installStopSignal(stop, CompletableDeferred())
        assertEquals(0, ksl_interop_raise_stop())
        withTimeout(5.seconds) { stop.await() }
        // what the handler left: the default action for both (read back by setting SIG_IGN, then restored)
        val term: CPointer<CFunction<(Int) -> Unit>>? = signal(SIGTERM, SIG_IGN)
        val int: CPointer<CFunction<(Int) -> Unit>>? = signal(SIGINT, SIG_IGN)
        signal(SIGTERM, SIG_DFL); signal(SIGINT, SIG_DFL)
        assertEquals(SIG_DFL, term, "SIGTERM is back to its default action")
        assertEquals(SIG_DFL, int, "SIGINT is back to its default action")
    }

    /** SIGINT ignored when the endpoint starts (a background job, nohup) stays ignored; SIGTERM is still taken. */
    @Test fun negative_anIgnoredSigintStaysIgnored() = runBlocking {
        signal(SIGINT, SIG_IGN)
        try {
            val stop = CompletableDeferred<Unit>()
            installStopSignal(stop, CompletableDeferred())
            val int: CPointer<CFunction<(Int) -> Unit>>? = signal(SIGINT, SIG_IGN)
            assertEquals(SIG_IGN, int, "SIGINT is still ignored")
            assertEquals(0, ksl_interop_raise_stop())
            withTimeout(5.seconds) { stop.await() }
            assertEquals(SIG_IGN, signal(SIGINT, SIG_IGN), "and stays ignored after the stop")
        } finally {
            signal(SIGTERM, SIG_DFL); signal(SIGINT, SIG_DFL)
        }
    }
}
