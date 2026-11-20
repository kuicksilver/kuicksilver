// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.interop

import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeoutOrNull
import kotlin.time.Duration.Companion.seconds

internal actual fun envVar(name: String): String? = System.getenv(name)

internal actual fun exitWith(code: Int): Nothing = kotlin.system.exitProcess(code)

// SIGTERM (and SIGINT) start the JVM's shutdown, which runs this hook: it asks the server to stop and holds the shutdown until the
// endpoints are closed, at most STOP_GRACE and a second. An exit of our own (exitWith) runs it too, with both already complete.
internal actual fun installStopSignal(stop: CompletableDeferred<Unit>, closed: CompletableDeferred<Unit>) {
    Runtime.getRuntime().addShutdownHook(
        Thread({
            stop.complete(Unit)
            runBlocking { withTimeoutOrNull(STOP_GRACE + 1.seconds) { closed.await() } }
        }, "interop-stop"),
    )
}
