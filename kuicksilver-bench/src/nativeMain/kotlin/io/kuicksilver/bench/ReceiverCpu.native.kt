// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.bench

/** Kotlin/Native names no thread the benchmark could pick out: `sample <pid>` shows the receiver (`SocketDispatcher.receive`). */
internal actual class ReceiverCpu {
    actual fun nanos(): Long = 0

    actual companion object {
        actual fun find(): ReceiverCpu? = null

        actual fun note(cpu: ReceiverCpu?): String = "Kotlin/Native: sample the process for the receiver's share"
    }
}
