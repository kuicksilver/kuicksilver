// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.native

@kotlin.native.concurrent.ThreadLocal
private object OpenHere {
    var count = 0L
}

internal actual fun packetBuffersOpenHere(): Long = OpenHere.count

internal actual fun countPacketBuffer(delta: Int) {
    OpenHere.count += delta
}
