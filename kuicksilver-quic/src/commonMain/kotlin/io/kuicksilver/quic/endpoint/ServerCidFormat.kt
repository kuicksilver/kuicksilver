// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.endpoint

import io.kuicksilver.quic.wire.ConnectionId
import kotlin.random.Random

/** Server connection IDs: `[format version 0x01][routing byte][random]`, 8 bytes by default. */
internal object ServerCidFormat {
    const val FORMAT_VERSION: Int = 0x01

    fun generate(
        loopIndex: Int,
        length: Int,
        random: Random,
    ): ConnectionId {
        val b = ByteArray(length)
        random.nextBytes(b)
        b[0] = FORMAT_VERSION.toByte()
        b[1] = loopIndex.toByte()
        return ConnectionId(b)
    }
}
