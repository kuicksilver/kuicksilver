// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.fuzz

import com.code_intelligence.jazzer.junit.FuzzTest
import io.kuicksilver.quic.recovery.BbrDriver

/**
 * Fuzz target `bbrInvariants`: arbitrary ACK, loss, timeout, CE, idle, MTU, spurious-loss and discard sequences for one BBR
 * controller ([BbrDriver]), every invariant checked after every operation. Input: [u16 seed][u8 datagram size / 256], then
 * operations [u8 op][3-byte arguments as the operation reads them]; a short input pads with zeros.
 */
class BbrInvariantFuzzTest {
    @FuzzTest(maxDuration = "60s")
    fun bbrInvariants(data: ByteArray) {
        var p = 0

        fun u8(): Int = if (p < data.size) data[p++].toInt() and 0xff else 0

        fun u24(): Int = (u8() shl 16) or (u8() shl 8) or u8()
        val seed = (u8() shl 8 or u8()).toLong()
        val d = BbrDriver(seed, 1200 + u8() * 256)
        while (p < data.size) d.step(u8()) { u24() }
    }
}
