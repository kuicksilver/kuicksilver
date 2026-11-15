// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.fuzz

import io.kuicksilver.quic.NullCryptoProvider
import kotlin.test.Test
import kotlin.test.assertContentEquals

/** [ConnectionProgramRewriter] on hand-made programs: what it must turn into one round, and what it must leave alone. */
class ConnectionProgramRewriterTest {
    private fun hex(h: String) = ByteArray(h.length / 2) { h.substring(2 * it, 2 * it + 2).toInt(16).toByte() }

    private fun check(
        input: String,
        expected: String,
    ) = assertContentEquals(hex(expected), ConnectionProgramRewriter.rewrite(hex(input), NullCryptoProvider), input)

    @Test fun aPathOperationBecomesOneRound() = check("001712", "000712")

    @Test fun argumentsZeroAndFifteenStay() = check("0007f712", "0007f712")

    @Test fun theServersSideBitStays() = check("001f12", "000f12")

    @Test fun aRawPayloadIsNoOperation() = check("000000021717", "000000021717")

    @Test fun aFramesFieldsAreNoOperations() = check("0001110017170812", "0001110017170812")

    /** 0x37 (E_PTB) read 0xc7 as an argument; once it is a round, 0xc7 (E_VN) is an operation of its own and goes too. */
    @Test fun theRunGoesOnFromTheStart() = check("0037c705", "00070705")

    /** Bits 3 to 7 of the flags byte came after these inputs: cleared, so SETUP no longer takes the next byte (0x17, now an operation). */
    @Test fun theNewFlagBitsAreClearedAndTheSetupByteWithThem() = check("fb1712", "030712")

    @Test fun theOldFlagBitsStay() = check("071212", "071212")

    @Test fun aRewrittenInputStaysAsItIs() {
        val once = ConnectionProgramRewriter.rewrite(hex("ff37c705171f12"), NullCryptoProvider)
        assertContentEquals(once, ConnectionProgramRewriter.rewrite(once, NullCryptoProvider), "idempotent")
    }

    /** Live handshake: the server's connection does not exist yet, so its application call reads no argument, and 0x17 after it is a PATH operation. */
    @Test fun anApplicationCallThatReadsNothingIsFollowed() = check("014b17", "014b07")
}
