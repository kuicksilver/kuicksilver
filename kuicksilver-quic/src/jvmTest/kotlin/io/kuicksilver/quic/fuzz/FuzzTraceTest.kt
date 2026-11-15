// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.fuzz

import io.kuicksilver.quic.NullCryptoProvider
import io.kuicksilver.quic.ksl
import io.kuicksilver.tls.QuicCrypto
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull

/**
 * The fingerprint of a fuzz program's decoded operations ([FuzzTrace], recorded per committed input in
 * tools/fuzz/formats/<target>.lock): the same input gives the same fingerprint in every run, also over real TLS; bytes
 * the decoder reads differently give another one (another frame kind, payload, length, or every later operation read out
 * of step); bytes the decoder does not read as anything else keep it (the flag bits ConnProgram ignores, the argument of
 * kind 7), which is what lets a rewrite that keeps an input's meaning keep its fingerprint; a run that decodes nothing has
 * none (so a target whose trace calls are gone is found).
 */
class FuzzTraceTest {
    private fun conn(
        input: ByteArray,
        crypto: QuicCrypto = NullCryptoProvider,
    ): String {
        val (fp, _, thrown) = FuzzTrace.record(false) { ConnectionFuzz(input, crypto).run() }
        if (thrown != null) throw thrown
        return assertNotNull(fp, "the program decoded no operation")
    }

    private val program =
        ConnProgram
            .Builder(0)
            .app(0, 0, ConnProgram.num(100), byteArrayOf(1))
            .frame(0, 3, "PING")
            .raw(1, 3, byteArrayOf(0x01, 0x01))
            .step()
            .tick(2)
            .build()

    @Test fun aProgramDecodesToTheSameOperationsInEveryRun() {
        assertEquals(conn(program), conn(program))
    }

    @Test fun overRealTlsTooTheTraceIsTheSameInEveryRun() {
        assertEquals(conn(program, ksl), conn(program, ksl))
    }

    @Test fun negative_anotherFrameKindIsAnotherTrace() {
        val other = ConnProgram.Builder(0).app(0, 0, ConnProgram.num(100), byteArrayOf(1)).frame(0, 3, "HANDSHAKE_DONE")
        assertNotEquals(
            conn(program),
            conn(
                other
                    .raw(1, 3, byteArrayOf(0x01, 0x01))
                    .step()
                    .tick(2)
                    .build(),
            ),
        )
    }

    @Test fun negative_anotherRawPayloadIsAnotherTrace() {
        val changed = program.copyOf()
        val at = changed.size - 3 // the RAW payload's last byte, before STEP and TICK
        changed[at] = 0x02
        assertNotEquals(conn(program), conn(changed))
    }

    @Test fun negative_anotherLengthIsAnotherTrace() {
        val other = ConnProgram.Builder(0).app(0, 0, ConnProgram.num(101), byteArrayOf(1)).frame(0, 3, "PING")
        assertNotEquals(
            conn(program),
            conn(
                other
                    .raw(1, 3, byteArrayOf(0x01, 0x01))
                    .step()
                    .tick(2)
                    .build(),
            ),
        )
    }

    @Test fun negative_operationsReadOutOfStepAreAnotherTrace() {
        // one byte more inside the first operation's arguments (its length 0, its fin flag the old length): every later
        // operation is read one byte off
        val shifted = byteArrayOf(program[0], program[1], 0) + program.copyOfRange(2, program.size)
        assertNotEquals(conn(program), conn(shifted))
    }

    @Test fun bytesTheDecoderDoesNotReadKeepTheTrace() {
        // flag bits 3 to 7 mean nothing to this decoder, and kind 7 is one round whatever its argument
        val flagged = program.copyOf().also { it[0] = (it[0].toInt() or 0xf8).toByte() }
        assertEquals(conn(program), conn(flagged))
        val round = program + byteArrayOf(0x07)
        val roundWithArgument = program + byteArrayOf(0x57)
        assertEquals(conn(round), conn(roundWithArgument))
        assertNotEquals(conn(program), conn(round), "a round is an operation of the trace")
    }

    @Test fun negative_aZeroRttProgramWithAnotherOutcomeIsAnotherTrace() {
        val accept = ZeroRttProgram.Builder(ZeroRttProgram.ACCEPT, 0).build()
        val lost = ZeroRttProgram.Builder(ZeroRttProgram.LOST, 0).build()
        val fp = { b: ByteArray -> FuzzTrace.record(false) { ZeroRttConnectionFuzz(b).run() }.first }
        assertEquals(fp(accept), fp(accept))
        assertNotEquals(fp(accept), fp(lost))
    }

    @Test fun negative_aRunThatDecodesNothingHasNoFingerprint() {
        assertNull(FuzzTrace.record(false) { }.first)
        assertNull(FuzzTrace.record(false) { ConnectionFuzz(ByteArray(0), NullCryptoProvider).run() }.first)
    }
}
