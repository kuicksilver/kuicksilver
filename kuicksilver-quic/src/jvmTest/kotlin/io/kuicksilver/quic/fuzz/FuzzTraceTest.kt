// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.fuzz

import io.kuicksilver.quic.CorePair
import io.kuicksilver.quic.NullCryptoProvider
import io.kuicksilver.quic.core.sizesForTest
import io.kuicksilver.quic.ksl
import io.kuicksilver.tls.QuicCrypto
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * The fingerprint of a fuzz program's decoded operations ([FuzzTrace], recorded per committed input in
 * tools/fuzz/formats/<target>.lock): the same input gives the same fingerprint in every run, also over real TLS; bytes
 * the decoder reads differently give another one (another frame kind, payload, length, or every later operation read out
 * of step); bytes the decoder does not read as anything else keep it (the flag bits ConnProgram ignores, the argument of
 * kind 7), which is what lets a rewrite that keeps an input's meaning keep its fingerprint; a run that decodes nothing has
 * none (so a target whose trace calls are gone is found). And the trace states everything the decoder makes of a byte:
 * over every value of the flags byte, of an operation byte (with the same argument bytes after it) and of the 0-RTT
 * outcome byte, two inputs whose traces are equal end in the same state, so a flag, an operation or an argument given a
 * meaning its trace does not state fails here.
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
        // kind 7 with the argument 0 or 15 is one round, whichever of the two (the others are PATH operations)
        val round = program + byteArrayOf(0x07)
        val roundWithArgument = program + byteArrayOf(0xf7.toByte())
        assertEquals(conn(round), conn(roundWithArgument))
        assertNotEquals(conn(program), conn(round), "a round is an operation of the trace")
    }

    @Test fun negative_aPathOperationIsAnotherTraceThanARound() {
        assertNotEquals(conn(program + byteArrayOf(0x07)), conn(program + byteArrayOf(0x27)))
    }

    @Test fun negative_aZeroRttProgramWithAnotherOutcomeIsAnotherTrace() {
        val accept = ZeroRttProgram.Builder(ZeroRttProgram.ACCEPT, 0).build()
        val lost = ZeroRttProgram.Builder(ZeroRttProgram.LOST, 0).build()
        val fp = { b: ByteArray -> FuzzTrace.record(false) { ZeroRttConnectionFuzz(b).run() }.first }
        assertEquals(fp(accept), fp(accept))
        assertNotEquals(fp(accept), fp(lost))
    }

    /** [observation] of the connection program's network: its two cores. */
    private fun observation(
        net: EndpointNet,
        wire: String,
    ): String = ends(listOfNotNull(net.client, net.serverCore), net.now.toString(), wire)

    /**
     * What a run ended in: each side's state, why it closed (code and reason), collection sizes and counters, the virtual
     * time, and what the program saw on the wire and handed to the applications ([wire]: a digest of every datagram and
     * every byte read for the connection program; datagram lengths and events for the 0-RTT one, whose bytes TLS
     * randomizes).
     */
    private fun observation(
        pair: CorePair,
        wire: String,
    ): String = ends(listOfNotNull(pair.client, pair.server), pair.now.toString(), wire)

    private fun ends(
        cores: List<io.kuicksilver.quic.ConnectionCore>,
        now: String,
        wire: String,
    ): String =
        cores.joinToString(" | ") { c ->
            val s = c.stats
            "${c.state} closed=${c.closedReason?.let { "${it::class.simpleName}:${it.message}" }} ${c.sizesForTest().toSortedMap()} " +
                "sent=${s.packetsSent}/${s.bytesSent} received=${s.packetsReceived}/${s.bytesReceived} lost=${s.lostPackets} " +
                "keyUpdates=${s.keyUpdates} rtt=${s.smoothedRtt} cwnd=${s.cwnd} mtu=${s.pathMtu}"
        } + " at $now wire $wire"

    /** (the run's trace, what it ended in) for a run that hands [observe] to the program. */
    private fun traced(run: (observe: (CorePair, String) -> Unit) -> Unit): Pair<String, String> {
        var end = "no end"
        val (_, text, thrown) = FuzzTrace.record(true) { run { pair, wire -> end = observation(pair, wire) } }
        return assertNotNull(text) to end + (thrown?.let { " threw ${it::class.simpleName}: ${it.message}" } ?: "")
    }

    /** [traced] for the connection program, which runs over an [EndpointNet]. */
    private fun tracedConn(input: ByteArray): Pair<String, String> {
        var end = "no end"
        val (_, text, thrown) =
            FuzzTrace.record(true) {
                ConnectionFuzz(input, NullCryptoProvider, observe = {
                    net,
                    wire,
                    ->
                    end = observation(net, wire)
                }).run()
            }
        return assertNotNull(text) to end + (thrown?.let { " threw ${it::class.simpleName}: ${it.message}" } ?: "")
    }

    /** Inputs with the same trace must end alike: a meaning the trace does not state shows as two ends for one trace. */
    private fun assertTheTraceStatesEveryMeaning(
        what: String,
        runs: List<Pair<String, String>>,
    ) {
        val groups = runs.groupBy({ it.first }, { it.second })
        assertTrue(groups.values.any { it.size > 1 }, "$what: no two inputs share a trace, so nothing was compared")
        for ((trace, ends) in groups) {
            assertEquals(
                1,
                ends.toSet().size,
                "$what: inputs with one trace ended differently:\n${ends.toSet().joinToString("\n")}\n$trace",
            )
        }
    }

    private val prefix =
        ConnProgram
            .Builder(0)
            .app(0, 0, ConnProgram.num(300), byteArrayOf(0))
            .app(1, 0, ConnProgram.num(200), byteArrayOf(0))
            .step()
            .frame(0, 3, "PING")
            .tick(15) // 3 s: long enough for path MTU probes, so PMTUD on or off ends differently
            .build()

    /** The bytes after the operation under test: a RAW of 2 bytes reads them so, the others read what they need. */
    private val arguments = byteArrayOf(0x00, 0x02, 0x41, 0x42, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x07, 0x07)

    @Test fun everyMeaningOfAConnProgramOperationByteIsInItsTrace() {
        val runs =
            (0..255).map { o -> tracedConn(prefix + byteArrayOf(o.toByte()) + arguments) }
        assertTheTraceStatesEveryMeaning("ConnProgram operation byte", runs)
    }

    @Test fun everyMeaningOfTheConnProgramFlagsIsInItsTrace() {
        val runs =
            (0..255).map { f ->
                tracedConn(prefix.copyOf().also { it[0] = f.toByte() } + arguments)
            }
        // every bit of the flags byte has a meaning since the path flags came, and the trace names each one set: no two
        // values share a trace, and each run must end as its own trace says (the same run twice ends alike)
        assertEquals(256, runs.map { it.first }.toSet().size, "two values of the flags byte share a trace")
        val again = tracedConn(prefix.copyOf().also { it[0] = 0xff.toByte() } + arguments)
        assertTheTraceStatesEveryMeaning("ConnProgram flags", runs + listOf(again))
    }

    /**
     * [outcome][flags], a bidirectional and a unidirectional client stream opened in 0-RTT with 20000 bytes each (more
     * than the smaller remembered limits let through), a round, then the byte under test and its arguments.
     */
    private fun zeroRtt(
        outcome: Int,
        flags: Int,
        op: Int,
    ): ByteArray {
        val big = ConnProgram.num(20_000)
        return byteArrayOf(outcome.toByte(), flags.toByte(), 0x00) + big + byteArrayOf(0, 0x80.toByte()) + big +
            byteArrayOf(0, 0x11, op.toByte(), 5, 3, 7, 9, 2, 1, 4, 6, 0x07, 0x05)
    }

    @Test fun everyMeaningOfAZeroRttProgramByteIsInItsTrace() {
        val run = { b: ByteArray -> traced { obs -> ZeroRttConnectionFuzz(b, observe = obs).run() } }
        assertTheTraceStatesEveryMeaning("ZeroRttProgram operation byte", (0..255).map { run(zeroRtt(0, 0, it)) })
        assertTheTraceStatesEveryMeaning("ZeroRttProgram flags", (0..255).map { run(zeroRtt(0, it, 0x07)) })
        assertTheTraceStatesEveryMeaning("ZeroRttProgram outcome", (0..255).map { run(zeroRtt(it, 0, 0x07)) })
    }

    /** The Int constants of a program object: flags, outcomes and limits. */
    private fun constants(o: Any): Map<String, Int> =
        o.javaClass.declaredFields
            .filter {
                java.lang.reflect.Modifier
                    .isStatic(it.modifiers) && it.type == Int::class.javaPrimitiveType
            }.associate { it.name to it.getInt(null) }

    /** The setup-byte bits of [ConnProgram], named in [ConnProgram.SETUP_NAMES]. */
    private val setupBits =
        setOf("PREFERRED", "COMPATIBLE", "CLIENT_NO_ECN_READ", "SERVER_NO_ECN_READ", "CLIENT_NO_DF", "SERVER_NO_DF", "NO_ICMP_HINTS", "BBR")

    @Test fun everyConnProgramFlagIsNamedInTheTrace() {
        // PATH codes and their variant bytes are operations, traced by what they do; the rest are flags or setup bits
        val all = constants(ConnProgram).filterKeys { !it.startsWith("E_") && !it.startsWith("MIGRATE_") && !it.startsWith("CAPS_") }
        val flags = all - setOf("MAX_FRAME", "MAX_OPS") - setupBits
        assertEquals(flags.values.toSet(), ConnProgram.FLAG_NAMES.keys, "a flag constant without a name in FLAG_NAMES")
        assertEquals(all.filterKeys { it in setupBits }.values.toSet(), ConnProgram.SETUP_NAMES.keys, "a setup bit without a name")
        for ((bit, name) in ConnProgram.FLAG_NAMES) {
            val (_, text, _) = FuzzTrace.record(true) { ConnectionFuzz(byteArrayOf(bit.toByte(), 0x07), NullCryptoProvider).run() }
            assertTrue(assertNotNull(text).lines().first().contains(name), "flag $name is not in the trace: $text")
        }
        for ((bit, name) in ConnProgram.SETUP_NAMES) {
            val input = byteArrayOf(ConnProgram.SETUP.toByte(), bit.toByte(), 0x07)
            val (_, text, _) = FuzzTrace.record(true) { ConnectionFuzz(input, NullCryptoProvider).run() }
            assertTrue(assertNotNull(text).lines()[1].contains(name), "setup bit $name is not in the trace: $text")
        }
    }

    @Test fun everyZeroRttProgramFlagAndOutcomeIsNamedInTheTrace() {
        val all = constants(ZeroRttProgram) - setOf("MAX_OPS", "OUTCOMES")
        val outcomes =
            setOf("ACCEPT", "REJECT_APPLICATION", "REJECT_LIMITS", "REJECT_REQUIRED", "REJECT_ALPN", "NO_SERVER_EARLY_DATA", "LOST")
        assertEquals((0 until ZeroRttProgram.OUTCOMES).toSet(), all.filterKeys { it in outcomes }.values.toSet())
        assertEquals(ZeroRttProgram.OUTCOMES, ZeroRttProgram.OUTCOME_NAMES.size, "an outcome without a name in OUTCOME_NAMES")
        val flags = all - outcomes
        assertEquals(flags.values.toSet(), ZeroRttProgram.FLAG_NAMES.keys, "a flag constant without a name in FLAG_NAMES: $flags")
        for ((bit, name) in ZeroRttProgram.FLAG_NAMES) {
            val (_, text, _) = FuzzTrace.record(true) { ZeroRttConnectionFuzz(byteArrayOf(0, bit.toByte(), 0x07)).run() }
            assertTrue(assertNotNull(text).lines().first().contains(name), "flag $name is not in the trace: $text")
        }
    }

    @Test fun negative_aRunThatDecodesNothingHasNoFingerprint() {
        assertNull(FuzzTrace.record(false) { }.first)
        assertNull(FuzzTrace.record(false) { ConnectionFuzz(ByteArray(0), NullCryptoProvider).run() }.first)
    }
}
