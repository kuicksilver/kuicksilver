// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.fuzz

import io.kuicksilver.quic.CorePair
import io.kuicksilver.quic.NullCryptoProvider
import io.kuicksilver.quic.core.sizesForTest
import io.kuicksilver.quic.ksl
import io.kuicksilver.tls.QuicCrypto
import java.io.File
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
 * meaning its trace does not state fails here. Every flag bit, setup bit and outcome has the constant, value and trace name
 * tools/fuzz/formats/flags.txt gives it ([flagTableFindings]): a renamed, moved or duplicated flag fails here, as it fails
 * tools/check/fuzz-formats.py, which checks the same table against the sources.
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
        // every flag bit means something since MTU (128): the inputs that share a trace are the MTU ones whose remembered byte
        // (253 and above: the server's own value) differs
        val mtu =
            (253..255).map { r ->
                run(
                    byteArrayOf(0, ZeroRttProgram.MTU.toByte(), 0, 0xff.toByte(), r.toByte()) +
                        zeroRtt(0, 0, 0x07).copyOfRange(2, zeroRtt(0, 0, 0x07).size),
                )
            }
        assertTheTraceStatesEveryMeaning("ZeroRttProgram flags", (0..255).map { run(zeroRtt(0, it, 0x07)) } + mtu)
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

    /** The tables of the compiled programs, as [flagTableFindings] reads them. */
    private fun compiled(): Map<String, ProgramTable> =
        mapOf(
            "ConnProgram" to
                ProgramTable(
                    constants(ConnProgram),
                    mapOf(
                        "flags" to ConnProgram.FLAG_NAMES.entries.map { it.key to it.value },
                        "setup" to ConnProgram.SETUP_NAMES.entries.map { it.key to it.value },
                    ),
                ),
            "ZeroRttProgram" to
                ProgramTable(
                    constants(ZeroRttProgram),
                    mapOf(
                        "flags" to ZeroRttProgram.FLAG_NAMES.entries.map { it.key to it.value },
                        "outcome" to ZeroRttProgram.OUTCOME_NAMES.mapIndexed { i, n -> i to n },
                    ),
                ),
        )

    private val manifest: List<FlagRow> by lazy {
        val start = File(System.getProperty("user.dir")).absoluteFile
        val root =
            generateSequence(start) { it.parentFile }.firstOrNull { File(it, "tools/fuzz/campaign.sh").isFile }
                ?: throw AssertionError("tools/fuzz/campaign.sh not found above $start")
        parseFlagRows(File(root, "tools/fuzz/formats/flags.txt").readLines())
    }

    @Test fun everyFlagHasTheConstantBitAndTraceNameOfFlagsTxt() {
        val programs = compiled()
        assertEquals(programs.keys, manifest.map { it.program }.toSet(), "flags.txt lists other programs than the traced ones")
        val findings = programs.flatMap { (name, table) -> flagTableFindings(manifest, name, table) }
        assertEquals(emptyList(), findings, "the flags of the programs disagree with tools/fuzz/formats/flags.txt")
    }

    /** One finding of [flagTableFindings] on [table] and [rows] changed from what they are, containing [expected]. */
    private fun assertFinds(
        expected: String,
        rows: List<FlagRow> = manifest,
        program: String = "ConnProgram",
        table: ProgramTable = compiled().getValue(program),
    ) {
        val findings = flagTableFindings(rows, program, table)
        assertTrue(findings.any { expected in it }, "expected a finding with `$expected`, got $findings")
    }

    private fun ProgramTable.withNames(
        field: String,
        change: (List<Pair<Int, String>>) -> List<Pair<Int, String>>,
    ) = ProgramTable(constants, names + (field to change(names.getValue(field))))

    @Test fun negative_aTraceNameRenamedInTheProgramFails() =
        assertFinds(
            "ConnProgram flags 4: the program traces it as `pmtudOff`, flags.txt as `noPmtud`",
            table = compiled().getValue("ConnProgram").withNames("flags") { l -> l.map { if (it.first == 4) 4 to "pmtudOff" else it } },
        )

    @Test fun negative_aTraceNameRenamedInFlagsTxtFails() =
        assertFinds(
            "ConnProgram flags NO_PMTUD is traced as `pmtudOff` in flags.txt, not `noPmtud`",
            rows = manifest.map { if (it.constant == "NO_PMTUD") it.copy(trace = "pmtudOff") else it },
        )

    @Test fun negative_aConstantRenamedFails() {
        val t = compiled().getValue("ConnProgram")
        assertFinds("ConnProgram has no constant NO_PMTUD", table = ProgramTable(t.constants - "NO_PMTUD" + ("PMTUD_OFF" to 4), t.names))
    }

    @Test fun negative_aFlagMovedToAnotherBitFails() {
        val t = compiled().getValue("ConnProgram")
        assertFinds("ConnProgram.NO_PMTUD is 8, flags.txt says 4", table = ProgramTable(t.constants + ("NO_PMTUD" to 8), t.names))
    }

    @Test fun negative_aDuplicatedBitFails() =
        assertFinds(
            "ConnProgram flags: value 4 is listed twice",
            rows = manifest.map { if (it.constant == "DF" && it.program == "ConnProgram") it.copy(value = 4) else it },
        )

    @Test fun negative_aDuplicatedTraceNameFails() =
        assertFinds(
            "ConnProgram flags: the program gives trace name `df` twice",
            table = compiled().getValue("ConnProgram").withNames("flags") { l -> l.map { if (it.first == 16) 16 to "df" else it } },
        )

    @Test fun negative_aGapFails() {
        val rows = manifest.filterNot { it.program == "ZeroRttProgram" && it.constant == "SMALL" }
        assertFinds("ZeroRttProgram flags: the values are [1, 2, 8, 16, 32, 64, 128], not [1, 2, 4, 8, 16, 32, 64]", rows, "ZeroRttProgram")
    }

    @Test fun negative_aFlagWithoutARowFails() =
        assertFinds(
            "ZeroRttProgram outcome 6 `lost` has no row in flags.txt",
            rows = manifest.filterNot { it.program == "ZeroRttProgram" && it.constant == "LOST" },
            program = "ZeroRttProgram",
        )

    @Test fun negative_aRowWithoutItsFlagFails() =
        assertFinds(
            "ConnProgram setup 256 `extra`: the program has no such name",
            rows = manifest + FlagRow("ConnProgram", "setup", 256, "EXTRA", "extra"),
        )

    @Test fun negative_aRunThatDecodesNothingHasNoFingerprint() {
        assertNull(FuzzTrace.record(false) { }.first)
        assertNull(FuzzTrace.record(false) { ConnectionFuzz(ByteArray(0), NullCryptoProvider).run() }.first)
    }
}

/** One row of tools/fuzz/formats/flags.txt: a flag bit, setup bit or outcome of [program], its [constant] and its [trace] name. */
internal data class FlagRow(
    val program: String,
    val field: String,
    val value: Int,
    val constant: String,
    val trace: String,
)

/** A compiled program's Int [constants] and, per field of flags.txt, the values and trace names its name tables give. */
internal class ProgramTable(
    val constants: Map<String, Int>,
    val names: Map<String, List<Pair<Int, String>>>,
)

/** The rows of flags.txt in [lines] (comments and `program` lines left out); a malformed row throws. */
internal fun parseFlagRows(lines: List<String>): List<FlagRow> =
    lines.filter { it.isNotBlank() && !it.startsWith("#") && !it.startsWith("program ") }.map { line ->
        val f = line.trim().split(Regex("\\s+"))
        require(f.size == 5) { "flags.txt: a row needs <program> <field> <value> <CONSTANT> <trace name>: $line" }
        FlagRow(f[0], f[1], f[2].toInt(), f[3], f[4])
    }

/** NO_PMTUD -> noPmtud: the trace name of a flag constant. */
internal fun lowerCamel(constant: String): String =
    constant.lowercase().split('_').let { p -> p.first() + p.drop(1).joinToString("") { it.replaceFirstChar(Char::uppercase) } }

/**
 * How [program]'s compiled [table] disagrees with its [rows] of flags.txt: a row whose constant is missing or has another value,
 * whose trace name is not the constant's in lowerCamelCase or not what the program traces for that value; a value, constant or
 * trace name listed twice; bits that are not 1, 2, 4, ... and outcomes not 0, 1, 2, ... without a gap; a name the program
 * gives that no row lists, or gives twice.
 */
internal fun flagTableFindings(
    rows: List<FlagRow>,
    program: String,
    table: ProgramTable,
): List<String> {
    val out = ArrayList<String>()
    val mine = rows.filter { it.program == program }
    if (mine.isEmpty()) out += "$program has no row in flags.txt"
    for (r in mine) {
        val v = table.constants[r.constant]
        when {
            v == null -> out += "$program has no constant ${r.constant} (flags.txt: ${r.field} ${r.value} ${r.trace})"
            v != r.value -> out += "$program.${r.constant} is $v, flags.txt says ${r.value}"
        }
        if (r.trace != lowerCamel(r.constant)) {
            out += "$program ${r.field} ${r.constant} is traced as `${r.trace}` in flags.txt, not `${lowerCamel(r.constant)}`"
        }
    }
    for (field in (mine.map { it.field } + table.names.keys).toSortedSet()) {
        val listed = mine.filter { it.field == field }
        val given = table.names[field].orEmpty()
        for ((what, key) in listOf<Pair<String, (FlagRow) -> Any>>(
            "value" to { it.value },
            "constant" to { it.constant },
            "trace name" to { it.trace },
        )) {
            for ((k, n) in listed.groupingBy(key).eachCount()) if (n > 1) out += "$program $field: $what $k is listed twice in flags.txt"
        }
        for ((k, n) in given.groupingBy { it.second }.eachCount()) {
            if (n >
                1
            ) {
                out += "$program $field: the program gives trace name `$k` twice"
            }
        }
        for ((k, n) in given.groupingBy { it.first }.eachCount()) if (n > 1) out += "$program $field: the program names value $k twice"
        val values = listed.map { it.value }.toSortedSet().toList()
        val want = if (field == "outcome") values.indices.toList() else values.indices.map { 1 shl it }
        if (values != want) out += "$program $field: the values are $values, not $want (a gap, or a bit that is not one bit)"
        val traced = given.groupBy({ it.first }, { it.second })
        for (r in listed) {
            val t = traced[r.value]
            when {
                t == null -> {
                    out += "$program $field ${r.value} `${r.trace}`: the program has no such name"
                }

                r.trace !in t -> {
                    out +=
                        "$program $field ${r.value}: the program traces it as `${t.joinToString()}`, flags.txt as `${r.trace}`"
                }
            }
        }
        val rowValues = listed.map { it.value }.toSet()
        for ((value, trace) in given) if (value !in rowValues) out += "$program $field $value `$trace` has no row in flags.txt"
    }
    return out
}
