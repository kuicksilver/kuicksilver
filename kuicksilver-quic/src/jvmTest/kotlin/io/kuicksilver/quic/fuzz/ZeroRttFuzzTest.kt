// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.fuzz

import com.code_intelligence.jazzer.junit.FuzzTest
import io.kuicksilver.quic.TimeMark
import io.kuicksilver.quic.core.rememberedBlob
import io.kuicksilver.quic.core.rememberedParameters
import io.kuicksilver.quic.endpoint.ZeroRttReplayRegister
import io.kuicksilver.quic.wire.TransportParametersCodec
import io.kuicksilver.tls.TlsRole
import kotlin.random.Random

/** Fuzz targets of the transport's 0-RTT state: the server's replay register and what a client ticket remembers. */
class ZeroRttFuzzTest {
    /**
     * `replayRegister`: `[layout][op]*`, a program of operations on a [ZeroRttReplayRegister] (of the production layout or
     * a small one, so that full halves, compaction and rotation are reached) checked against a model of what it must
     * refuse. Ops (`[op][args]`): 0 admit identity `[k]` of a pool of 64; 1 release `[k]`; 2 the monotonic clock advances
     * by `[u16]` ms; 3 the wall clock steps by `[s16]` × 10 ms against it; 4 admit `[u16]` fresh identities (fills the
     * stripes); 5 admit identity `[32 bytes]`.
     *
     * The register may refuse anything (it fails closed); it must never admit an identity it admitted, and did not
     * release, less than [ZeroRttReplayRegister.HALF_SPAN] of monotonic time ago, nor one that OpenSSL could still find
     * fresh by the wall clock: OpenSSL accepts a ticket age within a 10 s window, so a replay whose wall clock is within
     * 10 s (plus 1 s of slack) of the first admission's, in either direction, could pass.
     */
    @FuzzTest(maxDuration = "60s")
    fun replayRegister(data: ByteArray) {
        if (data.isEmpty()) return
        val (stripes, slots) = LAYOUTS[(data[0].toInt() and 0xff) % LAYOUTS.size]
        val reg = ZeroRttReplayRegister(Random(7), stripes, slots)
        var mono = 1_000_000_000_000L // ns
        var wallOffset = 1_700_000_000_000L // wall ms - mono ms
        val held = HashMap<List<Byte>, ArrayList<LongArray>>() // identity -> (mono ns, wall ms) of unreleased admissions
        var fresh = 0L
        var p = 1

        fun u8(): Int = if (p < data.size) data[p++].toInt() and 0xff else 0

        fun u16(): Int = (u8() shl 8) or u8()

        fun admit(id: ByteArray) {
            val now = TimeMark(mono)
            val wall = mono / 1_000_000 + wallOffset
            val ok = reg.admit(id, now, wall)
            val key = id.toList()
            if (ok) {
                for (a in held[key].orEmpty()) {
                    val sinceMono = mono - a[0]
                    val sinceWall = wall - a[1]
                    check(sinceMono >= ZeroRttReplayRegister.HALF_SPAN.inWholeNanoseconds) {
                        "identity re-admitted ${sinceMono / 1_000_000} ms (monotonic) after its first admission"
                    }
                    check(sinceWall > 11_000 || sinceWall < -11_000) {
                        "identity re-admitted while still fresh by the wall clock ($sinceWall ms after its first admission)"
                    }
                }
                held.getOrPut(key) { ArrayList() } += longArrayOf(mono, wall)
            }
        }

        fun pool(k: Int) = ByteArray(32) { (k * 31 + it).toByte() }
        var ops = 0
        while (p < data.size && ops++ < 2000) {
            when (u8() % 6) {
                0 -> {
                    admit(pool(u8() % 64))
                }

                1 -> {
                    val id = pool(u8() % 64)
                    reg.release(id)
                    held.remove(id.toList())
                }

                2 -> {
                    mono += u16().toLong() * 1_000_000
                }

                3 -> {
                    wallOffset += u16().toShort().toLong() * 10
                }

                4 -> {
                    repeat(u16() % 4096) { admit(ByteArray(32).also { b -> Random(fresh++).nextBytes(b) }) }
                }

                else -> {
                    admit(ByteArray(32) { u8().toByte() })
                }
            }
        }
    }

    /**
     * `rememberedTicket`: what a client ticket remembers (`QuicSessionTicket.remembered`, a public property the application
     * can set) is read back without an exception: malformed bytes give no 0-RTT. Input bit 0 of `[flags]`: the rest is
     * the blob itself; else it is `[alpn length][alpn][transport parameters]` re-encoded through [rememberedBlob].
     */
    @FuzzTest(maxDuration = "60s")
    fun rememberedTicket(data: ByteArray) {
        if (data.isEmpty()) return
        val rest = data.copyOfRange(1, data.size)
        val blob =
            if (data[0].toInt() and 1 != 0 || rest.isEmpty()) {
                rest
            } else {
                val n = minOf(rest[0].toInt() and 0xff, rest.size - 1)
                rememberedBlob(rest.decodeToString(1, 1 + n), rest.copyOfRange(1 + n, rest.size))
            }
        val parsed = rememberedParameters(blob) ?: return
        // what was read back encodes again (the client keeps it for the comparison at handshake completion)
        TransportParametersCodec.encode(parsed.second, TlsRole.Server, 0)
        check(parsed.first.length <= 255) { "an ALPN of ${parsed.first.length} characters" }
    }

    private companion object {
        /** (stripes, slots per half) of the register under test: tiny ones reach full halves within a few hundred admissions. */
        val LAYOUTS = listOf(1 to 8, 2 to 16, 4 to 64, ZeroRttReplayRegister.STRIPES to ZeroRttReplayRegister.SLOTS)
    }
}
