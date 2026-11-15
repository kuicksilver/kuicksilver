// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.fuzz

import io.kuicksilver.quic.fuzz.ConnProgram.BBR
import io.kuicksilver.quic.fuzz.ConnProgram.COMPATIBLE
import io.kuicksilver.quic.fuzz.ConnProgram.DF
import io.kuicksilver.quic.fuzz.ConnProgram.ECN
import io.kuicksilver.quic.fuzz.ConnProgram.E_CAPS
import io.kuicksilver.quic.fuzz.ConnProgram.E_CRASH
import io.kuicksilver.quic.fuzz.ConnProgram.E_ECN_PATH
import io.kuicksilver.quic.fuzz.ConnProgram.E_ICMP
import io.kuicksilver.quic.fuzz.ConnProgram.E_MIGRATE
import io.kuicksilver.quic.fuzz.ConnProgram.E_MTU
import io.kuicksilver.quic.fuzz.ConnProgram.E_PREFERRED_DOWN
import io.kuicksilver.quic.fuzz.ConnProgram.E_PREFERRED_LOSS
import io.kuicksilver.quic.fuzz.ConnProgram.E_PTB
import io.kuicksilver.quic.fuzz.ConnProgram.E_PTB_INFLIGHT
import io.kuicksilver.quic.fuzz.ConnProgram.E_RESET
import io.kuicksilver.quic.fuzz.ConnProgram.E_RETRY
import io.kuicksilver.quic.fuzz.ConnProgram.E_STRANGER
import io.kuicksilver.quic.fuzz.ConnProgram.E_VN
import io.kuicksilver.quic.fuzz.ConnProgram.LIVE
import io.kuicksilver.quic.fuzz.ConnProgram.PREFERRED
import io.kuicksilver.quic.fuzz.ConnProgram.RETRY
import io.kuicksilver.quic.fuzz.ConnProgram.SETUP
import io.kuicksilver.quic.fuzz.ConnProgram.VN
import io.kuicksilver.quic.fuzz.ConnProgram.num
import kotlin.random.Random

/**
 * Programs of the connection fuzzer for the path, ECN, address, version and reset dimensions ([ConnProgram] flags DF, ECN, RETRY,
 * VN, SETUP and the PATH operations): the seeds of `connectionNull` and `connectionTls` (SeedCorpusTest) and the fixed set that
 * ConnectionSeededTest runs in every build, which must reach every feature of [QuicReach.FEATURES]. [random] makes more of them.
 */
internal object ConnectionPathSeeds {
    private fun b(
        flags: Int,
        setup: Int = 0,
    ) = ConnProgram.Builder(if (setup != 0) flags or SETUP else flags, setup)

    private fun ConnProgram.Builder.bulk(
        side: Int = 0,
        bytes: Long = 20_000,
    ) = app(side, 0, num(bytes), byteArrayOf(1))

    /** Rounds with [ms5] x 5 ms between them. */
    private fun ConnProgram.Builder.run(
        n: Int,
        ms5: Int = 4,
    ) = apply { repeat(n) { step(ms5) } }

    private fun one(v: Int) = byteArrayOf(v.toByte())

    val programs: Map<String, ByteArray> by lazy {
        val m = LinkedHashMap<String, ByteArray>()
        // DPLPMTUD: the search over a 1472-byte link, probes acknowledged, the size raised
        m["pmtud-search"] =
            b(DF)
                .bulk()
                .run(30)
                .tick(10)
                .bulk(1)
                .run(30)
                .tick(15)
                .run(10)
                .build()
        // the link shrinks under a raised MTU: full-size packets vanish (a black hole), the size falls back to 1200
        m["pmtud-black-hole"] =
            b(DF)
                .bulk()
                .run(30)
                .tick(10)
                .run(10)
                .path(0, E_MTU, one(20))
                .bulk()
                .run(40)
                .tick(10)
                .run(20)
                .build()
        // a narrower link from the start, silent: the probes above it are lost and fail at their PROBE_TIMER, the size stays below it
        m["pmtud-narrow-link"] =
            b(
                DF,
            ).path(
                0,
                E_MTU,
                one(30),
            ).path(1, E_MTU, one(30))
                .bulk()
                .bulk(1)
                .run(30)
                .tick(15)
                .run(10)
                .tick(15)
                .bulk()
                .run(20)
                .tick(15)
                .run(20)
                .build()
        // a router that answers too-large datagrams with Packet Too Big: the probes above the link MTU are settled by it
        m["pmtud-icmp"] =
            b(DF)
                .path(0, E_MTU, one(30))
                .path(0, E_ICMP)
                .path(1, E_MTU, one(40))
                .path(1, E_ICMP)
                .bulk()
                .bulk(1)
                .run(40)
                .tick(10)
                .run(20)
                .build()
        // forged Packet Too Big messages: a valid quote with a small MTU, garbage, a stranger's destination, a truncated quote
        m["pmtud-forged-ptb"] =
            b(DF)
                .bulk()
                .run(20)
                .path(0, E_PTB, one(0), num(1300), one(0))
                .run(5)
                .path(1, E_PTB, one(1), num(1400), one(0))
                .path(
                    0,
                    E_PTB,
                    one(2),
                    num(1280),
                    one(0),
                ).path(1, E_PTB, one(3), num(1250), one(9))
                .path(0, E_PTB, one(0), num(1100), one(0))
                .run(30)
                .tick(10)
                .run(10)
                .build()
        // a router's Packet Too Big for a datagram in flight, claiming less than the path carries
        m["pmtud-ptb-in-flight"] =
            b(DF)
                .bulk()
                .run(20)
                .tick(5)
                .bulk()
                .step()
                .path(0, E_PTB_INFLIGHT, one(20))
                .run(30)
                .build()
        // the sockets lose DF and ECN marking mid-connection
        m["caps-lost"] =
            b(DF or ECN)
                .bulk()
                .run(20)
                .path(0, E_CAPS, one(1))
                .path(1, E_CAPS, one(0))
                .bulk(1)
                .run(20)
                .build()
        // ECN: validated on a clean path; bleached, remarked to ECT(1), ECT dropped, all CE
        m["ecn-validate"] =
            b(ECN)
                .bulk()
                .bulk(1)
                .run(30)
                .build()
        m["ecn-bleach"] =
            b(ECN or LIVE)
                .path(0, E_ECN_PATH, one(1))
                .path(1, E_ECN_PATH, one(1))
                .run(10)
                .bulk()
                .bulk(1)
                .run(30)
                .build()
        m["ecn-remark"] =
            b(ECN)
                .path(0, E_ECN_PATH, one(3))
                .bulk()
                .run(30)
                .build()
        m["ecn-drop-marked"] =
            b(ECN or LIVE)
                .path(0, E_ECN_PATH, one(4))
                .run(20)
                .tick(10)
                .run(10)
                .bulk()
                .run(30)
                .tick(15)
                .run(10)
                .build()
        m["ecn-ce"] =
            b(ECN)
                .bulk()
                .run(10)
                .path(0, E_ECN_PATH, one(2))
                .bulk()
                .run(20)
                .path(0, E_ECN_PATH, one(0))
                .bulk()
                .run(20)
                .build()
        m["ecn-ce-bbr"] =
            b(ECN, BBR)
                .bulk()
                .run(10)
                .path(0, E_ECN_PATH, one(2))
                .bulk()
                .run(30)
                .build()
        // ECN marks the client's socket cannot read
        m["ecn-unread"] = b(ECN, ConnProgram.CLIENT_NO_ECN_READ).bulk(1).run(30).build()
        // Retry and Version Negotiation inside a stateful run, with streams opened before the answer
        m["retry"] =
            b(RETRY or LIVE)
                .bulk()
                .run(20)
                .bulk(1)
                .run(10)
                .build()
        m["vn-incompatible"] =
            b(VN or LIVE)
                .bulk()
                .run(20)
                .bulk(1)
                .run(10)
                .build()
        m["vn-compatible"] =
            b(VN or LIVE, COMPATIBLE)
                .bulk()
                .run(20)
                .bulk(1)
                .run(10)
                .build()
        m["vn-and-retry"] = b(VN or RETRY or LIVE).bulk().run(30).build()
        // a forged Version Negotiation before the server's first packet: the client restarts in v2, the server offers v1 too, so
        // the client must refuse the handshake (RFC 9368 section 4)
        m["vn-forged-downgrade"] = b(VN or LIVE, COMPATIBLE).path(1, E_VN, one(1)).run(30).build()
        // forged Retry and Version Negotiation packets during and after the handshake: ignored
        m["retry-forged"] =
            b(RETRY or LIVE)
                .step()
                .path(1, E_RETRY, one(1))
                .path(1, E_RETRY, one(2))
                .run(10)
                .path(1, E_RETRY, one(0))
                .path(1, E_RETRY, one(3))
                .path(1, E_RETRY, one(4))
                .path(1, E_VN, one(2))
                .path(1, E_VN, one(0))
                .run(20)
                .build()
        m["vn-listing-ours"] =
            b(LIVE)
                .path(1, E_VN, one(2))
                .run(20)
                .path(1, E_VN, one(1))
                .run(10)
                .build()
        // Stateless Resets to either side: a valid one, then each kind that must be ignored
        for (side in 0..1) {
            for (v in 0..7) {
                m["reset-$v-to-${if (side == 0) "client" else "server"}"] =
                    b(0)
                        .bulk()
                        .run(6)
                        .path(side, E_RESET, one(v), num(60L + v))
                        .run(10)
                        .build()
            }
        }
        // retired and unused tokens exist once IDs were retired: a migration retires the first ones
        m["reset-retired"] =
            b(
                0,
                PREFERRED,
            ).bulk()
                .run(30)
                .path(0, E_RESET, one(1), num(80))
                .path(0, E_RESET, one(2), num(80))
                .path(1, E_RESET, one(1), num(50))
                .run(10)
                .build()
        // a failed validation of the active path (RFC 9000 section 9.3.2), from inputs the campaigns found: another validated path
        // takes over; the only validated one is on the server's other local address, so the server goes back to that peer address
        // from its own; no validated peer address is left, so the connection closes
        m["fallback-after-failed-validation"] =
            hex(
                "0083fdf42e3df42e2ef43af4f4f52ef402fdf43d02f4f4f5f4fd02f42e3df4f52ef43af4f5f4f43d02f4f4f5f4fd02f42e3d" +
                    "f4f52ef43af4eff42ef4fdf5f4f43d02f4f4f5f4fdf4f5f4f43d02f4f4f5f4fd02f42e3df4f52ef43af4eff42e02f42e3df4" +
                    "f52ef43af4eff42ef4fdf4ce3d0224",
            )
        m["revert-to-last-validated-address"] =
            hex(
                "fd3d02f4fdf4f43df502f4f42ef4fd3d02f4f52ef4f5f42ef4fd3d022ef4fd3d02f4f52e2ef4fd740254f4f52ef4fd3d397c" +
                    "128412121235f512121c24397c12121232e3f524022ef4fd3d02f4f52e2ef4fd740254f4f53d2ef4f42ef4fd3d02f4f52ef4" +
                    "f5f42ef4fd3d02f4f4f4f5f42ef4fd3d3df4f52e2ef4f42ef4fd3d02f4f412f9009a28",
            ).copyOfRange(0, 70) + // up to the revert, before the client's idle timeout; the rest of the input only waits
            // then the client gives a new ID (a frame injected into its next packet): the reverted path, waiting for one, sends again
            ConnProgram
                .Builder(0)
                .steps(2)
                .frameRaw(0, 3, ConnProgram.FRAME_KINDS.indexOf("NEW_CONNECTION_ID"), num(50), num(0), byteArrayOf(8, 0x5d))
                .tick(15) // the client's window is full of unacknowledged packets: the frame leaves with a PTO probe
                .tick(15)
                .steps(4)
                .build()
                .let { it.copyOfRange(1, it.size) }
        m["no-viable-path"] =
            hex(
                "00a49c9ca4e47f3113113113313914ff31131102f42e3df4f52ef43af4f5f4464646f43d000a00001100000005fd02f42e3d" +
                    "2ef43af4ef",
            )
        // the client migrates, so the server sends with one of the client's IDs that has a reset token; then that token arrives from a
        // stranger, with the server's own ID as destination (routed to the connection, not by the peer's address): not a reset
        m["reset-stranger-after-migration"] =
            b(0)
                .bulk()
                .run(10)
                .path(0, E_MIGRATE, one(0))
                .run(15)
                .path(0, E_MIGRATE, one(1))
                .bulk()
                .run(15)
                .path(1, E_RESET, one(7), num(80))
                .run(5)
                .path(1, E_RESET, one(4), num(80))
                .run(5)
                .bulk(1)
                .run(10)
                .build()
        // the server forgets the connection: the client's next packets draw real Stateless Resets, which end it
        m["server-crash"] =
            b(0)
                .bulk()
                .run(6)
                .path(1, E_CRASH)
                .bulk()
                .run(20)
                .tick(5)
                .run(10)
                .build()
        // the server's preferred address: the client moves after the handshake; it cannot reach it; it goes down after the move
        m["preferred-move"] =
            b(0, PREFERRED)
                .bulk()
                .run(20)
                .bulk(1)
                .run(20)
                .build()
        m["preferred-unreachable"] =
            b(0, PREFERRED)
                .path(0, E_PREFERRED_LOSS)
                .bulk()
                .run(20)
                .tick(15)
                .run(20)
                .build()
        m["preferred-down"] =
            b(0, PREFERRED)
                .run(20)
                .path(1, E_PREFERRED_DOWN)
                .bulk()
                .run(20)
                .tick(5)
                .run(10)
                .build()
        // the preferred-address socket does neither DF nor ECN, the main one does both: the server's path there must do neither
        m["preferred-socket-without-df-ecn"] =
            b(DF or ECN or LIVE, PREFERRED)
                .path(1, E_CAPS, one(3))
                .path(1, E_CAPS, one(2))
                .bulk()
                .run(30)
                .bulk(1)
                .run(30)
                .build()
        m["preferred-with-rebinding"] =
            b(DF or ECN, PREFERRED)
                .bulk()
                .run(10)
                .net(0, 8)
                .run(10)
                .net(0, 8)
                .bulk()
                .run(20)
                .build()
        // the client migrates to a new socket, switches to it, closes the old path; a stranger copies a server datagram
        m["client-migration"] =
            b(DF or ECN)
                .bulk()
                .run(10)
                .path(0, E_MIGRATE, one(0))
                .run(10)
                .path(0, E_MIGRATE, one(1))
                .bulk()
                .run(10)
                .path(0, E_MIGRATE, one(2))
                .run(10)
                .build()
        m["stranger"] =
            b(0, PREFERRED)
                .bulk()
                .run(5)
                .path(1, E_STRANGER)
                .run(5)
                .path(1, E_STRANGER)
                .run(10)
                .build()
        m
    }

    private fun hex(h: String): ByteArray = ByteArray(h.length / 2) { h.substring(2 * it, 2 * it + 2).toInt(16).toByte() }

    /**
     * A random program over every dimension: setup bits, transfers both ways, network faults and the PATH operations, with time
     * between them (the seeded test's breadth; the fuzzer's search is open-ended).
     */
    fun random(r: Random): ByteArray {
        val flags = r.nextInt(256) and SETUP.inv()
        val bld = b(flags, r.nextInt(1, 256))
        repeat(r.nextInt(10, 40)) {
            when (r.nextInt(10)) {
                0, 1 -> {
                    bld.bulk(r.nextInt(2), r.nextLong(100, 20_000))
                }

                2, 3 -> {
                    bld.run(r.nextInt(1, 6), r.nextInt(1, 8))
                }

                4 -> {
                    bld.tick(r.nextInt(1, 16))
                }

                5 -> {
                    bld.net(r.nextInt(2), r.nextInt(16))
                }

                else -> {
                    val e = r.nextInt(1, 15)
                    val args =
                        when (e) {
                            E_MTU, E_ECN_PATH, E_MIGRATE, E_CAPS, E_RETRY, E_VN, E_PTB_INFLIGHT -> arrayOf(one(r.nextInt(256)))
                            E_PTB -> arrayOf(one(r.nextInt(4)), num(r.nextLong(1100, 1600)), one(r.nextInt(64)))
                            E_RESET -> arrayOf(one(r.nextInt(8)), num(r.nextLong(10, 200)))
                            else -> emptyArray()
                        }
                    bld.path(r.nextInt(2), e, *args)
                }
            }
        }
        return bld.run(5).build()
    }
}
