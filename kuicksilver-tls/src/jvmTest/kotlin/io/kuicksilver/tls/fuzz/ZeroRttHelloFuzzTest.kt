// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.tls.fuzz

import com.code_intelligence.jazzer.junit.FuzzTest
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.native.KslLoader
import io.kuicksilver.tls.ClientHelloScan
import io.kuicksilver.tls.DriveResult
import io.kuicksilver.tls.EarlyDataAdmission
import io.kuicksilver.tls.EncryptionLevel
import io.kuicksilver.tls.Fixtures
import io.kuicksilver.tls.KslQuicCrypto
import io.kuicksilver.tls.Pump
import io.kuicksilver.tls.QuicTlsSession
import io.kuicksilver.tls.TlsEvent
import io.kuicksilver.tls.TlsException

/**
 * Fuzz targets of the server's 0-RTT gate (ADR-0015): the ClientHello scan that finds the resumed ticket's identity before
 * `ksl` processes the hello, and the hello as a whole through a real server session (OpenSSL, the ksl ticket callbacks,
 * the replay admission).
 */
@OptIn(ExperimentalKuicksilverApi::class)
class ZeroRttHelloFuzzTest {
    /**
     * `clientHelloScan`: `[fragment size][hello]`. Feeding the hello in fragments gives the result of feeding it whole; a
     * ticket identity is 32 bytes; early data implies an identity; the scan holds at most its bound.
     */
    @FuzzTest(maxDuration = "60s")
    fun clientHelloScan(data: ByteArray) {
        if (data.isEmpty()) return
        val step = (data[0].toInt() and 0xff) + 1
        val hello = data.copyOfRange(1, data.size)
        val max = 2048
        val whole = ClientHelloScan(max).feed(hello, 0, hello.size)
        val scan = ClientHelloScan(max)
        var parts: ClientHelloScan.Result? = null
        var off = 0
        while (off < hello.size) {
            val n = minOf(step, hello.size - off)
            val r = scan.feed(hello, off, n)
            check(parts == null || r === parts) { "the result changed after it was decided" }
            parts = r
            off += n
        }
        if (hello.isEmpty()) parts = scan.feed(hello, 0, 0)
        check((whole == null) == (parts == null)) { "whole: $whole, in fragments: $parts" }
        if (whole != null && parts != null) {
            check(whole.earlyData == parts.earlyData) { "early data differs between whole and fragmented feeding" }
            check(whole.ticketId.contentEqualsNullable(parts.ticketId)) { "ticket identity differs between whole and fragmented feeding" }
            for (r in listOf(whole, parts)) {
                r.ticketId?.let { check(it.size == 32) { "ticket identity of ${it.size} bytes" } }
                check(!r.earlyData || r.ticketId != null) { "early data without a ticket identity" }
            }
        }
    }

    /**
     * `zeroRttHello`: `[flags][rest]`. Flags bit 0 clear: rest is a ClientHello given to a server session with early data
     * on. Bit 0 set: a fresh resumption ClientHello offering 0-RTT is made in this process (a full handshake issues the
     * ticket) and given to two server sessions sharing one admission; rest is `[fragment size][(u16 offset, xor)*]`, the
     * edits applied to the second copy when bit 1 is set (else it is an exact replay); bit 2 interleaves the two deliveries.
     *
     * Invariants: no exception other than [TlsException] out of the session; a session that accepted early data had its
     * ticket identity admitted and not released; a session that did not accept early data holds no admission; of two
     * deliveries of one ticket at most one gets early data (the replay is refused).
     */
    @FuzzTest(maxDuration = "60s")
    fun zeroRttHello(data: ByteArray) {
        if (data.isEmpty()) return
        KslLoader.ensureLoaded()
        val flags = data[0].toInt()
        if (flags and 1 == 0) {
            val admission = RecordingAdmission()
            val s = Server(admission)
            try {
                s.deliver(data.copyOfRange(1, minOf(data.size, 1 + 16_384)), 16_384)
                s.checkSettled()
            } finally {
                s.close()
            }
            return
        }
        val hello = freshResumptionHello()
        val step = if (data.size > 1) (data[1].toInt() and 0xff) + 1 else hello.size
        val second = hello.copyOf()
        if (flags and 2 != 0) {
            var p = 2
            var edits = 0
            while (p + 2 < data.size && edits++ < 8) {
                val off = (((data[p].toInt() and 0xff) shl 8) or (data[p + 1].toInt() and 0xff)) % second.size
                second[off] = (second[off].toInt() xor data[p + 2].toInt()).toByte()
                p += 3
            }
        }
        val admission = RecordingAdmission()
        val a = Server(admission)
        val b = Server(admission)
        try {
            if (flags and 4 != 0) {
                a.deliver(hello.copyOf(hello.size / 2), step)
                b.deliver(second, step)
                a.deliver(hello.copyOfRange(hello.size / 2, hello.size), step)
            } else {
                a.deliver(hello, step)
                b.deliver(second, step)
            }
            a.checkSettled()
            b.checkSettled()
            if (flags and 2 == 0) check(!(a.accepted && b.accepted)) { "a replayed ClientHello got early data twice" }
        } finally {
            a.close()
            b.close()
        }
    }

    /** Remembers each admission per hello: what it was asked, what it answered, what was released. */
    private class RecordingAdmission : EarlyDataAdmission {
        val held = ArrayList<ByteArray>()
        var current: MutableList<Pair<ByteArray, Boolean>> = ArrayList()

        override fun admit(ticketId: ByteArray): Boolean {
            val ok = held.none { it.contentEquals(ticketId) }
            if (ok) held += ticketId.copyOf()
            current += ticketId.copyOf() to ok
            return ok
        }

        override fun release(ticketId: ByteArray) {
            held.removeAll { it.contentEquals(ticketId) }
        }
    }

    private class Server(
        private val admission: RecordingAdmission,
    ) {
        private val session: QuicTlsSession = KslQuicCrypto.newSession(Fixtures.server(), earlyData = true)
        private val asked: MutableList<Pair<ByteArray, Boolean>> = ArrayList()
        private var failed = false
        val accepted: Boolean get() = session.earlyDataAccepted == true

        init {
            check(session.enableEarlyData(CONTEXT, admission))
            session.setTransportParameters(Fixtures.tp)
        }

        fun deliver(
            hello: ByteArray,
            step: Int,
        ) {
            var off = 0
            while (off < hello.size && !failed) {
                val n = minOf(step, hello.size - off)
                admission.current = asked
                try {
                    session.provide(EncryptionLevel.Initial, hello, off, n)
                    if (session.drive() is DriveResult.Failed) failed = true
                } catch (_: TlsException) {
                    failed = true
                }
                while (true) {
                    val ev = session.nextEvent() ?: break
                    if (ev is TlsEvent.Keys) ev.protector.close()
                }
                off += n
            }
        }

        /** The verdict and the register agree: an accepted hello holds its admission, any other hello holds none. */
        fun checkSettled() {
            check(asked.size <= 1) { "one ClientHello was admitted ${asked.size} times" }
            val admitted = asked.firstOrNull()?.takeIf { it.second }?.first
            if (accepted) {
                check(admitted != null) { "early data accepted without an admission by the replay register" }
                check(admission.held.any { it.contentEquals(admitted) }) { "early data accepted, its admission released" }
            } else if (admitted != null) {
                check(admission.held.none { it.contentEquals(admitted) }) {
                    "early data not accepted (${session.earlyDataAccepted}, failed: $failed), its admission still held"
                }
            }
        }

        fun close() = session.close()
    }

    private companion object {
        val CONTEXT = byteArrayOf(1)

        /** A ClientHello resuming a ticket just issued by a server of [Fixtures.server], offering 0-RTT. */
        fun freshResumptionHello(): ByteArray {
            val server = KslQuicCrypto.newSession(Fixtures.server(), earlyData = true)
            check(server.enableEarlyData(CONTEXT, RecordingAdmission()))
            val client = KslQuicCrypto.newSession(Fixtures.client(), earlyData = true)
            client.setTransportParameters(Fixtures.tp)
            server.setTransportParameters(Fixtures.tp)
            val tickets = ArrayList<io.kuicksilver.tls.QuicSessionTicket>()
            val pump = Pump(client, server)
            pump.onEvent = { fromClient, ev -> if (fromClient && ev is TlsEvent.SessionTicket) tickets += ev.ticket }
            pump.run()
            pump.close()
            check(tickets.isNotEmpty()) { "the full handshake issued no ticket" }
            tickets.drop(1).forEach { it.close() }
            val c = KslQuicCrypto.newSession(Fixtures.client(), earlyData = true)
            try {
                check(c.resume(tickets[0]))
                check(c.enableEarlyData(null, null))
                c.setTransportParameters(Fixtures.tp)
                c.drive()
                var hello = ByteArray(0)
                while (true) {
                    val ev = c.nextEvent() ?: break
                    if (ev is TlsEvent.CryptoData && ev.level == EncryptionLevel.Initial) hello += ev.data
                    if (ev is TlsEvent.Keys) ev.protector.close()
                }
                return hello
            } finally {
                c.close()
            }
        }
    }
}

private fun ByteArray?.contentEqualsNullable(other: ByteArray?): Boolean =
    if (this ==
        null
    ) {
        other == null
    } else {
        other != null && contentEquals(other)
    }
