// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.tls

/**
 * Reads a server's first ClientHello from the Initial CRYPTO stream before `ksl` processes it (ADR-0015): whether it
 * offers early data, and the identity of the ticket it resumes, so the replay register decides before OpenSSL does
 * (RFC 8446 sections 4.1.2, 4.2.10, 4.2.11). Bounded: a hello beyond [max] bytes or a malformed one is decided as "no
 * early data"; OpenSSL still parses (and rejects) it on its own.
 */
internal class ClientHelloScan(
    private val max: Int = 16_384,
) {
    /** What the scan found. [ticketId] is the first 32 bytes (`key_name ‖ iv`) of the first PSK identity. */
    class Result(
        val earlyData: Boolean,
        val ticketId: ByteArray?,
    )

    private var buf = ByteArray(0)
    private var len = 0
    private var result: Result? = null

    /** Appends bytes; returns the result once the hello is complete (and on every later call), null while it is not. */
    fun feed(
        data: ByteArray,
        offset: Int,
        length: Int,
    ): Result? {
        result?.let { return it }
        val take = minOf(length, max + 4 - len)
        if (take > 0) {
            if (buf.size < len + take) buf = buf.copyOf(maxOf(len + take, buf.size * 2, 256))
            data.copyInto(buf, len, offset, offset + take)
            len += take
        }
        if (len < 4) return null
        if (buf[0].toInt() != 1) return done(Result(false, null))
        val bodyLen = ((buf[1].toInt() and 0xff) shl 16) or ((buf[2].toInt() and 0xff) shl 8) or (buf[3].toInt() and 0xff)
        if (bodyLen > max) return done(Result(false, null))
        if (len < 4 + bodyLen) return null
        return done(parse(4 + bodyLen))
    }

    private fun done(r: Result): Result {
        result = r
        buf = ByteArray(0)
        return r
    }

    private fun u8(p: Int) = buf[p].toInt() and 0xff

    private fun u16(p: Int) = (u8(p) shl 8) or u8(p + 1)

    private fun parse(end: Int): Result {
        val none = Result(false, null)
        var p = 4 + 2 + 32
        if (p + 1 > end) return none
        p += 1 + u8(p) // legacy_session_id
        if (p + 2 > end) return none
        p += 2 + u16(p) // cipher_suites
        if (p + 1 > end) return none
        p += 1 + u8(p) // legacy_compression_methods
        if (p + 2 > end) return none
        val extEnd = p + 2 + u16(p)
        if (extEnd > end) return none
        p += 2
        var early = false
        var id: ByteArray? = null
        while (p + 4 <= extEnd) {
            val type = u16(p)
            val l = u16(p + 2)
            val body = p + 4
            if (body + l > extEnd) return none
            when (type) {
                EARLY_DATA -> {
                    early = true
                }

                PRE_SHARED_KEY -> {
                    // OfferedPsks: identities<7..2^16-1> of (identity<1..2^16-1>, obfuscated_ticket_age u32), then binders
                    if (l >= 4) {
                        val first = u16(body + 2)
                        if (first >= TICKET_ID && body + 4 + first <= body + l) id = buf.copyOfRange(body + 4, body + 4 + TICKET_ID)
                    }
                }
            }
            p = body + l
        }
        return Result(early && id != null, if (early) id else null)
    }

    private companion object {
        const val EARLY_DATA = 42
        const val PRE_SHARED_KEY = 41
        const val TICKET_ID = 32
    }
}
