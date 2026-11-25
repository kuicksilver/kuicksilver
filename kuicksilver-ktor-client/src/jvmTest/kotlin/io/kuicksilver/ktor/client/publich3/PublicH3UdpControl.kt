// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.client.publich3

import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.SocketTimeoutException
import java.security.SecureRandom

/*
 * The control of the public HTTP/3 check: whether UDP to port 443 gets through at all, without our QUIC stack. A datagram
 * that only follows the version-independent invariants (RFC 8999 section 5.1: a long header) with a version reserved to
 * force Version Negotiation (RFC 9000 section 15, 0x?a?a?a?a), padded to 1200 bytes, makes a server answer with a Version
 * Negotiation packet (RFC 9000 sections 5.2.2 and 6.1). One that comes back shows the path carries QUIC, so a client whose
 * Initial gets no answer from any server is wrong; none from any target means the runner's network blocks QUIC, and the
 * run-wide rule (`escalate`) is not applied.
 */

/** The version the probe offers: of the 0x?a?a?a?a pattern no implementation may select (RFC 9000 section 15). */
internal const val PROBE_VERSION: Int = 0x1a2a3a4a

/** A 1200-byte long-header datagram offering [PROBE_VERSION] from [scid] to [dcid] (each 8..20 bytes). */
internal fun versionNegotiationProbe(
    dcid: ByteArray,
    scid: ByteArray,
): ByteArray {
    require(dcid.size in 8..20 && scid.size in 8..20)
    val out = ByteArray(1200)
    out[0] = 0xc0.toByte() // long header, fixed bit (an Initial's first byte apart from the version)
    for (i in 0..3) out[1 + i] = (PROBE_VERSION ushr (24 - 8 * i)).toByte()
    out[5] = dcid.size.toByte()
    dcid.copyInto(out, 6)
    out[6 + dcid.size] = scid.size.toByte()
    scid.copyInto(out, 7 + dcid.size)
    return out
}

/**
 * The versions a Version Negotiation packet in [d] lists, when it answers a probe sent with [ourDcid] and [ourScid]: a long
 * header, version 0, its Destination Connection ID our Source one and its Source Connection ID our Destination one
 * (RFC 9000 section 17.2.1); null for anything else.
 */
internal fun parseVersionNegotiation(
    d: ByteArray,
    ourDcid: ByteArray,
    ourScid: ByteArray,
): List<Int>? {
    if (d.size < 7 || d[0].toInt() and 0x80 == 0) return null
    if ((1..4).any { d[it] != 0.toByte() }) return null
    var p = 5
    val dl = d[p++].toInt() and 0xff
    if (p + dl > d.size || !d.copyOfRange(p, p + dl).contentEquals(ourScid)) return null
    p += dl
    if (p >= d.size) return null
    val sl = d[p++].toInt() and 0xff
    if (p + sl > d.size || !d.copyOfRange(p, p + sl).contentEquals(ourDcid)) return null
    p += sl
    val rest = d.size - p
    if (rest < 4 || rest % 4 != 0) return null
    return (0 until rest / 4).map { i ->
        val o = p + 4 * i
        ((d[o].toInt() and 0xff) shl 24) or ((d[o + 1].toInt() and 0xff) shl 16) or ((d[o + 2].toInt() and 0xff) shl 8) or
            (d[o + 3].toInt() and 0xff)
    }
}

/**
 * Sends the probe to [host]:443 up to [tries] times and returns the versions of the Version Negotiation that came back,
 * null when none did within [timeoutMillis] each (the socket's receive timeout: a bounded wait for an answer, not a sleep).
 */
internal fun versionNegotiationFrom(
    host: String,
    tries: Int = 2,
    timeoutMillis: Int = 3000,
): List<Int>? {
    val rnd = SecureRandom()
    val address =
        try {
            InetAddress.getByName(host)
        } catch (_: java.net.UnknownHostException) {
            return null
        }
    DatagramSocket().use { s ->
        s.soTimeout = timeoutMillis
        repeat(tries) {
            val dcid = ByteArray(8).also(rnd::nextBytes)
            val scid = ByteArray(8).also(rnd::nextBytes)
            val probe = versionNegotiationProbe(dcid, scid)
            s.send(DatagramPacket(probe, probe.size, address, 443))
            val buf = ByteArray(1500)
            // a few unrelated datagrams at most, each within the receive timeout; a timeout ends this try
            var left = 8
            while (left-- > 0) {
                val reply = DatagramPacket(buf, buf.size)
                try {
                    s.receive(reply)
                } catch (_: SocketTimeoutException) {
                    break
                }
                parseVersionNegotiation(buf.copyOf(reply.length), dcid, scid)?.let { return it }
            }
        }
    }
    return null
}
