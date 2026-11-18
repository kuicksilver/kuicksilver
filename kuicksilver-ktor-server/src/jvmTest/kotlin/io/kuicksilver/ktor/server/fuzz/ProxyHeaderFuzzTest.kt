// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.server.fuzz

import com.code_intelligence.jazzer.junit.FuzzTest
import io.ktor.utils.io.ByteChannel
import io.ktor.utils.io.readBuffer
import io.ktor.utils.io.writeFully
import io.kuicksilver.ktor.server.ProxyFamily
import io.kuicksilver.ktor.server.ProxyHeader
import io.kuicksilver.ktor.server.ProxyProtocolCodec
import io.kuicksilver.ktor.server.ProxyProtocolException
import io.kuicksilver.ktor.server.parseIpLiteral
import io.kuicksilver.ktor.server.readProxyHeader
import io.kuicksilver.quic.ipLiteralOf
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.yield
import kotlinx.io.readByteArray
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.TestInfo

/**
 * Fuzz target `proxyHeader`: input = [mode byte][what a proxy sends first on a connection]. Mode bits 0-3, when not 0, cut
 * the bytes into pieces of that many bytes, each handed over on its own (a header split over many reads), else they come at
 * once; bits 4-7 pick the `maxHeaderSize` (232, 512, 4096 or 65551, by the low two bits).
 *
 * The connection's reader ([readProxyHeader]) either refuses the bytes with [ProxyProtocolException] (nothing else may come
 * out) or returns a header, and then: it took exactly the header and not a byte more (the rest of the input, the request a
 * client pipelined, is still in the channel, whole and in order); the same bytes decoded in one piece ([ProxyProtocolCodec.decode])
 * give the same header, so a split never changes the verdict; a version 1 header is at most 107 bytes and a version 2
 * header at most the limit; the header's fields agree with each other (a client IP only for IPv4 and IPv6 with its
 * literal, ports in 0..65535, TLVs only in version 2). The channel is closed after the last piece, so a header cut by
 * the end of the input is refused, not waited for.
 */
class ProxyHeaderFuzzTest {
    @BeforeEach fun nameTheCase(case: TestInfo) = fuzzCase(case)

    @FuzzTest(maxDuration = "60s")
    fun proxyHeader(data: ByteArray) =
        runTest {
            if (data.isEmpty()) return@runTest
            val piece = data[0].toInt() and 0x0f
            val max = LIMITS[(data[0].toInt() ushr 4) and 3]
            val wire = data.copyOfRange(1, data.size)
            val ch = ByteChannel()
            val writer =
                launch {
                    var at = 0
                    while (at < wire.size) {
                        val n = if (piece == 0) wire.size else minOf(piece, wire.size - at)
                        ch.writeFully(wire, at, at + n)
                        ch.flush()
                        at += n
                        yield()
                    }
                    ch.flushAndClose()
                }
            val header =
                try {
                    ch.readProxyHeader(max)
                } catch (_: ProxyProtocolException) {
                    writer.cancel()
                    return@runTest // refused: the connection is closed, nothing more to check
                }
            writer.join()
            val rest = ch.readBuffer().readByteArray()
            val taken = wire.size - rest.size
            check(taken > 0) { "a header of no bytes" }
            check(rest.contentEquals(wire.copyOfRange(taken, wire.size))) { "the bytes after the header were changed or lost" }
            val whole = ProxyProtocolCodec.decode(wire.copyOf(taken))
            check(whole.toString() == header.toString() && whole.tlvs.size == header.tlvs.size) {
                "the header read in pieces ($header) is not the one decoded whole ($whole)"
            }
            checkFields(header, taken, max)
        }

    private fun checkFields(
        h: ProxyHeader,
        size: Int,
        max: Int,
    ) {
        when (h.version) {
            1 -> check(size <= ProxyProtocolCodec.V1_MAX && h.tlvs.isEmpty()) { "version 1 of $size bytes with ${h.tlvs.size} TLVs" }
            2 -> check(size <= max) { "version 2 of $size bytes over the limit $max" }
            else -> error("version ${h.version}")
        }
        for (p in listOfNotNull(h.sourcePort, h.destinationPort)) check(p in 0..0xffff) { "port $p" }
        val ip = h.family == ProxyFamily.Inet || h.family == ProxyFamily.Inet6
        if (h.sourceAddress == null) {
            check(h.sourcePort == null && h.destinationAddress == null && h.tlvs.isEmpty()) { "fields without addresses: $h" }
        } else if (ip) {
            val literal = h.sourceAddress
            check(literal == canonical(literal)) { "source $literal is not in canonical text" }
            check((h.family == ProxyFamily.Inet6) == (':' in literal)) { "source $literal for ${h.family}" }
            check(h.sourcePort != null && h.destinationPort != null) { "an IP header without ports: $h" }
        } else {
            check(h.family == ProxyFamily.Unix && h.sourcePort == null) { "a non-IP address for ${h.family}: $h" }
        }
        for (t in h.tlvs) check(t.type in 0..255 && t.type != ProxyHeader.PP2_TYPE_NOOP) { "TLV ${t.type}" }
        h.ssl // parses, or the header would have been refused
    }

    private fun canonical(literal: String): String = ipLiteralOf(parseIpLiteral(literal) ?: error("source $literal is no IP literal"))

    private companion object {
        val LIMITS = intArrayOf(232, 512, 4096, ProxyProtocolCodec.V2_MAX)
    }
}
