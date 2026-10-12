// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic

import io.kuicksilver.quic.VersionProfile
import io.kuicksilver.quic.crypto.NullPacketProtector
import io.kuicksilver.quic.wire.QuicWireException
import io.kuicksilver.quic.wire.TransportParametersCodec
import io.kuicksilver.quic.wire.chooseVersion
import io.kuicksilver.tls.Certificate
import io.kuicksilver.tls.Direction
import io.kuicksilver.tls.DriveResult
import io.kuicksilver.tls.EncryptionLevel
import io.kuicksilver.tls.QuicTlsSession
import io.kuicksilver.tls.TlsConfig
import io.kuicksilver.tls.TlsEvent
import io.kuicksilver.tls.TlsException
import io.kuicksilver.tls.TlsRole
import io.kuicksilver.tls.VerifyResult

/**
 * A scripted stand-in for the TLS handshake (ADR-0004; also used by the fuzzers): ClientHello' carries ALPN and transport parameters in an
 * Initial CRYPTO frame, ServerHello' answers with the chosen ALPN and the server's parameters, Finished' completes each
 * side. No certificates, no secrets: every key event carries [NullPacketProtector].
 */
internal class NullTlsSession(
    private val config: TlsConfig,
) : QuicTlsSession {
    private val events = ArrayDeque<TlsEvent>()
    private val inbox = Array(4) { ByteArray(0) }
    private var localTp = ByteArray(0)
    private var stage = 0 // client: 0 start, 1 sent CH, 2 got SH, 3 done; server: 0 wait CH, 1 sent SH, 3 done
    private var failed: DriveResult.Failed? = null

    private var version: Int = 1

    override fun setTransportParameters(encoded: ByteArray) {
        localTp = encoded.copyOf()
    }

    override fun setQuicVersion(version: Int) {
        require(VersionProfile.of(version) != null) { "unknown QUIC version 0x${version.toUInt().toString(16)}" }
        check(stage < 2 && !(config.role == TlsRole.Server && stage >= 1)) { "QUIC version is fixed once Handshake keys exist" }
        this.version = version
    }

    override fun provide(
        level: EncryptionLevel,
        data: ByteArray,
        offset: Int,
        length: Int,
    ) {
        inbox[level.ordinal] +=
            data.copyOfRange(offset, offset + length)
    }

    override fun nextEvent(): TlsEvent? = events.removeFirstOrNull()

    override suspend fun verifyPeer(chain: List<Certificate>): VerifyResult = VerifyResult.Accepted(chain)

    override fun resumeVerify(result: VerifyResult) {}

    var closed: Boolean = false
        private set

    override fun close() {
        closed = true
    }

    override fun drive(): DriveResult {
        failed?.let { return it }
        val before = events.size
        if (config.role == TlsRole.Client) driveClient() else driveServer()
        failed?.let { return it }
        return if (events.size > before) DriveResult.Progress else DriveResult.WantRead
    }

    private fun keys(level: EncryptionLevel) {
        events += TlsEvent.Keys(level, Direction.Read, NullPacketProtector)
        events +=
            TlsEvent.Keys(level, Direction.Write, NullPacketProtector)
    }

    private fun driveClient() {
        if (stage == 0) {
            events += TlsEvent.CryptoData(EncryptionLevel.Initial, message(1, clientHelloBody()))
            stage = 1
        }
        if (stage == 1) {
            val m = take(EncryptionLevel.Initial) ?: return
            val (type, body) = m
            if (type != 2) {
                fail("unexpected message $type")
                return
            }
            val (alpn, tp) =
                parseServerHello(body) ?: run {
                    fail("malformed ServerHello'")
                    return
                }
            if (alpn !in config.alpn) {
                fail("server chose an unknown protocol")
                return
            }
            negotiatedAlpn = alpn
            keys(EncryptionLevel.Handshake)
            events += TlsEvent.PeerTransportParameters(tp, version)
            stage = 2
        }
        if (stage == 2) {
            val m = take(EncryptionLevel.Handshake) ?: return
            if (m.first != 20) {
                fail("expected Finished")
                return
            }
            keys(EncryptionLevel.Application)
            events += TlsEvent.CryptoData(EncryptionLevel.Handshake, message(20, ByteArray(0)))
            events +=
                TlsEvent.HandshakeDone
            stage = 3
        }
    }

    private fun driveServer() {
        if (stage == 0) {
            val m = take(EncryptionLevel.Initial) ?: return
            if (m.first != 1) {
                fail("unexpected message ${m.first}")
                return
            }
            val (alpns, tp) =
                parseClientHello(m.second) ?: run {
                    fail("malformed ClientHello'")
                    return
                }
            val chosen = config.alpn.firstOrNull { it in alpns }
            if (chosen == null) {
                failed = DriveResult.Failed(TlsException.Protocol(null, "no application protocol", null), 120)
                return
            }
            negotiatedAlpn = chosen
            negotiateVersion(tp)
            events += TlsEvent.CryptoData(EncryptionLevel.Initial, message(2, serverHelloBody(chosen)))
            keys(EncryptionLevel.Handshake)
            events += TlsEvent.CryptoData(EncryptionLevel.Handshake, message(20, ByteArray(0)))
            keys(EncryptionLevel.Application)
            events += TlsEvent.PeerTransportParameters(tp, version)
            stage = 1
        }
        if (stage == 1) {
            val m = take(EncryptionLevel.Handshake) ?: return
            if (m.first != 20) {
                fail("expected Finished")
                return
            }
            events += TlsEvent.HandshakeDone
            stage = 3
        }
    }

    override var negotiatedAlpn: String? = null
        private set
    override val peerCertificates: List<Certificate> get() = emptyList()

    /** Deterministic stand-in: the label and context bytes, repeated or cut to [length]. */
    override fun exportKeyingMaterial(
        label: String,
        context: ByteArray?,
        length: Int,
    ): ByteArray {
        val src =
            label.encodeToByteArray() + (context ?: ByteArray(0)) + byteArrayOf(1)
        return ByteArray(length) { src[it % src.size] }
    }

    private fun fail(msg: String) {
        failed = DriveResult.Failed(TlsException.Protocol(null, msg, null), 10)
    }

    /** Server rule of RFC 9368 section 2.3, as in `ksl`: our Available Versions (from our own TP) against the client's; our Chosen Version is rewritten to the result. */
    private fun negotiateVersion(clientTp: ByteArray) {
        val client =
            try {
                TransportParametersCodec.decode(clientTp, TlsRole.Client)
            } catch (_: QuicWireException) {
                return
            }
        val ours =
            try {
                TransportParametersCodec.decode(localTp, TlsRole.Server)
            } catch (_: QuicWireException) {
                return
            }
        val av = client.availableVersions ?: return
        val chosen = chooseVersion(ours.availableVersions ?: intArrayOf(version), client.chosenVersion, av)
        if (VersionProfile.of(chosen) == null) return
        version = chosen
        if (ours.availableVersions != null &&
            ours.chosenVersion != chosen
        ) {
            ours.chosenVersion = chosen
            localTp = TransportParametersCodec.encode(ours, TlsRole.Server, 27)
        }
    }

    // ---- framing: [type u8][length u24][body] ----
    private fun message(
        type: Int,
        body: ByteArray,
    ): ByteArray = byteArrayOf(type.toByte(), (body.size ushr 16).toByte(), (body.size ushr 8).toByte(), body.size.toByte()) + body

    private fun take(level: EncryptionLevel): Pair<Int, ByteArray>? {
        val b = inbox[level.ordinal]
        if (b.size < 4) return null
        val len = ((b[1].toInt() and 0xff) shl 16) or ((b[2].toInt() and 0xff) shl 8) or (b[3].toInt() and 0xff)
        if (b.size < 4 + len) return null
        inbox[level.ordinal] = b.copyOfRange(4 + len, b.size)
        return (b[0].toInt() and 0xff) to b.copyOfRange(4, 4 + len)
    }

    private fun u16(v: Int) = byteArrayOf((v ushr 8).toByte(), v.toByte())

    private fun clientHelloBody(): ByteArray {
        var alpn = ByteArray(0)
        for (a in config.alpn) {
            val e = a.encodeToByteArray()
            alpn +=
                byteArrayOf(e.size.toByte()) + e
        }
        return u16(alpn.size) + alpn + u16(localTp.size) + localTp
    }

    private fun serverHelloBody(alpn: String): ByteArray {
        val e = alpn.encodeToByteArray()
        return byteArrayOf(e.size.toByte()) + e +
            u16(localTp.size) +
            localTp
    }

    /** Null when a length runs past the message (peer input: never index out of bounds). */
    private fun parseClientHello(b: ByteArray): Pair<List<String>, ByteArray>? {
        if (b.size < 2) return null
        val alpnLen = ((b[0].toInt() and 0xff) shl 8) or (b[1].toInt() and 0xff)
        var p = 2
        val alpns = ArrayList<String>()
        if (2 + alpnLen + 2 > b.size) return null
        while (p <
            2 + alpnLen
        ) {
            val n =
                b[p].toInt() and 0xff
            if (p + 1 + n > 2 + alpnLen) return null
            alpns += b.decodeToString(p + 1, p + 1 + n)
            p += 1 + n
        }
        val tpLen = ((b[p].toInt() and 0xff) shl 8) or (b[p + 1].toInt() and 0xff)
        if (p + 2 + tpLen > b.size) return null
        return alpns to b.copyOfRange(p + 2, p + 2 + tpLen)
    }

    private fun parseServerHello(b: ByteArray): Pair<String, ByteArray>? {
        if (b.isEmpty()) return null
        val n = b[0].toInt() and 0xff
        if (1 + n + 2 > b.size) return null
        val alpn = b.decodeToString(1, 1 + n)
        val p = 1 + n
        val tpLen = ((b[p].toInt() and 0xff) shl 8) or (b[p + 1].toInt() and 0xff)
        if (p + 2 + tpLen > b.size) return null
        return alpn to b.copyOfRange(p + 2, p + 2 + tpLen)
    }
}
