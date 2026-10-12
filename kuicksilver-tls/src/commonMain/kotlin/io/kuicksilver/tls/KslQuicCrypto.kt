// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(InternalKuicksilverApi::class, DelicateKuicksilverApi::class)

package io.kuicksilver.tls

import io.kuicksilver.annotations.DelicateKuicksilverApi
import io.kuicksilver.annotations.InternalKuicksilverApi
import io.kuicksilver.native.Ksl
import io.kuicksilver.native.KslConst
import io.kuicksilver.native.KslEvent
import io.kuicksilver.native.KslException
import io.kuicksilver.native.KslLoader
import io.kuicksilver.native.PacketBuffer
import io.kuicksilver.native.of

/** The OpenSSL-backed [QuicCrypto]. */
public object KslQuicCrypto : QuicCrypto {
    override fun newSession(config: TlsConfig): QuicTlsSession = KslQuicTlsSession(KslContext.create(config, quic = true))

    override fun initialProtectors(
        dcid: ByteArray,
        version: Int,
        role: TlsRole,
    ): Pair<PacketProtector, PacketProtector> {
        KslLoader.ensureLoaded()
        val server = role == TlsRole.Server
        val read = KslPacketProtector(Ksl.keyInitial(dcid, server, KslConst.DIR_READ, version), Aead.AES_128_GCM)
        val write =
            try {
                KslPacketProtector(Ksl.keyInitial(dcid, server, KslConst.DIR_WRITE, version), Aead.AES_128_GCM)
            } catch (
                t: Throwable,
            ) {
                read.close()
                throw t
            }
        return read to write
    }

    override fun retryIntegrityTag(
        version: Int,
        odcid: ByteArray,
        retryPseudoPacket: ByteArray,
    ): ByteArray {
        KslLoader.ensureLoaded()
        return Ksl.retryTag(version, odcid, retryPseudoPacket)
    }

    override fun newTokenKey(): TokenKey {
        KslLoader.ensureLoaded()
        return KslTokenKey(Ksl.keyRandom(KslConst.EKEY_TOKEN))
    }

    override fun newResetKey(): ResetKey {
        KslLoader.ensureLoaded()
        return KslResetKey(Ksl.keyRandom(KslConst.EKEY_RESET))
    }
}

internal class KslTokenKey(
    private var key: Long,
) : TokenKey {
    private fun k(): Long = key.also { if (it == 0L) throw IllegalStateException("TokenKey is closed") }

    override fun seal(
        nonce: Long,
        aad: ByteArray,
        plaintext: ByteArray,
    ): ByteArray {
        val h = PacketBuffer.of(if (aad.isEmpty()) ByteArray(1) else aad)
        val p = PacketBuffer.allocate(plaintext.size + 16)
        try {
            p.copyFrom(plaintext, 0, 0, plaintext.size)
            val n = Ksl.seal(k(), nonce, h, 0, aad.size, p, 0, plaintext.size)
            return ByteArray(n).also { p.copyTo(it, 0, 0, n) }
        } finally {
            h.close()
            p.close()
        }
    }

    override fun open(
        nonce: Long,
        aad: ByteArray,
        sealed: ByteArray,
    ): ByteArray? {
        if (sealed.size < 16) return null
        val h = PacketBuffer.of(if (aad.isEmpty()) ByteArray(1) else aad)
        val p = PacketBuffer.of(sealed)
        try {
            val n =
                try {
                    Ksl.open(k(), nonce, h, 0, aad.size, p, 0, sealed.size)
                } catch (
                    _: KslException.Internal,
                ) {
                    return null
                }
            return ByteArray(n).also { p.copyTo(it, 0, 0, n) }
        } finally {
            h.close()
            p.close()
        }
    }

    override fun close() {
        if (key != 0L) {
            Ksl.keyFree(key)
            key = 0L
        }
    }
}

internal class KslResetKey(
    private var key: Long,
) : ResetKey {
    override fun token(
        cid: PacketBuffer,
        offset: Int,
        length: Int,
        out: ByteArray,
        outOffset: Int,
    ) {
        val k = key
        if (k ==
            0L
        ) {
            throw IllegalStateException("ResetKey is closed")
        }
        Ksl.keyMac16(k, cid, offset, length, out, outOffset)
    }

    override fun close() {
        if (key != 0L) {
            Ksl.keyFree(key)
            key = 0L
        }
    }
}

internal class KslPacketProtector(
    private var key: Long,
    override val aead: Aead,
) : PacketProtector {
    private fun k(): Long = key.also { if (it == 0L) throw IllegalStateException("PacketProtector is closed") }

    override fun seal(
        packetNumber: Long,
        header: PacketBuffer,
        headerOffset: Int,
        headerLength: Int,
        payload: PacketBuffer,
        payloadOffset: Int,
        payloadLength: Int,
    ): Int = Ksl.seal(k(), packetNumber, header, headerOffset, headerLength, payload, payloadOffset, payloadLength)

    override fun open(
        packetNumber: Long,
        header: PacketBuffer,
        headerOffset: Int,
        headerLength: Int,
        payload: PacketBuffer,
        payloadOffset: Int,
        payloadLength: Int,
    ): Int =
        try {
            Ksl.open(k(), packetNumber, header, headerOffset, headerLength, payload, payloadOffset, payloadLength)
        } catch (
            e: KslException.Internal,
        ) {
            throw PacketProtectionException("packet protection removal failed: ${e.message}")
        }

    override fun headerMask(
        sample: PacketBuffer,
        sampleOffset: Int,
        mask: ByteArray,
    ): Unit = Ksl.headerMask(k(), sample, sampleOffset, mask)

    override fun next(): PacketProtector = KslPacketProtector(Ksl.keyNext(k()), aead)

    override fun close() {
        if (key != 0L) {
            Ksl.keyFree(key)
            key = 0L
        }
    }
}

internal class KslQuicTlsSession(
    private val ctx: KslContext,
) : QuicTlsSession {
    private var ssl: Long = Ksl.sslNew(ctx.handle, KslConst.MODE_QUIC)
    private val event = KslEvent()
    private var presented: List<Certificate> = emptyList()
    private var alpn: String? = null
    private var failure: DriveResult.Failed? = null
    private var done = false
    private val verification = Verification(ctx.config)
    private lateinit var reference: HostName
    private var rejection: VerifyReason? = null // the Kotlin-side verdict, kept so the failure carries the real reason

    init {
        val config = ctx.config
        if (config.role == TlsRole.Client) {
            val reference =
                when (val t = config.trust) {
                    is TrustConfig.ExpectedName -> {
                        t.name
                    }

                    is TrustConfig.Pinned -> {
                        (t.base as? TrustConfig.ExpectedName)?.name
                            ?: config.serverName
                    }

                    else -> {
                        config.serverName
                    }
                }
                    ?: throw TlsException.Config("a client needs serverName (or ExpectedName) as the reference identifier")
            val host = HostName.normalize(reference)
            this.reference = host
            sniOf(config)?.let { Ksl.sslSet(ssl, KslConst.SET_SNI, it.encodeToByteArray()) }
            Ksl.sslSet(ssl, KslConst.SET_VERIFY_NAME, host.value.encodeToByteArray())
        }
    }

    private fun s(): Long = ssl.also { if (it == 0L) throw IllegalStateException("session closed") }

    override fun setTransportParameters(encoded: ByteArray): Unit = mapped { Ksl.quicSetTransportParams(s(), encoded) }

    override fun setQuicVersion(version: Int) {
        try {
            Ksl.sslSet(
                s(),
                KslConst.SET_QUIC_VERSION,
                byteArrayOf((version ushr 24).toByte(), (version ushr 16).toByte(), (version ushr 8).toByte(), version.toByte()),
            )
        } catch (
            e: KslException.Internal,
        ) {
            if (e.packed ==
                KslConst.E_TOO_LATE
            ) {
                throw IllegalStateException(e.message, e)
            } else {
                throw IllegalArgumentException(e.message, e)
            }
        }
    }

    private fun quicVersion(): Int {
        val b = Ksl.sslGet(s(), KslConst.GET_QUIC_VERSION)
        return ((b[0].toInt() and 0xff) shl 24) or
            ((b[1].toInt() and 0xff) shl 16) or
            ((b[2].toInt() and 0xff) shl 8) or
            (b[3].toInt() and 0xff)
    }

    override fun provide(
        level: EncryptionLevel,
        data: ByteArray,
        offset: Int,
        length: Int,
    ): Unit = mapped { Ksl.quicProvide(s(), level.ksl, data, offset, length) }

    override fun drive(): DriveResult {
        failure?.let { return it }
        val rc =
            try {
                Ksl.drive(s()).also { deliverKeylog() }
            } catch (e: KslException.Internal) {
                deliverKeylog()
                presented = Ksl.sslPeerChain(s(), KslConst.CHAIN_PRESENTED).map(::Certificate)
                val r = rejection
                val (ex, alert) =
                    if (r !=
                        null
                    ) {
                        TlsException.Verify(r, presented) to (if (ctx.config.genericAlerts) 40 else r.alertCode)
                    } else {
                        e.toTlsFailure(presented)
                    }
                return DriveResult.Failed(ex, alert).also { failure = it }
            }
        return when (rc) {
            KslConst.WANT_READ -> {
                DriveResult.WantRead
            }

            KslConst.WANT_VERIFY -> {
                presented = Ksl.sslPeerChain(s(), KslConst.CHAIN_PRESENTED).map(::Certificate)
                DriveResult.WantVerify(presented)
            }

            else -> {
                if (!done) completed()
                failure ?: DriveResult.Progress
            }
        }
    }

    /** Handshake finished on the OpenSSL side: when ksl verified the chain itself (AnchoredCa), pins are checked here against its validated chain. */
    private fun completed() {
        done = true
        alpn = Ksl.sslGet(s(), KslConst.GET_ALPN).takeIf { it.isNotEmpty() }?.decodeToString()
        val config = ctx.config
        val pinsApply =
            (config.role == TlsRole.Client && ctx.verifyMode == KslConst.VERIFY_OPENSSL) ||
                (config.role == TlsRole.Server && config.clientAuth != ClientAuth.None && config.trust is TrustConfig.Pinned)
        if (pinsApply) {
            presented = Ksl.sslPeerChain(s(), KslConst.CHAIN_PRESENTED).map(::Certificate)
            val r = verification.pinCheck(validatedChain())
            if (r is VerifyResult.Rejected) {
                failure =
                    DriveResult.Failed(TlsException.Verify(r.reason, presented), if (config.genericAlerts) 40 else r.reason.alertCode)
            }
        }
    }

    override suspend fun verifyPeer(chain: List<Certificate>): VerifyResult = verification.verify(chain, reference)

    override fun resumeVerify(result: VerifyResult) {
        when (result) {
            is VerifyResult.Accepted -> {
                mapped { Ksl.sslVerifyResume(s(), true, 0) }
            }

            is VerifyResult.Rejected -> {
                mapped { Ksl.sslVerifyResume(s(), false, if (ctx.config.genericAlerts) 40 else result.reason.alertCode) }
                rejection = result.reason
            }
        }
    }

    override fun nextEvent(): TlsEvent? {
        if (failure !=
            null
        ) {
            while (Ksl.quicNextEvent(s(), event)) if (event.type == KslConst.EV_KEY) Ksl.keyFree(event.key)
            return null
        } // a failed session hands out nothing, not even keys
        if (!Ksl.quicNextEvent(s(), event)) return null
        return when (event.type) {
            KslConst.EV_CRYPTO_SEND -> {
                TlsEvent.CryptoData(EncryptionLevel.of(event.level), event.payload)
            }

            KslConst.EV_KEY -> {
                TlsEvent.Keys(
                    EncryptionLevel.of(event.level),
                    if (event.direction ==
                        KslConst.DIR_READ
                    ) {
                        Direction.Read
                    } else {
                        Direction.Write
                    },
                    KslPacketProtector(event.key, Aead.of(event.aead)),
                )
            }

            KslConst.EV_TRANSPORT_PARAMS -> {
                TlsEvent.PeerTransportParameters(event.payload, quicVersion())
            }

            KslConst.EV_HANDSHAKE_DONE -> {
                if (!done) completed()
                if (failure != null) null else TlsEvent.HandshakeDone
            }

            else -> {
                throw IllegalStateException("unknown ksl event ${event.type}")
            }
        }
    }

    override val peerCertificates: List<Certificate> get() =
        if (ssl != 0L &&
            presented.isEmpty()
        ) {
            Ksl.sslPeerChain(s(), KslConst.CHAIN_PRESENTED).map(::Certificate).also { presented = it }
        } else {
            presented
        }
    override val negotiatedAlpn: String? get() = alpn
    override val earlyData: EarlyDataState get() = EarlyDataState.Disabled

    override fun exportKeyingMaterial(
        label: String,
        context: ByteArray?,
        length: Int,
    ): ByteArray = mapped { Ksl.sslExportKeyingMaterial(s(), label, context, length) }

    internal fun drainKeylog(): String = if (ctx.config.keylog == null) "" else Ksl.sslGet(s(), KslConst.GET_KEYLOG).decodeToString()

    private fun deliverKeylog() {
        val sink = ctx.config.keylog ?: return
        sink.deliver(drainKeylog())
    }

    /** The validated chain when `ksl` verified (AnchoredCa); used by the trust pipeline for pins. */
    internal fun validatedChain(): List<Certificate> = Ksl.sslPeerChain(s(), KslConst.CHAIN_VALIDATED).map(::Certificate)

    internal fun newSessionTicket(): Unit = Ksl.sslNewSessionTicket(s())

    override fun close() {
        if (ssl != 0L) {
            Ksl.sslFree(ssl)
            ssl = 0L
        }
        ctx.close()
    }
}

/**
 * Keeps the native layer's [KslException.Internal] behind the public TLS surface: a call in the wrong state (no verification
 * pending, exporter before the handshake) is an [IllegalStateException], anything else a [TlsException.Protocol].
 */
internal inline fun <T> mapped(block: () -> T): T =
    try {
        block()
    } catch (e: KslException.Internal) {
        when (e.packed) {
            KslConst.E_NOT_PAUSED, KslConst.E_NOT_SUPPORTED -> throw IllegalStateException(e.message, e)
            else -> throw TlsException.Protocol(e.packed, e.message ?: "ksl error", e)
        }
    }
