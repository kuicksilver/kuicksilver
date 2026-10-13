// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(InternalKuicksilverApi::class, DelicateKuicksilverApi::class, ExperimentalKuicksilverApi::class)

package io.kuicksilver.tls

import io.kuicksilver.annotations.DelicateKuicksilverApi
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
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
    override fun newSession(config: TlsConfig): QuicTlsSession =
        KslQuicTlsSession(KslContext.create(config, quic = true), earlyDataSession = false)

    override fun newSession(
        config: TlsConfig,
        earlyData: Boolean,
    ): QuicTlsSession =
        KslQuicTlsSession(
            KslContext.create(config, quic = true, quicTickets = earlyData, earlyData = earlyData),
            earlyDataSession = earlyData,
        )

    /** Test hook: a server whose tickets do not allow early data (RFC 8446 section 4.2.10), to prove a client then sends no 0-RTT. */
    internal fun newSessionForTest(
        config: TlsConfig,
        ticketsWithoutEarlyData: Boolean,
    ): QuicTlsSession =
        KslQuicTlsSession(KslContext.create(config, quic = true, quicTickets = ticketsWithoutEarlyData), earlyDataSession = true)

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
    private val earlyDataSession: Boolean = false,
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
            val reference = referenceOf(config)
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
    ) {
        mapped { Ksl.quicProvide(s(), level.ksl, data, offset, length) }
        val sc = scan ?: return
        if (level != EncryptionLevel.Initial) return
        val r = sc.feed(data, offset, length) ?: return
        scan = null
        val id = r.ticketId
        if (r.earlyData && id != null && admission?.admit(id) == true) {
            admitted = id
            mapped { Ksl.sslSet(s(), KslConst.SET_EARLY_DATA, byteArrayOf(1)) }
        }
    }

    // ---- 0-RTT (ADR-0015) ----
    private var scan: ClientHelloScan? = null
    private var admission: EarlyDataAdmission? = null
    private var admitted: ByteArray? = null // the ticket identity the register admitted, until TLS confirmed or refused the early data
    private var resumed: QuicSessionTicket? = null
    private var lastSession = 0L // our reference to the newest session seen, so a new ticket is told apart from it
    private val pendingTickets = ArrayDeque<QuicSessionTicket>()

    override fun resume(ticket: QuicSessionTicket): Boolean {
        check(ctx.config.role == TlsRole.Client) { "only a client resumes" }
        if (ticket.closed) return false
        // ADR-0011: the OpenSSL verifier's verdict is not taken from the cache: an expired leaf or a withdrawn anchor runs a full handshake
        if (ctx.verifyMode == KslConst.VERIFY_OPENSSL && !ctx.cachedChainStillTrusted(ticket.entry.chain, reference)) {
            ticket.close()
            return false
        }
        return try {
            Ksl.sslSetSession(s(), ticket.entry.session)
            resumed?.close()
            resumed = ticket // kept until close: its chain stands in for the certificates a resumed handshake does not carry
            true
        } catch (_: KslException.Internal) {
            ticket.close()
            false
        }
    }

    override fun enableEarlyData(
        context: ByteArray?,
        admission: EarlyDataAdmission?,
    ): Boolean {
        if (ctx.config.role == TlsRole.Client) {
            if (resumed == null) return false
            return try {
                Ksl.sslSet(s(), KslConst.SET_EARLY_DATA, byteArrayOf(1))
                true
            } catch (_: KslException.Internal) {
                false
            }
        }
        check(earlyDataSession) { "a server session needs newSession(config, earlyData = true)" }
        require(context != null && context.size in 1..64) { "the early-data context is 1..64 bytes" }
        mapped { Ksl.sslSet(s(), KslConst.SET_EARLY_CONTEXT, context) }
        if (admission != null) {
            this.admission = admission
            scan = ClientHelloScan()
        }
        return true
    }

    private var earlySeen = 0 // the last early-data status read, kept for a session that failed since (ksl refuses queries then)

    private fun earlyStatus(): Int {
        if (ssl == 0L || failure != null) return earlySeen
        return Ksl.sslGet(ssl, KslConst.GET_EARLY_DATA)[0].toInt().also { earlySeen = it }
    }

    override val earlyDataAccepted: Boolean? get() {
        // the client counts early data as rejected until EncryptedExtensions says otherwise
        if (ctx.config.role == TlsRole.Client && !done) return null
        return when (earlyStatus()) {
            2 -> true
            1 -> false
            else -> null
        }
    }

    /**
     * Server: a hello the register admitted keeps its reservation only if TLS accepted its early data. OpenSSL 3.5 decides in
     * `final_early_data` after the ClientHello is processed: it calls the allow-early-data callback (our verdict) only when the
     * ticket decrypted, the binder verified (`hit`) and the age is fresh (`early_data_ok`), and the status records the result,
     * so a forged or stale identity is released in the same `ksl` call that saw it.
     */
    private fun settleAdmission(failed: Boolean) {
        val id = admitted ?: return
        val st = if (failed) 1 else earlyStatus()
        if (st == 0) return
        admitted = null
        if (st != 2) admission?.release(id)
    }

    /** Client: a NewSessionTicket replaced the session; queue it as a [TlsEvent.SessionTicket]. */
    private fun collectTicket() {
        if (!earlyDataSession || ctx.config.role != TlsRole.Client || !done || failure != null) return
        val h = Ksl.sslGet1Session(s())
        if (h == 0L) return
        if (h == lastSession || h == resumed?.entry?.session) {
            Ksl.sessionFree(h)
            return
        }
        val prev = lastSession
        lastSession = h
        if (prev != 0L) Ksl.sessionFree(prev)
        val chain = resumed?.entry?.chain ?: presented
        val validated =
            resumed?.entry?.validated ?: if (ctx.verifyMode == KslConst.VERIFY_OPENSSL) validatedChain() else presented
        Ksl.sslGet1Session(s()).let { pendingTickets += QuicSessionTicket(SessionCache.Entry(it, chain, validated)) }
    }

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
                settleAdmission(failed = true)
                return DriveResult.Failed(ex, alert).also { failure = it }
            }
        settleAdmission(failed = false)
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
                collectTicket()
                failure ?: DriveResult.Progress
            }
        }.also { if (rc == KslConst.WANT_READ) collectTicket() }
    }

    /** Handshake finished on the OpenSSL side: when ksl verified the chain itself (AnchoredCa), pins are checked here against its validated chain. */
    private fun completed() {
        done = true
        alpn = Ksl.sslGet(s(), KslConst.GET_ALPN).takeIf { it.isNotEmpty() }?.decodeToString()
        val config = ctx.config
        val pinsApply =
            (config.role == TlsRole.Client && ctx.verifyMode == KslConst.VERIFY_OPENSSL) ||
                (config.role == TlsRole.Server && config.clientAuth != ClientAuth.None && config.trust is TrustConfig.Pinned)
        val cached =
            resumed?.entry?.takeIf {
                config.role == TlsRole.Client && Ksl
                    .sslGet(
                        s(),
                        KslConst.GET_SESSION_REUSED,
                    )[0]
                    .toInt() == 1
            }
        // a resumed handshake carries no Certificate; the cached chain was verified again before resuming
        if (cached != null) presented = cached.chain
        if (pinsApply) {
            if (cached == null) presented = Ksl.sslPeerChain(s(), KslConst.CHAIN_PRESENTED).map(::Certificate)
            // ClientAuth.Optional: a client without a certificate is accepted; one that presents a certificate must pass the pins
            if (config.role == TlsRole.Server && config.clientAuth == ClientAuth.Optional && presented.isEmpty()) return
            val r = verification.pinCheck(cached?.validated ?: validatedChain())
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
        if (!Ksl.quicNextEvent(s(), event)) return pendingTickets.removeFirstOrNull()?.let { TlsEvent.SessionTicket(it) }
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

    // a server that accepted 0-RTT knows the protocol from the ClientHello, before the handshake completes
    override val negotiatedAlpn: String? get() =
        alpn ?: if (ssl != 0L && failure == null && ctx.config.role == TlsRole.Server) {
            Ksl.sslGet(ssl, KslConst.GET_ALPN).takeIf { it.isNotEmpty() }?.decodeToString()
        } else {
            null
        }

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
        // a hello closed before TLS decided on its early data never got it: its reservation goes too
        admitted?.let { admission?.release(it) }
        admitted = null
        if (ssl != 0L) {
            Ksl.sslFree(ssl)
            ssl = 0L
        }
        resumed?.close()
        resumed = null
        pendingTickets.forEach { it.close() }
        pendingTickets.clear()
        if (lastSession != 0L) Ksl.sessionFree(lastSession)
        lastSession = 0L
        ctx.close()
    }
}

/** A client's reference identifier (RFC 9525): the ExpectedName, else the server name; Config error when there is none. */
internal fun referenceOf(config: TlsConfig): String =
    when (val t = config.trust) {
        is TrustConfig.ExpectedName -> t.name
        is TrustConfig.Pinned -> (t.base as? TrustConfig.ExpectedName)?.name ?: config.serverName
        else -> config.serverName
    } ?: throw TlsException.Config("a client needs serverName (or ExpectedName) as the reference identifier")

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
