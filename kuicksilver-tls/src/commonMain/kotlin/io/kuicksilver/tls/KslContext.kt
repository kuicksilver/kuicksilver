// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(
    InternalKuicksilverApi::class,
    DelicateKuicksilverApi::class,
    io.kuicksilver.annotations.ExperimentalKuicksilverApi::class,
    ExperimentalAtomicApi::class,
)

package io.kuicksilver.tls

import io.kuicksilver.annotations.DelicateKuicksilverApi
import io.kuicksilver.annotations.InternalKuicksilverApi
import io.kuicksilver.native.Ksl
import io.kuicksilver.native.KslConst
import io.kuicksilver.native.KslException
import io.kuicksilver.native.KslLoader
import kotlin.concurrent.atomics.AtomicInt
import kotlin.concurrent.atomics.AtomicReference
import kotlin.concurrent.atomics.ExperimentalAtomicApi

/**
 * Translates a [TlsConfig] into a frozen `ksl_ctx`; shared by the QUIC and TCP sessions. Reference-counted: [create] and
 * [acquire] hand out a [Lease] (one reference, given back once by [Lease.close], however often it is called); the native
 * context is freed with the last reference. A server's sessions share one per configuration and identity snapshot ([acquire],
 * [SharedServerContexts]).
 */
internal class KslContext private constructor(
    val handle: Long,
    val config: TlsConfig,
    val quic: Boolean,
    /**
     * The SHA-256 of the whole leaf certificate this context presents (not of its key: a renewal that keeps the key is another
     * certificate, as the server's ticket binding sees it too) (the snapshot a `TlsIdentity.Reloadable` gave), null without an identity.
     * A client stores it with each ticket and resumes a ticket only under the same one: the cache key reads the identity
     * separately, and a reload in between must not resume a session authenticated with another client certificate.
     */
    val identityTag: String?,
    private val quicTickets: Boolean,
    private val earlyData: Boolean,
) {
    /** One holder's reference to [ctx]: [close] gives it back once, so a second close cannot take another holder's reference. */
    class Lease internal constructor(
        val ctx: KslContext,
    ) : AutoCloseable {
        private val closed = AtomicInt(0)

        override fun close() {
            if (closed.compareAndSet(0, 1)) ctx.release()
        }
    }

    /** The verifier `ksl` runs itself (AnchoredCa) or the pause for Kotlin-side trust. */
    val verifyMode: Int = verifyModeFor(config)

    // 1 for whoever built it; +1 for each other holder (a sharing registry, each session of a shared context)
    private val refs = AtomicInt(1)

    /** True once the native context was freed (tests). */
    internal val isFreed: Boolean get() = refs.load() == 0

    /** Takes one more reference unless the context is already freed (then false, and nothing to [release]). */
    fun tryRetain(): Boolean {
        while (true) {
            val r = refs.load()
            if (r == 0) return false
            if (refs.compareAndSet(r, r + 1)) return true
        }
    }

    /** Gives one reference back; the last one frees the native context. Holders outside this file go through a [Lease]. */
    fun release() {
        val r = refs.addAndFetch(-1)
        check(r >= 0) { "KslContext closed more often than retained" }
        if (r == 0) Ksl.ctxFree(handle)
    }

    /** Whether this context is the one [acquire] would build for these arguments. */
    fun serves(
        config: TlsConfig,
        quic: Boolean,
        quicTickets: Boolean,
        earlyData: Boolean,
    ): Boolean = this.config === config && this.quic == quic && this.quicTickets == quicTickets && this.earlyData == earlyData

    companion object {
        fun verifyModeFor(config: TlsConfig): Int {
            if (config.role ==
                TlsRole.Server
            ) {
                return if (config.clientAuth == ClientAuth.None) KslConst.VERIFY_NONE else KslConst.VERIFY_OPENSSL
            }
            return when (val t = config.trust) {
                is TrustConfig.Platform -> if (platformTrustViaOpenSsl) KslConst.VERIFY_OPENSSL else KslConst.VERIFY_PAUSE
                is TrustConfig.AnchoredCa -> KslConst.VERIFY_OPENSSL
                is TrustConfig.Pinned -> verifyModeOfBase(t.base)
                is TrustConfig.ExpectedName -> verifyModeOfBase(t.base)
                else -> KslConst.VERIFY_PAUSE
            }
        }

        private fun verifyModeOfBase(base: TrustConfig): Int =
            when (base) {
                is TrustConfig.AnchoredCa -> KslConst.VERIFY_OPENSSL
                is TrustConfig.Platform -> if (platformTrustViaOpenSsl) KslConst.VERIFY_OPENSSL else KslConst.VERIFY_PAUSE
                is TrustConfig.ExpectedName -> verifyModeOfBase(base.base)
                else -> KslConst.VERIFY_PAUSE
            }

        fun rootsOf(trust: TrustConfig): List<Certificate>? =
            when (trust) {
                is TrustConfig.AnchoredCa -> trust.roots

                is TrustConfig.Platform -> if (platformTrustViaOpenSsl) emptyList() else null

                // empty = OpenSSL default paths
                is TrustConfig.Pinned -> rootsOf(trust.base)

                is TrustConfig.ExpectedName -> rootsOf(trust.base)

                else -> null
            }

        /**
         * A context of its own for one session, the caller's to close (its [Lease]). [quicTickets]: a QUIC server issues session tickets (two
         * per full handshake, one per resumption) and, with [earlyData], ones that allow 0-RTT (ADR-0015); a QUIC server without
         * it issues none. Servers use [acquire].
         */
        fun create(
            config: TlsConfig,
            quic: Boolean,
            quicTickets: Boolean = false,
            earlyData: Boolean = false,
        ): Lease = Lease(build(config, quic, quicTickets, earlyData, null)!!)

        /**
         * The context for one more session of [config], the caller's to close (one reference, its [Lease]). A server configuration with an
         * identity shares one context per identity snapshot between all its sessions (P.3: `SSL_CTX_new` and the identity's
         * set-up were a twelfth of a handshake's CPU), kept by that snapshot until it is closed ([SharedServerContexts]); a
         * `TlsIdentity.Reloadable` takes its [TlsIdentity.Reloadable.current] snapshot per handshake, as before, so a reload makes
         * the next handshake build a context from the new identity. A context is immutable once built (`ksl_ctx_freeze`), and
         * everything that differs per connection lives in the session (`ksl_ssl`); the process ticket keys are looked up per
         * ticket, so they rotate under a shared context. Anything else (a client, an SNI override, a server without an identity)
         * gets a context of its own ([create]).
         *
         * @throws IllegalStateException when the identity is closed.
         */
        fun acquire(
            config: TlsConfig,
            quic: Boolean,
            quicTickets: Boolean = false,
            earlyData: Boolean = false,
        ): Lease {
            if (config.role != TlsRole.Server) return create(config, quic, quicTickets, earlyData)
            val ctx =
                when (val id = config.identity) {
                    is TlsIdentity.InMemory -> {
                        id.serverContexts.acquire(config, quic, quicTickets, earlyData) { build(config, quic, quicTickets, earlyData, id) }
                            ?: throw IllegalStateException("identity closed")
                    }

                    is TlsIdentity.Reloadable -> {
                        id.withCurrentSnapshot { cur ->
                            cur.serverContexts.acquire(
                                config,
                                quic,
                                quicTickets,
                                earlyData,
                            ) { build(config, quic, quicTickets, earlyData, cur) }
                        }
                    }

                    null -> {
                        return create(config, quic, quicTickets, earlyData)
                    }
                }
            return Lease(ctx)
        }

        /**
         * Builds and freezes a context. [snapshot]: the identity to configure instead of resolving `config.identity` (its key
         * taken with [TlsIdentity.InMemory.tryAcquire]); null is returned, and nothing is left behind, when that snapshot's key
         * is already gone (closed and released): the caller retries with the current one or reports the identity closed.
         */
        private fun build(
            config: TlsConfig,
            quic: Boolean,
            quicTickets: Boolean,
            earlyData: Boolean,
            snapshot: TlsIdentity.InMemory?,
        ): KslContext? {
            KslLoader.ensureLoaded()
            config.validateFor(quic)
            if (earlyData && config.role == TlsRole.Server && config.clientAuth != ClientAuth.None) {
                throw TlsException.Config("0-RTT with client certificates is not supported")
            }
            if (snapshot != null && !snapshot.tryAcquire()) return null
            try {
                val h = Ksl.ctxNew(if (config.role == TlsRole.Client) KslConst.CLIENT else KslConst.SERVER)
                try {
                    val tag: String?
                    try {
                        tag = configure(h, config, quic, snapshot)
                        if (quic && quicTickets && config.role == TlsRole.Server) quicServerTickets(h, config, earlyData)
                    } catch (
                        e: KslException.Internal,
                    ) {
                        throw TlsException.Config("invalid TLS configuration: ${e.message}")
                    }
                    Ksl.ctxFreeze(h)
                    return KslContext(h, config, quic, tag, quicTickets, earlyData)
                } catch (t: Throwable) {
                    Ksl.ctxFree(h)
                    throw t
                }
            } finally {
                snapshot?.release()
            }
        }

        /** [identityTag] of [leaf]: the SHA-256 of its DER, hex. */
        private fun certificateTag(leaf: Certificate): String =
            Ksl.sha2(256, leaf.encoded).joinToString("") { (it.toInt() and 0xff).toString(16).padStart(2, '0') }

        /** Returns the [identityTag] of the identity it configured: [snapshot] (whose key the caller holds) when given. */
        private fun configure(
            h: Long,
            config: TlsConfig,
            quic: Boolean,
            snapshot: TlsIdentity.InMemory?,
        ): String? {
            if (config.alpn.isNotEmpty()) Ksl.ctxSetAlpn(h, alpnWire(config.alpn))
            if (!quic && config.versions == TlsVersions.Tls12And13) Ksl.ctxSetOption(h, KslConst.OPT_MIN_VERSION, KslConst.TLS1_2)
            Ksl.ctxSetCiphers(h, config.cipherSuites.openSslList, null)
            val tag =
                if (snapshot != null) {
                    Ksl.ctxSetIdentityKey(h, snapshot.chain.map { it.encoded }, snapshot.keyHandle)
                    certificateTag(snapshot.chain[0])
                } else {
                    config.identity?.let { id -> identityOf(h, id) }
                }
            if (config.role ==
                TlsRole.Client
            ) {
                rootsOf(config.trust)?.let { Ksl.ctxSetRoots(h, it.map { c -> c.encoded }) }
            } else {
                rootsOf(config.trust)?.takeIf { it.isNotEmpty() }?.let { Ksl.ctxSetRoots(h, it.map { c -> c.encoded }) }
            }
            if (config.role == TlsRole.Client) {
                Ksl.ctxSetOption(h, KslConst.OPT_VERIFY_MODE, verifyModeFor(config))
            } else {
                Ksl.ctxSetOption(
                    h,
                    KslConst.OPT_CLIENT_CERT,
                    when (config.clientAuth) {
                        ClientAuth.None -> KslConst.CLIENT_CERT_NONE
                        ClientAuth.Optional -> KslConst.CLIENT_CERT_OPTIONAL
                        ClientAuth.Required -> KslConst.CLIENT_CERT_REQUIRED
                    },
                )
                if (config.sniSelector != null) Ksl.ctxSetOption(h, KslConst.OPT_SNI_PAUSE, 1)
                if (!quic) {
                    // contexts of other configurations and processes (and, before P.3, of every connection): without shared keys no ticket could be
                    // resumed elsewhere, so the default is a process-wide rotating set
                    useTicketKeys(h, config.sessionTickets)
                    Ksl.ctxSetOption(
                        h,
                        KslConst.OPT_TICKET_LIFETIME,
                        config.sessionTickets.ticketLifetime.inWholeSeconds
                            .toInt()
                            .coerceAtLeast(1),
                    )
                    // tickets are issued explicitly after the pin verdict when client certificates are pinned (ADR-0012); with 0, ksl also
                    // suppresses the in-handshake TLS 1.2 ticket, which would precede the verdict
                    // a ticket resumes only under the trust configuration that issued it (and, for pinned clients, only after its verdict)
                    Ksl.ctxSetSessionContext(h, Ksl.sha2(256, "server|${config.clientAuth}|${config.trust.cacheKey()}".encodeToByteArray()))
                    Ksl.ctxSetOption(
                        h,
                        KslConst.OPT_NUM_TICKETS,
                        if (config.trust is TrustConfig.Pinned &&
                            config.clientAuth != ClientAuth.None
                        ) {
                            0
                        } else {
                            TlsConnection.TCP_TICKETS
                        },
                    )
                }
            }
            if (config.keylog != null) Ksl.ctxSetOption(h, KslConst.OPT_KEYLOG, 1)
            if (config.genericAlerts) Ksl.ctxSetOption(h, KslConst.OPT_GENERIC_ALERTS, 1)
            return tag
        }

        private fun quicServerTickets(
            h: Long,
            config: TlsConfig,
            earlyData: Boolean,
        ) {
            useTicketKeys(h, config.sessionTickets)
            Ksl.ctxSetOption(
                h,
                KslConst.OPT_TICKET_LIFETIME,
                config.sessionTickets.ticketLifetime.inWholeSeconds
                    .toInt()
                    .coerceAtLeast(1),
            )
            Ksl.ctxSetSessionContext(h, Ksl.sha2(256, "quic|server|${config.clientAuth}|${config.trust.cacheKey()}".encodeToByteArray()))
            Ksl.ctxSetOption(h, KslConst.OPT_NUM_TICKETS, 2)
            if (earlyData) Ksl.ctxSetOption(h, KslConst.OPT_EARLY_DATA, 1)
        }

        /** Configures [id] into [h]; returns its [identityTag]. */
        private fun identityOf(
            h: Long,
            id: TlsIdentity,
        ): String =
            when (id) {
                is TlsIdentity.InMemory -> {
                    id.withKey { k -> Ksl.ctxSetIdentityKey(h, id.chain.map { it.encoded }, k) }
                    certificateTag(id.chain[0])
                }

                // chain and key from one snapshot: a reload between them would pair one identity's chain with another's key
                is TlsIdentity.Reloadable -> {
                    id.withCurrentKey { cur, k ->
                        Ksl.ctxSetIdentityKey(h, cur.chain.map { it.encoded }, k)
                        certificateTag(cur.chain[0])
                    }
                }
            }

        fun alpnWire(alpn: List<String>): ByteArray =
            alpn
                .flatMap { p ->
                    val b = p.encodeToByteArray()
                    listOf(b.size.toByte()) +
                        b.toList()
                }.toByteArray()
    }
}

/**
 * The server contexts built from one identity snapshot ([TlsIdentity.InMemory.serverContexts]), one per configuration and kind
 * ([KslContext.serves]), each shared by every session of its configuration. The registry holds one reference to each; [close]
 * (the identity's close, which a reload does to the snapshot it replaces) drops them, so a context goes when the identity is
 * closed and its last session is gone, never while a session uses it. At most [MAX] contexts are kept: the least recently used
 * one goes first (a process that keeps building new configurations around one identity holds no more), and still serves its
 * sessions. A hit in the older half moves its context to the young end of the list (best effort: a concurrent change wins).
 */
internal class SharedServerContexts {
    // null once closed: nothing is kept any more
    private val entries = AtomicReference<List<KslContext>?>(emptyList())

    /**
     * One reference to the context for these arguments, [build] it when there is none yet (null from [build]: the snapshot's key
     * is gone). Null when the registry is closed and [build] could not run, or returned null.
     */
    fun acquire(
        config: TlsConfig,
        quic: Boolean,
        quicTickets: Boolean,
        earlyData: Boolean,
        build: () -> KslContext?,
    ): KslContext? {
        val first = entries.load() ?: return null
        find(first, config, quic, quicTickets, earlyData)?.let {
            touch(first, it)
            return it
        }
        val made = build() ?: return null
        while (true) {
            // closed meanwhile: the context was built from a key still held, so this handshake goes on with it, unshared
            val list = entries.load() ?: return made
            find(list, config, quic, quicTickets, earlyData)?.let {
                made.release() // another session built one first: share that one
                touch(list, it)
                return it
            }
            check(made.tryRetain()) // the registry's reference
            val grown = list + made
            val evicted = if (grown.size > MAX) grown[0] else null
            if (entries.compareAndSet(list, if (evicted != null) grown.drop(1) else grown)) {
                evicted?.release()
                return made
            }
            made.release() // the list changed: give the registry's reference back and look again
        }
    }

    private fun find(
        list: List<KslContext>,
        config: TlsConfig,
        quic: Boolean,
        quicTickets: Boolean,
        earlyData: Boolean,
    ): KslContext? {
        for (c in list) if (c.serves(config, quic, quicTickets, earlyData) && c.tryRetain()) return c
        return null
    }

    /**
     * Moves [c] to the young end of [list] when it is in the older half; the references do not change. A context in the younger
     * half stays put: a server alternating between its configurations then costs no list copy and no CAS per handshake, and
     * eviction still takes one that was not used lately.
     */
    private fun touch(
        list: List<KslContext>,
        c: KslContext,
    ) {
        val i = list.indexOfFirst { it === c }
        if (i >= 0 && i < list.size / 2) entries.compareAndSet(list, list.filter { it !== c } + c)
    }

    /** Drops the registry's references; contexts still in use go with their last session. */
    fun close() {
        entries.exchange(null)?.forEach { it.release() }
    }

    private companion object {
        /** Contexts one identity snapshot keeps: a server rarely has more configurations per identity (QUIC, TCP, a few ports). */
        const val MAX = 8
    }
}

/**
 * Session ticket keys stay in `ksl` (threat model 1, 3.7): the process-wide generated keys are made and rotated there (current +
 * previous, per [SessionTicketConfig.rotateEvery]); explicit keys were copied there when the [SessionTicketConfig] was built.
 */
internal fun useTicketKeys(
    h: Long,
    tickets: SessionTicketConfig,
) {
    if (tickets.keysId != 0) {
        Ksl.ctxUseTicketKeys(h, tickets.keysId)
    } else {
        Ksl.ctxUseDefaultTicketKeys(h, tickets.rotateEvery.inWholeSeconds.toInt())
    }
}

/** Maps a `ksl` failure to the TLS exception model and the alert to send (RFC 9846 section 6.2). */
internal fun KslException.Internal.toTlsFailure(presented: List<Certificate>): Pair<TlsException, Int?> {
    val received = alert and 0x100 != 0
    val code = alert and 0xff
    val x509 = alert ushr 16 // X509_V_ERR_* of a local verification failure
    if (received && code != 0) return TlsException.AlertReceived(code, alertName(code)) to null
    val reason: VerifyReason? =
        when (x509) {
            62, 64 -> {
                VerifyReason.HostnameMismatch(
                    "",
                    presented.firstOrNull()?.let { c ->
                        runCatching {
                            c.dnsNames +
                                c.ipAddresses.map { ip -> ip.joinToString(".") { b -> (b.toInt() and 0xff).toString() } }
                        }.getOrNull()
                    }
                        ?: emptyList(),
                )
            }

            // HOSTNAME_MISMATCH, IP_ADDRESS_MISMATCH; a certificate the walker cannot read reports no names instead of failing
            9 -> {
                VerifyReason.NotYetValid
            }

            10 -> {
                VerifyReason.Expired
            }

            23 -> {
                VerifyReason.Revoked
            }

            26 -> {
                VerifyReason.InvalidPurpose
            }

            2, 18, 19, 20, 21, 24, 27 -> {
                VerifyReason.UnknownIssuer
            }

            // issuer / self-signed / untrusted family
            7, 8 -> {
                VerifyReason.BadSignature
            }

            // EE_KEY_TOO_SMALL, CA_KEY_TOO_SMALL; CA_MD_TOO_WEAK: below the security level (ksl on the pause path, OpenSSL on its own)
            66, 67 -> {
                VerifyReason.WeakKey
            }

            68 -> {
                VerifyReason.WeakSignature
            }

            else -> {
                when {
                    x509 != 0 -> VerifyReason.Custom("X509 verification error $x509")
                    code == 42 -> VerifyReason.BadSignature
                    code == 43 -> VerifyReason.InvalidPurpose
                    code == 44 -> VerifyReason.Revoked
                    code == 45 -> VerifyReason.Expired
                    code == 48 -> VerifyReason.UnknownIssuer
                    else -> null
                }
            }
        }
    return if (reason != null &&
        !received
    ) {
        TlsException.Verify(reason, presented) to code
    } else {
        TlsException.Protocol(
            if (isKsl) null else packed,
            message ?: "TLS failure",
            this,
        ) to
            (if (code != 0 && !received) code else null)
    }
}

internal fun alertName(code: Int): String =
    when (code) {
        0 -> "close_notify"
        10 -> "unexpected_message"
        20 -> "bad_record_mac"
        40 -> "handshake_failure"
        42 -> "bad_certificate"
        43 -> "unsupported_certificate"
        44 -> "certificate_revoked"
        45 -> "certificate_expired"
        46 -> "certificate_unknown"
        47 -> "illegal_parameter"
        48 -> "unknown_ca"
        49 -> "access_denied"
        50 -> "decode_error"
        51 -> "decrypt_error"
        70 -> "protocol_version"
        71 -> "insufficient_security"
        80 -> "internal_error"
        86 -> "inappropriate_fallback"
        90 -> "user_canceled"
        109 -> "missing_extension"
        110 -> "unsupported_extension"
        112 -> "unrecognized_name"
        113 -> "bad_certificate_status_response"
        115 -> "unknown_psk_identity"
        116 -> "certificate_required"
        117 -> "general_error"
        120 -> "no_application_protocol"
        else -> "alert_$code"
    }
