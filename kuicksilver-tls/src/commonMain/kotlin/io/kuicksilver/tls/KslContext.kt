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
    /**
     * The certificate chain this context presents (leaf first), the snapshot [identityTag] was taken from; empty without an
     * identity. A server's requests are checked against its leaf (RFC 9110 section 7.4).
     */
    val localChain: List<Certificate>,
    private val quicTickets: Boolean,
    private val earlyData: Boolean,
    /**
     * The bundle a `TrustConfig.ReloadableCa` in [config] gave when this context was built (its roots are this context's
     * client-certificate anchors), null for any other trust: a server's handshakes share a context only under the same bundle.
     */
    val trustSnapshot: TrustConfig.AnchoredCa?,
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
        trustSnapshot: TrustConfig.AnchoredCa?,
    ): Boolean = sameKind(config, quic, quicTickets, earlyData) && sameBundle(this.trustSnapshot, trustSnapshot)

    /**
     * The client certificate check at the end of a server handshake under a `TrustConfig.ReloadableCa`: OpenSSL verified
     * [presented] (leaf first) against [trustSnapshot], the bundle current when the ClientHello arrived; when a reload has
     * replaced that bundle with other certificates since, the chain is verified again (at the context's security level)
     * against the bundle current now, and the pins of a `TrustConfig.Pinned` around it are checked on the path built under it,
     * until the bundle it passed is still the current one. So after `reload` returns no handshake completes with a
     * certificate only a removed CA vouches for, however its flights were timed. Returns null when it passes (and for a client
     * without a certificate, any other trust, or a bundle whose certificates did not change), else why it failed. A resumed
     * session (no Certificate message: [presented] holds only the leaf its session kept) whose bundle changed during its
     * handshake passes only if that leaf chains to the new bundle without intermediates.
     */
    fun recheckClientChain(presented: List<Certificate>): VerifyReason? {
        var verifiedUnder = trustSnapshot ?: return null
        if (presented.isEmpty()) return null
        while (true) {
            val now = clientCaSnapshot(config) ?: return null
            if (sameBundle(now, verifiedUnder)) return null
            // a context of its own, never registered: an SNI override's configuration is a copy per connection, and a rare
            // recheck must not push the shared contexts out of their registry
            val lease =
                try {
                    create(config, quic, quicTickets, earlyData)
                } catch (e: IllegalStateException) {
                    return VerifyReason.Custom("the client CA bundle changed and cannot be checked again: ${e.message}")
                }
            try {
                val under = lease.ctx.trustSnapshot ?: return null
                val path = ArrayList<ByteArray>()
                val err = Ksl.ctxVerifyChainPath(lease.ctx.handle, presented.map { it.encoded }, null, 0, path)
                if (err != 0) {
                    return verifyReasonOf(if (err > 0) err else 0, 0, presented)
                        ?: VerifyReason.Custom("the client certificate does not pass the reloaded CA bundle")
                }
                // pins (CA scope too) hold on the path built under the new bundle, not on the one of the handshake
                val pinned = Verification(config).pinCheck(path.map(::Certificate))
                if (pinned is VerifyResult.Rejected) return pinned.reason
                verifiedUnder = under
            } finally {
                lease.close()
            }
        }
    }

    /** Built for the same configuration and kind as [other], whatever the client CA bundle. */
    fun sameKindAs(other: KslContext): Boolean = sameKind(other.config, other.quic, other.quicTickets, other.earlyData)

    private fun sameKind(
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
        ): Lease = Lease(build(config, quic, quicTickets, earlyData, null, clientCaSnapshot(config))!!)

        /**
         * The context for one more session of [config], the caller's to close (one reference, its [Lease]). A server configuration with an
         * identity shares one context per identity snapshot between all its sessions (P.3: `SSL_CTX_new` and the identity's
         * set-up were a twelfth of a handshake's CPU), kept by that snapshot until it is closed ([SharedServerContexts]); a
         * `TlsIdentity.Reloadable` takes its [TlsIdentity.Reloadable.current] snapshot per handshake, as before, so a reload makes
         * the next handshake build a context from the new identity. A context is immutable once built (`ksl_ctx_freeze`), and
         * everything that differs per connection lives in the session (`ksl_ssl`); the process ticket keys are looked up per
         * ticket, so they rotate under a shared context. A `TrustConfig.ReloadableCa` is read once per handshake as well: the
         * context also carries the client CA bundle, so contexts are shared per identity snapshot and bundle, and the first
         * handshake after a reload builds one with the new bundle. Anything else (a client, an SNI override, a server without an
         * identity) gets a context of its own ([create]).
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
            // the client CA bundle of this handshake, read once: a reload after this line is for the next handshake
            val ca = clientCaSnapshot(config)
            val ctx =
                when (val id = config.identity) {
                    is TlsIdentity.InMemory -> {
                        id.serverContexts.acquire(config, quic, quicTickets, earlyData, ca) {
                            build(config, quic, quicTickets, earlyData, id, ca)
                        }
                            ?: throw IllegalStateException("identity closed")
                    }

                    is TlsIdentity.Reloadable -> {
                        id.withCurrentSnapshot { cur ->
                            cur.serverContexts.acquire(
                                config,
                                quic,
                                quicTickets,
                                earlyData,
                                ca,
                            ) { build(config, quic, quicTickets, earlyData, cur, ca) }
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
         * [ca]: the bundle of a `TrustConfig.ReloadableCa` in `config.trust` this context verifies client certificates against
         * (read once by the caller), null for any other trust.
         */
        private fun build(
            config: TlsConfig,
            quic: Boolean,
            quicTickets: Boolean,
            earlyData: Boolean,
            snapshot: TlsIdentity.InMemory?,
            ca: TrustConfig.AnchoredCa?,
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
                    val chain: List<Certificate>
                    try {
                        val trust = config.trust.withSnapshot(ca)
                        chain = configure(h, config, quic, snapshot, trust)
                        if (quic && quicTickets && config.role == TlsRole.Server) quicServerTickets(h, config, earlyData, trust)
                    } catch (
                        e: KslException.Internal,
                    ) {
                        throw TlsException.Config("invalid TLS configuration: ${e.message}")
                    }
                    Ksl.ctxFreeze(h)
                    return KslContext(h, config, quic, chain.firstOrNull()?.let(::certificateTag), chain, quicTickets, earlyData, ca)
                } catch (t: Throwable) {
                    Ksl.ctxFree(h)
                    throw t
                }
            } finally {
                snapshot?.release()
            }
        }

        /**
         * The bundle of a `TrustConfig.ReloadableCa` in a server's `config.trust` that this handshake verifies client
         * certificates against, read once; null for any other trust, and when the server asks for no client certificate (the
         * bundle then plays no part: a reload neither builds another context nor voids tickets).
         */
        fun clientCaSnapshot(config: TlsConfig): TrustConfig.AnchoredCa? =
            if (config.role == TlsRole.Server && config.clientAuth != ClientAuth.None) config.trust.reloadableSnapshot() else null

        /** [identityTag] of [leaf]: the SHA-256 of its DER, hex. */
        private fun certificateTag(leaf: Certificate): String =
            Ksl.sha2(256, leaf.encoded).joinToString("") { (it.toInt() and 0xff).toString(16).padStart(2, '0') }

        /**
         * Returns the chain of the identity it configured (empty without one): [snapshot] (whose key the caller holds) when given. [trust] is
         * `config.trust` with a ReloadableCa replaced by the bundle this context was built for.
         */
        private fun configure(
            h: Long,
            config: TlsConfig,
            quic: Boolean,
            snapshot: TlsIdentity.InMemory?,
            trust: TrustConfig,
        ): List<Certificate> {
            if (config.alpn.isNotEmpty()) Ksl.ctxSetAlpn(h, alpnWire(config.alpn))
            if (!quic && config.versions == TlsVersions.Tls12And13) Ksl.ctxSetOption(h, KslConst.OPT_MIN_VERSION, KslConst.TLS1_2)
            Ksl.ctxSetCiphers(h, config.cipherSuites.openSslList, null)
            val chain =
                if (snapshot != null) {
                    Ksl.ctxSetIdentityKey(h, snapshot.chain.map { it.encoded }, snapshot.keyHandle)
                    snapshot.chain
                } else {
                    config.identity?.let { id -> identityOf(h, id) } ?: emptyList()
                }
            if (config.role ==
                TlsRole.Client
            ) {
                rootsOf(trust)?.let { Ksl.ctxSetRoots(h, it.map { c -> c.encoded }) }
            } else {
                rootsOf(trust)?.takeIf { it.isNotEmpty() }?.let { Ksl.ctxSetRoots(h, it.map { c -> c.encoded }) }
            }
            if (config.role == TlsRole.Client) {
                val mode = verifyModeFor(config)
                Ksl.ctxSetOption(h, KslConst.OPT_VERIFY_MODE, mode)
                // T.5b: the platform's path is held to the level after its yes (platformLevel), not the presented chain before the pause
                if (mode == KslConst.VERIFY_PAUSE && platformDecides(config.trust)) Ksl.ctxSetOption(h, KslConst.OPT_LEVEL_AFTER_PAUSE, 1)
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
                    // and so, with a ReloadableCa, under the bundle it was authenticated with: a reload makes older tickets resume nothing
                    Ksl.ctxSetSessionContext(h, Ksl.sha2(256, "server|${config.clientAuth}|${trust.cacheKey()}".encodeToByteArray()))
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
            return chain
        }

        private fun quicServerTickets(
            h: Long,
            config: TlsConfig,
            earlyData: Boolean,
            trust: TrustConfig,
        ) {
            useTicketKeys(h, config.sessionTickets)
            Ksl.ctxSetOption(
                h,
                KslConst.OPT_TICKET_LIFETIME,
                config.sessionTickets.ticketLifetime.inWholeSeconds
                    .toInt()
                    .coerceAtLeast(1),
            )
            Ksl.ctxSetSessionContext(h, Ksl.sha2(256, "quic|server|${config.clientAuth}|${trust.cacheKey()}".encodeToByteArray()))
            Ksl.ctxSetOption(h, KslConst.OPT_NUM_TICKETS, 2)
            if (earlyData) Ksl.ctxSetOption(h, KslConst.OPT_EARLY_DATA, 1)
        }

        /** Configures [id] into [h]; returns the chain it configured. */
        private fun identityOf(
            h: Long,
            id: TlsIdentity,
        ): List<Certificate> =
            when (id) {
                is TlsIdentity.InMemory -> {
                    id.withKey { k -> Ksl.ctxSetIdentityKey(h, id.chain.map { it.encoded }, k) }
                    id.chain
                }

                // chain and key from one snapshot: a reload between them would pair one identity's chain with another's key
                is TlsIdentity.Reloadable -> {
                    id.withCurrentKey { cur, k ->
                        Ksl.ctxSetIdentityKey(h, cur.chain.map { it.encoded }, k)
                        cur.chain
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
        ca: TrustConfig.AnchoredCa?,
        build: () -> KslContext?,
    ): KslContext? {
        val first = entries.load() ?: return null
        find(first, config, quic, quicTickets, earlyData, ca)?.let {
            touch(first, it)
            return it
        }
        val made = build() ?: return null
        while (true) {
            // closed meanwhile: the context was built from a key still held, so this handshake goes on with it, unshared
            val list = entries.load() ?: return made
            // the bundle was reloaded while this context was built or since: it serves this handshake (which read the bundle
            // before the reload) and goes with it, unshared, so the registry never takes a context of a replaced bundle
            if (ca != null && !sameBundle(config.trust.reloadableSnapshot(), ca)) return made
            find(list, config, quic, quicTickets, earlyData, ca)?.let {
                made.release() // another session built one first: share that one
                touch(list, it)
                return it
            }
            check(made.tryRetain()) // the registry's reference
            // a context of an older client CA bundle serves no new handshake: the first context of the current one replaces it
            val stale = if (ca != null) list.filter { it.sameKindAs(made) && !sameBundle(it.trustSnapshot, ca) } else emptyList()
            val grown = list.filter { it !in stale } + made
            val evicted = if (grown.size > MAX) grown[0] else null
            if (entries.compareAndSet(list, if (evicted != null) grown.drop(1) else grown)) {
                stale.forEach { it.release() }
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
        ca: TrustConfig.AnchoredCa?,
    ): KslContext? {
        for (c in list) if (c.serves(config, quic, quicTickets, earlyData, ca) && c.tryRetain()) return c
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

    /** The contexts the registry holds now (tests). */
    internal fun contextsForTest(): List<KslContext> = entries.load().orEmpty()

    /** Drops the registry's references; contexts still in use go with their last session. */
    fun close() {
        entries.exchange(null)?.forEach { it.release() }
    }

    private companion object {
        /** Contexts one identity snapshot keeps: a server rarely has more configurations per identity (QUIC, TCP, a few ports). */
        const val MAX = 8
    }
}

/** The bundle a [TrustConfig.ReloadableCa] in this trust (alone or as the base of Pinned) holds now; null for any other trust. */
internal fun TrustConfig.reloadableSnapshot(): TrustConfig.AnchoredCa? =
    when (this) {
        is TrustConfig.ReloadableCa -> current
        is TrustConfig.Pinned -> (base as? TrustConfig.ReloadableCa)?.current
        else -> null
    }

/**
 * Whether two client CA bundles are the same trust: one object, or the same certificates in the same order (a reload with
 * unchanged content changes nothing: no other context, no recheck, the tickets stay).
 */
internal fun sameBundle(
    a: TrustConfig.AnchoredCa?,
    b: TrustConfig.AnchoredCa?,
): Boolean = a === b || (a != null && b != null && a.derKey == b.derKey)

/** This trust with its [TrustConfig.ReloadableCa] replaced by [ca] (from [reloadableSnapshot]); unchanged when [ca] is null. */
internal fun TrustConfig.withSnapshot(ca: TrustConfig.AnchoredCa?): TrustConfig =
    when {
        ca == null -> this
        this is TrustConfig.ReloadableCa -> ca
        this is TrustConfig.Pinned && base is TrustConfig.ReloadableCa -> TrustConfig.Pinned(pins, scope, ca)
        else -> this
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

/** The [VerifyReason] of an X509_V_ERR_* code (null for 0), or, without one, of the TLS alert [code] the failure carries. */
internal fun verifyReasonOf(
    x509: Int,
    code: Int,
    presented: List<Certificate>,
): VerifyReason? =
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

        2, 18, 19, 20, 21, 22, 24, 27 -> {
            VerifyReason.UnknownIssuer
        }

        // issuer / self-signed / untrusted family; 22 CERT_CHAIN_TOO_LONG (also ksl's chain walk past its bounds), unknown_ca on the wire
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

internal fun KslException.Internal.toTlsFailure(presented: List<Certificate>): Pair<TlsException, Int?> {
    val received = alert and 0x100 != 0
    val code = alert and 0xff
    val x509 = alert ushr 16 // X509_V_ERR_* of a local verification failure
    if (received && code != 0) return TlsException.AlertReceived(code, alertName(code)) to null
    val reason: VerifyReason? = verifyReasonOf(x509, code, presented)
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
