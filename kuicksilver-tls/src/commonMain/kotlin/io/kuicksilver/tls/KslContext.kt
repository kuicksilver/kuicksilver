// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(InternalKuicksilverApi::class, DelicateKuicksilverApi::class)

package io.kuicksilver.tls

import io.kuicksilver.annotations.DelicateKuicksilverApi
import io.kuicksilver.annotations.InternalKuicksilverApi
import io.kuicksilver.native.Ksl
import io.kuicksilver.native.KslConst
import io.kuicksilver.native.KslException
import io.kuicksilver.native.KslLoader
import kotlin.concurrent.atomics.AtomicReference
import kotlin.concurrent.atomics.ExperimentalAtomicApi

/** Translates a [TlsConfig] into a frozen `ksl_ctx`; shared by the QUIC and TCP sessions. */
internal class KslContext private constructor(
    val handle: Long,
    val config: TlsConfig,
    val quic: Boolean,
) : AutoCloseable {
    /** The verifier `ksl` runs itself (AnchoredCa) or the pause for Kotlin-side trust. */
    val verifyMode: Int = verifyModeFor(config)
    private var closed = false

    override fun close() {
        if (!closed) {
            closed = true
            Ksl.ctxFree(handle)
        }
    }

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

        fun create(
            config: TlsConfig,
            quic: Boolean,
        ): KslContext {
            KslLoader.ensureLoaded()
            config.validateFor(quic)
            val h = Ksl.ctxNew(if (config.role == TlsRole.Client) KslConst.CLIENT else KslConst.SERVER)
            try {
                try {
                    configure(h, config, quic)
                } catch (
                    e: KslException.Internal,
                ) {
                    throw TlsException.Config("invalid TLS configuration: ${e.message}")
                }
                Ksl.ctxFreeze(h)
                return KslContext(h, config, quic)
            } catch (t: Throwable) {
                Ksl.ctxFree(h)
                throw t
            }
        }

        private fun configure(
            h: Long,
            config: TlsConfig,
            quic: Boolean,
        ) {
            if (config.alpn.isNotEmpty()) Ksl.ctxSetAlpn(h, alpnWire(config.alpn))
            if (!quic && config.versions == TlsVersions.Tls12And13) Ksl.ctxSetOption(h, KslConst.OPT_MIN_VERSION, KslConst.TLS1_2)
            Ksl.ctxSetCiphers(h, config.cipherSuites.openSslList, null)
            config.identity?.let { id ->
                if (id is TlsIdentity.InMemory) {
                    Ksl.ctxSetIdentity(
                        h,
                        id.chain.map {
                            it.der
                        },
                        id.privateKeyDer,
                    )
                } else {
                    throw TlsException.Config("unsupported identity ${id::class.simpleName}")
                }
            }
            if (config.role ==
                TlsRole.Client
            ) {
                rootsOf(config.trust)?.let { Ksl.ctxSetRoots(h, it.map { c -> c.der }) }
            } else {
                rootsOf(config.trust)?.takeIf { it.isNotEmpty() }?.let { Ksl.ctxSetRoots(h, it.map { c -> c.der }) }
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
                    // every connection has its own SSL_CTX: without shared keys no ticket could ever be resumed, so the default is a process-wide rotating set
                    Ksl.ctxSetTicketKeys(h, config.sessionTickets.keys ?: DefaultTicketKeys.current(config.sessionTickets))
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
                            1
                        },
                    )
                }
            }
            if (config.keylog != null) Ksl.ctxSetOption(h, KslConst.OPT_KEYLOG, 1)
            if (config.genericAlerts) Ksl.ctxSetOption(h, KslConst.OPT_GENERIC_ALERTS, 1)
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

/** Process-wide session ticket keys (name 16 | AES-256 32 | HMAC 32), rotated per [SessionTicketConfig.rotateEvery] with one previous key kept. */
@OptIn(ExperimentalAtomicApi::class)
internal object DefaultTicketKeys {
    private class Keys(
        val current: ByteArray,
        val previous: ByteArray?,
        val rotatedAt: Long,
    )

    /** One immutable snapshot swapped atomically: servers starting together agree on the current key. */
    private val state = AtomicReference<Keys?>(null)

    internal fun resetForTest() {
        state.store(null)
    }

    fun current(config: SessionTicketConfig): List<ByteArray> {
        while (true) {
            val s = state.load()
            val now = nowSeconds()
            val keys =
                if (s != null &&
                    now - s.rotatedAt < config.rotateEvery.inWholeSeconds
                ) {
                    s
                } else {
                    Keys(Ksl.rand(80), s?.current, now).takeIf { state.compareAndSet(s, it) }
                        ?: continue
                }
            return listOfNotNull(keys.current, keys.previous).map { it.copyOf() }
        }
    }
}

/** Maps a `ksl` failure to the TLS exception model and the alert to send (RFC 8446 section 6.2). */
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
        120 -> "no_application_protocol"
        else -> "alert_$code"
    }
