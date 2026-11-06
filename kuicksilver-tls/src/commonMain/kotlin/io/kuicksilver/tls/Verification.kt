// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(DelicateKuicksilverApi::class, InternalKuicksilverApi::class)

package io.kuicksilver.tls

import io.kuicksilver.annotations.DelicateKuicksilverApi
import io.kuicksilver.annotations.InternalKuicksilverApi
import io.kuicksilver.native.Ksl
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/**
 * The platform's own verifier (ADR-0011, ADR-0012): JDK/Android TrustManager, Apple SecTrust, Windows CertVerify. Only trust and
 * (where the platform supports it) the name are decided here; `ksl` re-checks the reference identifier afterwards.
 */
internal expect object PlatformVerifier {
    suspend fun evaluate(
        chain: List<Certificate>,
        host: HostName,
        role: TlsRole,
    ): PlatformVerdict
}

/** The platform's verdict alone, without the path it built. */
internal suspend fun PlatformVerifier.verify(
    chain: List<Certificate>,
    host: HostName,
    role: TlsRole,
): VerifyResult = evaluate(chain, host, role).result

/**
 * What the platform verifier said. On a yes, [builtPath] is the path it built, leaf first and its trust anchor last (Android
 * `X509TrustManagerExtensions.checkServerTrusted`, Apple `SecTrustCopyCertificateChain`, Windows the first simple chain of
 * `CertGetCertificateChain`, the JDK the PKIX path rebuilt to the trust manager's issuers), or null when the platform did not say
 * which path it took; [result]'s validated chain is what pins are compared against.
 */
internal class PlatformVerdict(
    val result: VerifyResult,
    val builtPath: List<Certificate>?,
)

/**
 * RFC 9325 section 4.5 under [TrustConfig.Platform] (T.5b): after the platform's yes, OpenSSL security level 2 (112 bits)
 * holds on the path the platform built, as OpenSSL holds it on the path it builds itself (`x509_vfy.c` `check_auth_level`):
 * every key, the anchor's included, and every signature but the anchor's. A certificate the peer sent that the platform did not
 * use (an extra cross-certificate above its anchor) does not count. When the platform did not say which path it took, the
 * presented chain is held to the level as for `Custom` and `Tofu` (the walk `ksl` runs before the pause): stricter, never
 * weaker. The same reasons and alert (`bad_certificate`) as that walk.
 *
 * A platform's no for a chain below the level (the JDK's algorithm constraints, SecTrust and CryptoAPI refuse MD5, SHA-1 and
 * small keys themselves) carries no such reason, only "untrusted": RFC 9846 section 4.5.1.3 still wants `bad_certificate`
 * (MUST for MD5, RECOMMENDED for SHA-1), so such a refusal is reported as [VerifyReason.WeakKey] or
 * [VerifyReason.WeakSignature] when the presented chain is below the level. A refusal for the name or the pins keeps its
 * reason, as does a refusal of a chain that meets the level.
 */
internal fun platformLevel(
    verdict: PlatformVerdict,
    presented: List<Certificate>,
): VerifyResult {
    val accepted =
        verdict.result as? VerifyResult.Accepted ?: return weakRefusal(verdict.result as VerifyResult.Rejected, presented)
    val path = verdict.builtPath?.takeIf { it.isNotEmpty() }
    return when (Ksl.chainLevel((path ?: presented).map { it.encoded }, builtPath = path != null)) {
        0 -> accepted

        // EE_KEY_TOO_SMALL, CA_KEY_TOO_SMALL
        66, 67 -> VerifyResult.Rejected(VerifyReason.WeakKey)

        // CA_MD_TOO_WEAK
        68 -> VerifyResult.Rejected(VerifyReason.WeakSignature)

        // CERT_CHAIN_TOO_LONG: the walk's bounds, unknown_ca as on the pause path
        22 -> VerifyResult.Rejected(VerifyReason.UnknownIssuer)

        else -> VerifyResult.Rejected(VerifyReason.BadEncoding)
    }
}

private fun weakRefusal(
    refused: VerifyResult.Rejected,
    presented: List<Certificate>,
): VerifyResult.Rejected {
    if (refused.reason is VerifyReason.HostnameMismatch || refused.reason is VerifyReason.PinMismatch || presented.isEmpty()) return refused
    return when (Ksl.chainLevel(presented.map { it.encoded }, builtPath = false)) {
        66, 67 -> VerifyResult.Rejected(VerifyReason.WeakKey)
        68 -> VerifyResult.Rejected(VerifyReason.WeakSignature)
        else -> refused
    }
}

/**
 * Whether [trust] has the platform verifier decide (directly, or under [TrustConfig.Pinned] / [TrustConfig.ExpectedName], as
 * [Verification] dispatches it): then the level holds on the path the platform built ([platformLevel]), and `ksl` does not check
 * the presented chain before the pause (`KSL_OPT_LEVEL_AFTER_PAUSE`).
 */
internal fun platformDecides(trust: TrustConfig): Boolean {
    val base = (trust as? TrustConfig.Pinned)?.base ?: trust
    return base is TrustConfig.Platform || (base is TrustConfig.ExpectedName && base.base is TrustConfig.Platform)
}

/** True where [TrustConfig.Platform] means "OpenSSL with the system certificate directory" (Linux), so no pause is needed. */
internal expect val platformTrustViaOpenSsl: Boolean

/**
 * Runs the Kotlin side of trust for a paused client handshake: base trust (platform, custom, TOFU), then pins against
 * the validated chain. Name and purpose are enforced by `ksl` when the handshake resumes (ADR-0011 rule 4).
 */
internal class Verification(
    private val config: TlsConfig,
    /** The platform verifier; tests put one in that says yes with a path of their choosing. */
    private val platform: suspend (List<Certificate>, HostName, TlsRole) -> PlatformVerdict = { chain, host, role ->
        withContext(Dispatchers.Default) { PlatformVerifier.evaluate(chain, host, role) }
    },
) {
    private val trust get() = config.trust

    suspend fun verify(
        presented: List<Certificate>,
        reference: HostName,
    ): VerifyResult {
        if (presented.isEmpty()) return VerifyResult.Rejected(VerifyReason.NoCertificate)
        val base =
            when (val t = trust) {
                is TrustConfig.Pinned -> t.base
                else -> t
            }
        val baseResult =
            when (base) {
                is TrustConfig.Platform -> {
                    platformLevel(platform(presented, reference, config.role), presented)
                }

                is TrustConfig.ExpectedName -> {
                    when (val inner = base.base) {
                        is TrustConfig.Platform -> {
                            platformLevel(platform(presented, reference, config.role), presented)
                        }

                        is TrustConfig.Custom -> {
                            inner.verifier.verify(presented, reference.value, config.role)
                        }

                        else -> {
                            return VerifyResult.Rejected(
                                VerifyReason.Custom("unsupported ExpectedName base ${inner::class.simpleName}"),
                            )
                        }
                    }
                }

                is TrustConfig.Custom -> {
                    base.verifier.verify(presented, reference.value, config.role)
                }

                is TrustConfig.Tofu -> {
                    tofu(base.store, presented, reference)
                }

                is TrustConfig.AnchoredCa -> {
                    VerifyResult.Accepted(presented)
                }

                // not reached: ksl verifies anchored chains itself
                is TrustConfig.Pinned -> {
                    error("nested Pinned")
                }
            }
        if (baseResult is VerifyResult.Rejected) return baseResult
        val validated = (baseResult as VerifyResult.Accepted).validatedChain.ifEmpty { presented }
        return pinCheck(validated)
    }

    /** Pin check against a chain the verifier (or `ksl`) built; also used after an AnchoredCa handshake. */
    fun pinCheck(validated: List<Certificate>): VerifyResult {
        val pinned = trust as? TrustConfig.Pinned ?: return VerifyResult.Accepted(validated)
        val candidates = if (pinned.scope == PinScope.Leaf) validated.take(1) else validated
        return if (candidates.any {
                it.spkiSha256 in pinned.pins
            }
        ) {
            VerifyResult.Accepted(validated)
        } else {
            VerifyResult.Rejected(VerifyReason.PinMismatch(validated.map { it.spkiSha256 }))
        }
    }

    private suspend fun tofu(
        store: TofuStore,
        presented: List<Certificate>,
        reference: HostName,
    ): VerifyResult {
        val leaf = presented[0].spkiSha256
        val known = store.get(reference.value)
        return when {
            known == null -> {
                store.put(reference.value, leaf)
                VerifyResult.Accepted(presented)
            }

            known == leaf -> {
                VerifyResult.Accepted(presented)
            }

            else -> {
                VerifyResult.Rejected(VerifyReason.PinMismatch(listOf(leaf)))
            }
        }
    }
}
