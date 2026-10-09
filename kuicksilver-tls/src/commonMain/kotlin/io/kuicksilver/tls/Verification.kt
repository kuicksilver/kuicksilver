// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(DelicateKuicksilverApi::class)

package io.kuicksilver.tls

import io.kuicksilver.annotations.DelicateKuicksilverApi
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/**
 * The platform's own verifier (ADR-0011, ADR-0012): JDK/Android TrustManager, Apple SecTrust, Windows CertVerify. Only trust and
 * (where the platform supports it) the name are decided here; `ksl` re-checks the reference identifier afterwards.
 */
internal expect object PlatformVerifier {
    suspend fun verify(
        chain: List<Certificate>,
        host: HostName,
        role: TlsRole,
    ): VerifyResult
}

/** True where [TrustConfig.Platform] means "OpenSSL with the system certificate directory" (Linux), so no pause is needed. */
internal expect val platformTrustViaOpenSsl: Boolean

/**
 * Runs the Kotlin side of trust for a paused client handshake: base trust (platform, custom, TOFU), then pins against
 * the validated chain. Name and purpose are enforced by `ksl` when the handshake resumes (ADR-0011 rule 4).
 */
internal class Verification(
    private val config: TlsConfig,
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
                    withContext(Dispatchers.Default) { PlatformVerifier.verify(presented, reference, config.role) }
                }

                is TrustConfig.ExpectedName -> {
                    when (val inner = base.base) {
                        is TrustConfig.Platform -> {
                            withContext(
                                Dispatchers.Default,
                            ) { PlatformVerifier.verify(presented, reference, config.role) }
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
