// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(ExperimentalAtomicApi::class, io.kuicksilver.annotations.InternalKuicksilverApi::class)

package io.kuicksilver.tls

import io.kuicksilver.annotations.DelicateKuicksilverApi
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.native.Ksl
import kotlin.concurrent.atomics.AtomicReference
import kotlin.concurrent.atomics.ExperimentalAtomicApi
import kotlin.io.encoding.Base64

/**
 * How a peer is trusted (ADR-0011). Rules: the host name is always checked by the shared matcher and can be
 * replaced ([ExpectedName]) but never disabled; a pin is checked in addition to the base trust and against the
 * validated chain; session resumption never bypasses any of this.
 */
public sealed interface TrustConfig {
    /** The platform's trust store and verifier (JDK/Android TrustManager, Apple SecTrust, Windows CertVerify, OpenSSL system store on Linux). */
    public object Platform : TrustConfig {
        /** For logs. */
        override fun toString(): String = "Platform"
    }

    /** Only chains anchored at one of [roots][TrustConfig.AnchoredCa.roots] are trusted; verified by OpenSSL inside `ksl` (bypasses Android NSC on purpose). */
    public class AnchoredCa(
        roots: List<Certificate>,
    ) : TrustConfig {
        /**
         * The trust anchors, never empty (often from [Certificate.parsePem]); each is trusted as a root, also one that is not
         * self-signed (an intermediate CA: a chain that reaches it is accepted without its issuers); the OS store is not used.
         */
        public val roots: List<Certificate> = roots.toList()

        init {
            require(roots.isNotEmpty()) { "AnchoredCa needs at least one root" }
        }

        /** The SHA-256 of each root's DER, hex, in order: what session caches and server session contexts key this trust by. */
        internal val derKey: String by lazy {
            this.roots.joinToString(
                ",",
            ) { c -> Ksl.sha2(256, c.encoded).joinToString("") { (it.toInt() and 0xff).toString(16).padStart(2, '0') } }
        }
    }

    /**
     * Replaces the reference identifier: the certificate must match [name][TrustConfig.ExpectedName.name] (from configuration only) instead of the connection's host.
     * [base][TrustConfig.ExpectedName.base] is [Platform], [AnchoredCa] or [Custom]; to pin as well, wrap this one: `Pinned(pins, base = ExpectedName(name, base))`
     * (not with a [Custom] base: pins never sit on top of a Custom verifier).
     *
     * @property name the DNS name or IP literal the certificate must match (RFC 9525); never blank, validated when the
     *   [TlsConfig] is built. SNI still carries [TlsConfig.serverName].
     * @property base the trust that validates the chain; default [Platform]. Any other kind throws on construction.
     */
    @OptIn(DelicateKuicksilverApi::class)
    public class ExpectedName(
        public val name: String,
        public val base: TrustConfig = Platform,
    ) : TrustConfig {
        init {
            require(name.isNotBlank()) { "ExpectedName needs a name" }
            require(base !is ExpectedName) { "ExpectedName cannot wrap ExpectedName" }
            // any other base would build fine and then fail every handshake
            if (base !is Platform && base !is AnchoredCa &&
                base !is Custom
            ) {
                throw TlsException.Config(
                    "ExpectedName cannot wrap ${base::class.simpleName}: use Pinned(pins, base = ExpectedName(name, base))",
                )
            }
        }
    }

    /**
     * [base][TrustConfig.Pinned.base] trust AND one of [pins][TrustConfig.Pinned.pins] must match the validated chain within [scope][TrustConfig.Pinned.scope].
     *
     * @property scope which certificates of the validated chain may match; default [PinScope.Leaf], the strictest.
     * @property base the trust that must accept the chain as well (AND, never OR: ADR-0011); default [Platform]. [Tofu],
     *   [Custom] (also inside [ExpectedName]) and another [Pinned] throw [TlsException.Config]: a Custom verifier decides on
     *   its own, so pins on top of it would only look like a second check.
     */
    @OptIn(DelicateKuicksilverApi::class)
    public class Pinned(
        pins: Set<SpkiSha256>,
        public val scope: PinScope = PinScope.Leaf,
        public val base: TrustConfig = Platform,
    ) : TrustConfig {
        /**
         * The accepted SPKI hashes (RFC 7469), never empty; one match is enough, so list a backup key to survive a key
         * rotation. A miss fails with [VerifyReason.PinMismatch] even when [base][TrustConfig.Pinned.base] trusts the chain.
         */
        public val pins: Set<SpkiSha256> = pins.toSet()

        init {
            require(pins.isNotEmpty()) { "Pinned needs at least one pin" }
            if (base is Tofu || base is Custom) throw TlsException.Config("Pinned cannot be combined with ${base::class.simpleName}")
            if (base is ExpectedName &&
                base.base is Custom
            ) {
                throw TlsException.Config("Pinned cannot be combined with Custom, even through ExpectedName")
            }
            if (base is Pinned) throw TlsException.Config("Pinned cannot wrap Pinned")
        }
    }

    /**
     * Trust on first use: the first key seen for a name is stored and later connections must present it.
     *
     * The chain is not validated against any CA: the first connection to a name trusts whatever key it meets, so an attacker
     * present at that moment is trusted from then on. The host name is still checked; a later key change fails with
     * [VerifyReason.PinMismatch]. Clients only in v1.
     *
     * @property store where the leaf SPKI hash of each name is kept.
     */
    public class Tofu(
        public val store: TofuStore,
    ) : TrustConfig

    /**
     * A caller-provided verifier; it must check the name itself and is still followed by the shared matcher.
     *
     * @property verifier decides trust for each presented chain; clients only in v1.
     */
    @DelicateKuicksilverApi
    public class Custom(
        public val verifier: CertificateVerifier,
    ) : TrustConfig

    /**
     * A server's client-certificate CA bundle that can be replaced at run time (made by [TrustConfig.reloadable]): the
     * client CA rotates without a restart, as [TlsIdentity.Reloadable] rotates the server certificate. Servers only: wherever
     * an [AnchoredCa] verifies client certificates (`clientAuth` Optional or Required), alone or as the base of [Pinned];
     * a client configuration with one throws [TlsException.Config].
     *
     * **The rule.** After [reload] returns, no handshake accepts a client certificate that only a removed CA vouches for, over
     * TCP and QUIC alike and however the client times its flights; connections established before are not affected. A
     * handshake takes the [current] bundle when the client's ClientHello arrives (over TCP when its first bytes are there,
     * not at the accept; over QUIC with its first Initial) and OpenSSL verifies the client's certificate against it; when the
     * handshake completes and a [reload] has replaced that bundle meanwhile, the certificate is verified again against the
     * bundle current then, and the handshake fails unless it passes (a session resumed across a reload passes only if its
     * leaf chains to the new bundle on its own). Close connections of a compromised CA yourself. The handshakes of one server
     * configuration share one OpenSSL context per identity and bundle; the first handshake after a [reload] builds one with
     * the new bundle and drops the old one from the shared contexts, which is freed once that has happened and its last
     * connection is gone (a handshake that read the old bundle while the new one's context was built gets a context of its
     * own, freed with it). With `clientAuth` None the bundle plays no part: a reload changes nothing then. The server's
     * CertificateRequest carries no `certificate_authorities` extension (RFC 9846 section 4.3.4: "The server MAY send it"), so
     * no CA list is announced that a reload would have to change.
     *
     * **Resumption.** A session resumes only under the bundle it was authenticated with: after a [reload] a ticket issued
     * before it resumes nothing (RFC 9846 section 4.7.1: "A server MAY treat a ticket as valid for a shorter period"); the
     * client runs a full handshake, and its certificate is verified against the new bundle. A client whose CA was dropped
     * cannot get back in with a ticket.
     *
     * **Checks.** [reload] refuses a bundle in which no certificate is valid now (each expired, or not valid yet beyond 5
     * minutes of clock skew): it could accept no client. A bundle with some expired certificates is accepted (they anchor
     * nothing). The pins of a [Pinned] around this trust do not change with a reload.
     */
    @ExperimentalKuicksilverApi
    public class ReloadableCa internal constructor(
        initial: AnchoredCa,
        private val now: () -> Long = ::nowSeconds,
    ) : TrustConfig {
        init {
            validate(initial)
        }

        private val ref = AtomicReference(initial)

        /** The bundle handshakes whose ClientHello arrives now verify client certificates against; a snapshot a later [reload] does not change. */
        public val current: AnchoredCa get() = ref.load()

        /**
         * Makes [next] the bundle client certificates are verified against: once this returns, no handshake completes with a
         * certificate that only a CA missing from [next] vouches for; established connections are not affected.
         *
         * @throws TlsException.Config when no certificate of [next] is valid now; [current] stays.
         */
        public fun reload(next: AnchoredCa) {
            validate(next)
            ref.store(next)
        }

        private fun validate(bundle: AnchoredCa) {
            val t = now() // read once; the message carries no time, so a watcher's repeated failure reads the same
            if (bundle.roots.none { it.notAfterEpochSeconds >= t && it.notBeforeEpochSeconds <= t + NOT_BEFORE_SKEW_SECONDS }) {
                throw TlsException.Config("no certificate of the CA bundle is valid now (each expired or not valid yet)")
            }
        }

        /** For logs. */
        override fun toString(): String = "ReloadableCa"

        private companion object {
            /** How far a certificate's notBefore may lie ahead of our clock, as for [TlsIdentity.Reloadable]: 5 minutes. */
            const val NOT_BEFORE_SKEW_SECONDS: Long = 300
        }
    }

    /**
     * Anchor for platform extensions such as `TrustConfig.fromTrustManager` on the JVM, and [reloadable] for a client CA bundle
     * that rotates.
     */
    public companion object {
        /**
         * A [ReloadableCa] that starts with [initial] (see [ReloadableCa] for what a reload changes and the checks).
         *
         * @throws TlsException.Config when no certificate of [initial] is valid now.
         */
        @ExperimentalKuicksilverApi
        public fun reloadable(initial: AnchoredCa): ReloadableCa = ReloadableCa(initial)
    }
}

/** Which link of the validated chain a pin may match (RFC 7469 section 2.6). */
public enum class PinScope {
    /** Only the peer's own certificate: survives a CA change, breaks when the peer rotates its key. */
    Leaf,

    /** Any certificate of the chain the verifier built, intermediates and anchor included, never one only presented. */
    AnyInValidatedChain,
}

/** SHA-256 of a SubjectPublicKeyInfo; equality by content; text form is OkHttp's `sha256/<base64>`. */
public class SpkiSha256(
    bytes: ByteArray,
) {
    /** The digest, copied on construction and never handed out: pin checks compare it. */
    internal val digest: ByteArray = bytes.copyOf()

    /** The 32-byte digest; a fresh copy on every read, so changing it never changes a pin. */
    public val bytes: ByteArray get() = digest.copyOf()

    init {
        require(digest.size == 32) { "SpkiSha256 is 32 bytes" }
    }

    /** Equal when the digests are. */
    override fun equals(other: Any?): Boolean = other is SpkiSha256 && other.digest.contentEquals(digest)

    /** Consistent with [equals]. */
    override fun hashCode(): Int = digest.contentHashCode()

    /** OkHttp's text form, `sha256/<base64>`. */
    override fun toString(): String = "sha256/" + Base64.encode(digest)

    /** Holds [parse]. */
    public companion object {
        /** Parses `sha256/<base64>`. */
        public fun parse(text: String): SpkiSha256 {
            require(text.startsWith("sha256/")) { "expected sha256/<base64>" }
            return SpkiSha256(Base64.decode(text.removePrefix("sha256/")))
        }
    }
}

/** Asynchronous verifier used by [TrustConfig.Custom]. Contract: return [VerifyResult.Accepted] only after checking the name yourself. */
public fun interface CertificateVerifier {
    /**
     * Decides whether [chain] (as presented, leaf first) is trusted. [serverName] is the normalized reference identifier the
     * leaf must match (never null for a client), [role] is the local side. Return [VerifyResult.Accepted] with the chain you
     * validated (pins are compared against it) or [VerifyResult.Rejected]. Runs while the handshake is paused (ADR-0012),
     * so it may suspend for OCSP or network calls; the handshake deadline still applies.
     */
    public suspend fun verify(
        chain: List<Certificate>,
        serverName: String?,
        role: TlsRole,
    ): VerifyResult
}

/** Storage for [TrustConfig.Tofu]. */
public interface TofuStore {
    /** The pin stored for [name] (a normalized host name), or null on first contact; may be called concurrently. */
    public suspend fun get(name: String): SpkiSha256?

    /** Stores [pin] for [name] after a first contact; must persist across restarts, or every restart is a new first contact. */
    public suspend fun put(
        name: String,
        pin: SpkiSha256,
    )
}

/** Outcome of a verification step. */
public sealed interface VerifyResult {
    /** Trusted; [validatedChain][VerifyResult.Accepted.validatedChain] is the chain the verifier built (leaf first, anchor last), the one pins are compared against. */
    public class Accepted(
        validatedChain: List<Certificate>,
    ) : VerifyResult {
        /** The chain the verifier built, leaf first, anchor last. */
        public val validatedChain: List<Certificate> = validatedChain.toList()
    }

    /**
     * Not trusted: the handshake ends with [TlsException.Verify] and the alert of [reason][VerifyResult.Rejected.reason] ([alertCode]).
     *
     * @property reason why the peer was rejected.
     */
    public class Rejected(
        public val reason: VerifyReason,
    ) : VerifyResult
}

/** Why a peer was rejected; mapped to alerts by [alertCode]. */
public sealed interface VerifyReason {
    /**
     * The certificate does not match the reference identifier (RFC 9525); alert `bad_certificate` (42).
     *
     * @property expected the reference identifier ([TlsConfig.serverName] or [TrustConfig.ExpectedName.name]); empty when the
     *   OpenSSL-side matcher reported the mismatch.
     * @property presented the dNSName and iPAddress entries of the leaf, for diagnostics.
     */
    public class HostnameMismatch(
        public val expected: String,
        public val presented: List<String>,
    ) : VerifyReason {
        /** For logs. */
        override fun toString(): String = "HostnameMismatch(expected=$expected, presented=$presented)"
    }

    /**
     * No configured pin matched, or a [TrustConfig.Tofu] key changed; alert `bad_certificate` (42).
     *
     * @property chainPins the SPKI hashes of the checked chain, leaf first, to compare with the configuration; empty when
     *   the platform (Android network security config) reported the mismatch.
     */
    public class PinMismatch(
        public val chainPins: List<SpkiSha256>,
    ) : VerifyReason {
        /** For logs. */
        override fun toString(): String = "PinMismatch(chain=$chainPins)"
    }

    /** No chain to a trusted anchor could be built; alert `unknown_ca` (48). Also the fallback for unclassified platform failures. */
    public data object UnknownIssuer : VerifyReason

    /** A certificate of the chain is past its notAfter; alert `certificate_expired` (45). */
    public data object Expired : VerifyReason

    /** A certificate of the chain is before its notBefore; alert `certificate_expired` (45). */
    public data object NotYetValid : VerifyReason

    /** A certificate of the chain is revoked; alert `certificate_revoked` (44). */
    public data object Revoked : VerifyReason

    /**
     * The revocation status could not be determined and the verifier requires it; alert `unknown_ca` (48). Reported by the
     * platform verifier when it says so (JVM PKIX `UNDETERMINED_REVOCATION_STATUS`, Apple
     * `errSecIncompleteCertRevocationCheck`) and by a [CertificateVerifier]; `ksl`'s own verifier does not check revocation in v1.
     */
    public data object UnknownRevocationStatus : VerifyReason

    /** A signature in the chain does not verify; alert `bad_certificate` (42). */
    public data object BadSignature : VerifyReason

    /** The key usage or extended key usage forbids this use (RFC 5280 section 4.2.1.12); alert `unsupported_certificate` (43). */
    public data object InvalidPurpose : VerifyReason

    /** A certificate could not be parsed; alert `bad_certificate` (42). */
    public data object BadEncoding : VerifyReason

    /** The peer sent no certificate where one is required; alert `bad_certificate` (42). */
    public data object NoCertificate : VerifyReason

    /**
     * A key in the peer's chain is below OpenSSL security level 2, 112 bits (RSA under 2048 bits, an elliptic curve under
     * 224 bits); alert `bad_certificate` (42). Checked under every [TrustConfig] (the JDK, Android and Windows verifiers
     * accept 1024-bit RSA): on OpenSSL's own path ([TrustConfig.AnchoredCa], `Platform` on Linux) by OpenSSL on the path
     * it built; under [TrustConfig.Platform] elsewhere by `ksl` after the platform's yes, on the path the platform built
     * (a certificate the peer sent that the platform did not use does not count), or on the presented chain when the
     * platform does not say its path; under [TrustConfig.Custom] and [TrustConfig.Tofu] by `ksl` before the verifier or
     * the store is asked, on every certificate the peer sent that is reachable from the leaf through issuers whose key
     * verifies the signature (stricter than OpenSSL for a certificate sent above the anchor the application trusts). The
     * trust anchor's key counts everywhere.
     */
    @ExperimentalKuicksilverApi
    public data object WeakKey : VerifyReason

    /**
     * A certificate in the peer's chain is signed with a digest below OpenSSL security level 2, 112 bits: SHA-1 or MD5
     * (RFC 9846 section 4.5.1.3: MD5 MUST and SHA-1 SHOULD be refused); alert `bad_certificate` (42). The trust anchor's
     * signature is not checked on a path OpenSSL or the platform built, nor, on a presented chain, the own signature of a
     * self-signed certificate (one that verifies under its own key): they begin the path. Checked where [WeakKey] is.
     */
    @ExperimentalKuicksilverApi
    public data object WeakSignature : VerifyReason

    /**
     * A Certificate Transparency policy (RFC 6962) rejected the chain; alert `certificate_unknown` (46). Reported by the
     * platform verifier when it says so (Android, whose CT policy names it in its error) and by a [CertificateVerifier].
     */
    public data object CertificateTransparency : VerifyReason

    /**
     * A reason a [CertificateVerifier] or the platform gave that fits no other case; alert `certificate_unknown` (46).
     *
     * @property text a human-readable explanation, for logs.
     */
    public class Custom(
        public val text: String,
    ) : VerifyReason {
        /** For logs. */
        override fun toString(): String = "Custom($text)"
    }
}
