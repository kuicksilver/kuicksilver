// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(InternalKuicksilverApi::class)

package io.kuicksilver.tls

import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.annotations.InternalKuicksilverApi
import io.kuicksilver.native.Ksl
import io.kuicksilver.native.KslConst
import io.kuicksilver.native.KslLoader

/**
 * The hash of a TLS 1.3 key schedule, chosen by the cipher suite (RFC 9846 section 7.1); used by [KslCrypto.hkdfExpandLabel].
 *
 * @property size the output length in bytes.
 */
public enum class Hash(
    internal val ksl: Int,
    public val size: Int,
) {
    /** SHA-256, 32 bytes: the hash of the AES-128-GCM and ChaCha20-Poly1305 suites. */
    Sha256(1, 32),

    /** SHA-384, 48 bytes: the hash of the AES-256-GCM suite. */
    Sha384(2, 48),
}

/** A signature algorithm of [KslCrypto.sign] and [KslCrypto.verify]. */
public enum class SignatureAlgorithm(
    internal val ksl: Int,
) {
    /** ECDSA over P-256 with SHA-256 and DER-encoded signatures (`ecdsa_secp256r1_sha256`, RFC 9846 section 4.3.3). */
    EcdsaP256(1),

    /** Ed25519 (RFC 8032), signing the message itself. */
    Ed25519(2),
}

/**
 * An AES-128-ECB block key for QUIC-LB connection IDs (draft-ietf-quic-load-balancers-21 section 5.4) held in `ksl`: the 16
 * key bytes are copied into native memory once and wiped there on [close]; Kotlin keeps only the handle. Immutable (the key
 * schedule is expanded once and copied per call), so [encrypt], [decrypt] and [derive] may run on several threads at once.
 * [close] is idempotent and safe from any thread, but it frees the native key: call it once no call on the key is running or
 * can start (an endpoint closes its keys after its loops stopped); a call after it throws IllegalStateException.
 */
@InternalKuicksilverApi
@OptIn(ExperimentalKuicksilverApi::class, kotlin.concurrent.atomics.ExperimentalAtomicApi::class)
public class KslLbKey internal constructor(
    handle: Long,
) : LoadBalancerKey {
    private val h = kotlin.concurrent.atomics.AtomicLong(handle)

    private fun k(): Long = h.load().also { if (it == 0L) throw IllegalStateException("KslLbKey is closed") }

    override fun derive(label: ByteArray): LoadBalancerKey = KslLbKey(Ksl.keyLbDerive(k(), label))

    override fun encrypt(
        input: ByteArray,
        inOffset: Int,
        out: ByteArray,
        outOffset: Int,
    ): Unit = Ksl.keyEcb16(k(), false, input, inOffset, out, outOffset)

    override fun decrypt(
        input: ByteArray,
        inOffset: Int,
        out: ByteArray,
        outOffset: Int,
    ): Unit = Ksl.keyEcb16(k(), true, input, inOffset, out, outOffset)

    /** One-block convenience: [encrypt] of `in16` into `out16`. */
    public fun encrypt(
        in16: ByteArray,
        out16: ByteArray,
    ): Unit = encrypt(in16, 0, out16, 0)

    /** One-block convenience: [decrypt] of `in16` into `out16`. */
    public fun decrypt(
        in16: ByteArray,
        out16: ByteArray,
    ): Unit = decrypt(in16, 0, out16, 0)

    override fun close() {
        val k = h.exchange(0L)
        if (k != 0L) Ksl.keyFree(k)
    }

    public companion object {
        /** A key from the 16 bytes of [key]; [key] is wiped whether or not this succeeds. */
        public fun of(key: ByteArray): KslLbKey {
            try {
                require(key.size == 16) { "a QUIC-LB key is 16 bytes, not ${key.size}" }
                KslLoader.ensureLoaded()
                return KslLbKey(Ksl.keyLb(key))
            } finally {
                key.fill(0)
            }
        }
    }
}

/** The small set of primitives the stack exposes from OpenSSL: random bytes, SHA-2, HKDF-Expand-Label, ECDSA P-256 and Ed25519. */
public object KslCrypto {
    private fun ready() = KslLoader.ensureLoaded()

    /** [n] bytes from OpenSSL's CSPRNG (`RAND_bytes`), fit for keys, nonces and connection IDs; thread-safe. [n] must not be negative. */
    public fun randomBytes(n: Int): ByteArray {
        ready()
        require(n >= 0) { "randomBytes: n must not be negative, was $n" }
        return Ksl.rand(n)
    }

    /** The SHA-256 digest of [data] (32 bytes). */
    public fun sha256(data: ByteArray): ByteArray {
        ready()
        return Ksl.sha2(256, data)
    }

    /** The SHA-384 digest of [data] (48 bytes). */
    public fun sha384(data: ByteArray): ByteArray {
        ready()
        return Ksl.sha2(384, data)
    }

    /** RFC 9846 section 7.1 `HKDF-Expand-Label(secret, label, context, length)`; the "tls13 " prefix is added here. */
    public fun hkdfExpandLabel(
        hash: Hash,
        secret: ByteArray,
        label: String,
        context: ByteArray,
        length: Int,
    ): ByteArray {
        ready()
        require(length in 1..65535) { "length 1..65535" }
        require(label.length <= 249) { "label too long" }
        require(context.size <= 255) { "context too long" }
        return Ksl.hkdfExpandLabel(hash.ksl, secret, label, context, length)
    }

    /** Signs [data] (unhashed) with a PKCS#8 DER key of the algorithm's type; ECDSA uses SHA-256 and DER-encoded signatures. */
    public fun sign(
        alg: SignatureAlgorithm,
        privateKeyDer: ByteArray,
        data: ByteArray,
    ): ByteArray {
        ready()
        return Ksl.sign(alg.ksl, privateKeyDer, data)
    }

    /**
     * Verifies with a DER SubjectPublicKeyInfo; a key of the wrong type throws, a bad signature returns false (also one that is
     * not a DER-encoded ECDSA signature, or empty).
     */
    public fun verify(
        alg: SignatureAlgorithm,
        publicKeyDer: ByteArray,
        data: ByteArray,
        signature: ByteArray,
    ): Boolean {
        ready()
        return Ksl.verify(alg.ksl, publicKeyDer, data, signature)
    }

    /** SHA-256 over the SubjectPublicKeyInfo of a DER certificate. */
    public fun spkiSha256(certificateDer: ByteArray): SpkiSha256 {
        ready()
        return SpkiSha256(Ksl.spkiSha256(certificateDer))
    }

    internal fun sha2(
        bits: Int,
        data: ByteArray,
    ): ByteArray {
        ready()
        return Ksl.sha2(bits, data)
    }

    internal val defaultHash: Int get() = KslConst.HASH_SHA256
}
