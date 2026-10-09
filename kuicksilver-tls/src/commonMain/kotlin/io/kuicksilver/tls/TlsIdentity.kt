// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(InternalKuicksilverApi::class)

package io.kuicksilver.tls

import io.kuicksilver.annotations.DelicateKuicksilverApi
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.annotations.InternalKuicksilverApi
import io.kuicksilver.native.Ksl
import io.kuicksilver.native.KslConst
import io.kuicksilver.native.KslException
import io.kuicksilver.native.KslLoader
import kotlin.io.encoding.Base64

/** A certificate chain (leaf first, RFC 8446 section 4.4.2) and the matching private key. */
public sealed interface TlsIdentity {
    /** The certificates sent to the peer, leaf first; the leaf's public key matches the private key. */
    public val chain: List<Certificate>

    /** v1: the key is held in memory (PKCS#8 DER); it is checked against `chain[0]` on creation and zeroed on [close]. */
    public class InMemory internal constructor(
        chain: List<Certificate>,
        keyDer: ByteArray,
    ) : TlsIdentity,
        AutoCloseable {
        override val chain: List<Certificate> = chain.toList()
        private var key: ByteArray? = keyDer
        internal val privateKeyDer: ByteArray get() = key ?: throw IllegalStateException("identity closed")

        override fun close() {
            key?.fill(0)
            key = null
        }
    }

    /**
     * Planned for v2: the key stays in a keystore or HSM. Not available in v1.
     *
     * @property signer signs handshake messages with the key; the constructor throws [UnsupportedOperationException] in v1.
     */
    @ExperimentalKuicksilverApi
    @DelicateKuicksilverApi
    public class Signer(
        chain: List<Certificate>,
        public val signer: PrivateKeySigner,
    ) : TlsIdentity {
        override val chain: List<Certificate> = chain.toList()

        init {
            throw UnsupportedOperationException("TlsIdentity.Signer is planned for v2")
        }
    }

    /** Factories: [fromPem], [fromDer], and on the JVM `fromKeyStore` and `fromPkcs12`. Each throws [TlsException.Config] on bad input. */
    public companion object {
        /** PEM chain (leaf first) + PKCS#8 PEM key as a `CharArray`, zeroed after import; encrypted keys are not supported in v1. */
        public fun fromPem(
            chainPem: String,
            keyPem: CharArray,
            password: CharArray? = null,
        ): InMemory {
            try {
                if (password != null) throw TlsException.Config("encrypted PEM keys are not supported in v1; decrypt before import")
                val chain = Pem.blocks(chainPem, "CERTIFICATE").map { Certificate(it) }
                val keys = Pem.blocks(keyPem.concatToString(), "PRIVATE KEY")
                if (keys.size != 1) throw TlsException.Config("expected exactly one PKCS#8 PRIVATE KEY block")
                return fromDer(chain.map { it.der }, keys[0])
            } finally {
                keyPem.fill('\u0000')
                password?.fill('\u0000')
            }
        }

        /** DER chain (leaf first) + PKCS#8 DER key; [keyDer] is zeroed after import. */
        public fun fromDer(
            chain: List<ByteArray>,
            keyDer: ByteArray,
        ): InMemory {
            try {
                if (chain.isEmpty()) throw TlsException.Config("empty certificate chain")
                val copy = keyDer.copyOf()
                checkKeyMatches(chain, copy)
                return InMemory(chain.map { Certificate(it) }, copy)
            } finally {
                keyDer.fill(0)
            }
        }

        /** Lets `ksl` (OpenSSL) confirm that the key belongs to the leaf; the temporary context is freed immediately. */
        private fun checkKeyMatches(
            chain: List<ByteArray>,
            keyDer: ByteArray,
        ) {
            KslLoader.ensureLoaded()
            val ctx = Ksl.ctxNew(KslConst.SERVER)
            try {
                Ksl.ctxSetIdentity(ctx, chain, keyDer)
            } catch (
                e: KslException.Internal,
            ) {
                throw TlsException.Config("private key does not match chain[0] or the chain is invalid: ${e.message}")
            } finally {
                Ksl.ctxFree(ctx)
            }
        }
    }
}

/** Planned for v2: signs with a key that never leaves its store. */
@DelicateKuicksilverApi
public interface PrivateKeySigner {
    /** The public half of the key as a DER SubjectPublicKeyInfo; it must match the leaf certificate. */
    public val publicKey: ByteArray

    /** Picks a SignatureScheme (RFC 8446 section 4.2.3) from those the peer [offered], or null when the key can use none. */
    public fun chooseScheme(offered: List<Int>): Int?

    /** Signs [message] with [scheme]; may suspend while a remote store or HSM answers. */
    public suspend fun sign(
        scheme: Int,
        message: ByteArray,
    ): ByteArray
}

internal object Pem {
    fun blocks(
        pem: String,
        type: String,
    ): List<ByteArray> {
        val begin = "-----BEGIN $type-----"
        val end = "-----END $type-----"
        val out = ArrayList<ByteArray>()
        var from = 0
        while (true) {
            val b = pem.indexOf(begin, from)
            if (b < 0) break
            val e = pem.indexOf(end, b)
            if (e < 0) throw TlsException.Config("unterminated PEM block $type")
            out += Base64.Mime.decode(pem.substring(b + begin.length, e))
            from = e + end.length
        }
        return out
    }
}
