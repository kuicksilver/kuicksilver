// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(InternalKuicksilverApi::class, ExperimentalAtomicApi::class)

package io.kuicksilver.tls

import io.kuicksilver.annotations.InternalKuicksilverApi
import io.kuicksilver.native.Ksl
import io.kuicksilver.native.KslConst
import io.kuicksilver.native.KslException
import io.kuicksilver.native.KslLoader
import kotlin.concurrent.atomics.AtomicInt
import kotlin.concurrent.atomics.ExperimentalAtomicApi
import kotlin.io.encoding.Base64

/**
 * A certificate chain (leaf first, RFC 9846 section 4.5.1) and the matching private key. Sealed: the one kind in 0.2.0 is
 * [InMemory]; identities whose key stays in a keystore or HSM may be added later, so do not match on it exhaustively.
 */
public sealed interface TlsIdentity {
    /** The certificates sent to the peer, leaf first; the leaf's public key matches the private key. */
    public val chain: List<Certificate>

    /**
     * v1: the key is parsed once into OpenSSL (a native `ksl_pkey`) and checked against `chain[0]` on creation; Kotlin keeps
     * only the handle, never the key bytes (threat model 1, 3.7). Every context built from this identity holds its own
     * reference, so [close] frees the key once those contexts are gone too; closing is safe while connections still run.
     * Building a context after [close] throws [IllegalStateException].
     */
    public class InMemory internal constructor(
        chain: List<Certificate>,
        pkey: Long,
    ) : TlsIdentity,
        AutoCloseable {
        override val chain: List<Certificate> = chain.toList()
        private val pkey: Long = pkey

        // 1 for the owner until close(), +1 for each use in progress; the last release frees the native key
        private val refs = AtomicInt(1)

        private val closed = AtomicInt(0)

        /** Runs [block] with the native key handle; the key cannot be freed by a concurrent [close] meanwhile. */
        internal fun <T> withKey(block: (Long) -> T): T {
            while (true) {
                val r = refs.load()
                if (r == 0) throw IllegalStateException("identity closed")
                if (refs.compareAndSet(r, r + 1)) break
            }
            try {
                return block(pkey)
            } finally {
                release()
            }
        }

        private fun release() {
            if (refs.addAndFetch(-1) == 0) Ksl.pkeyFree(pkey)
        }

        /** True once [close] ran (the native key may still serve contexts built before). */
        internal val isClosed: Boolean get() = closed.load() != 0

        override fun close() {
            if (closed.compareAndSet(0, 1)) release()
        }
    }

    /** Factories: [fromPem], [fromDer], and on the JVM `fromKeyStore` and `fromPkcs12`. Each throws [TlsException.Config] on bad input. */
    public companion object {
        /**
         * PEM chain (leaf first) + PKCS#8 PEM key as a `CharArray`, zeroed after import; encrypted keys are not supported in
         * v1. The key is decoded straight from the array (no `String` of it is made) and every decoded block is wiped, on
         * failure too; a `String` the caller read the key into is outside the library's reach.
         */
        public fun fromPem(
            chainPem: String,
            keyPem: CharArray,
            password: CharArray? = null,
        ): InMemory {
            try {
                if (password != null) throw TlsException.Config("encrypted PEM keys are not supported in v1; decrypt before import")
                val chain = Pem.blocks(chainPem, "CERTIFICATE").map { Certificate(it) }
                val keys = Pem.secretBlocks(keyPem, "PRIVATE KEY") // no String of the key text is ever made
                try {
                    if (keys.size != 1) throw TlsException.Config("expected exactly one PKCS#8 PRIVATE KEY block")
                    return fromDer(chain.map { it.encoded }, keys[0])
                } finally {
                    keys.forEach { it.fill(0) }
                }
            } finally {
                keyPem.fill('\u0000')
                password?.fill('\u0000')
            }
        }

        /** DER chain (leaf first) + PKCS#8 DER key; [keyDer] is zeroed after import, the key then lives in OpenSSL only. */
        public fun fromDer(
            chain: List<ByteArray>,
            keyDer: ByteArray,
        ): InMemory {
            try {
                if (chain.isEmpty()) throw TlsException.Config("empty certificate chain")
                KslLoader.ensureLoaded()
                val pkey =
                    try {
                        Ksl.pkeyNew(keyDer)
                    } catch (e: KslException.Internal) {
                        throw TlsException.Config("the private key is not PKCS#8 DER: ${e.message}")
                    }
                try {
                    checkKeyMatches(chain, pkey)
                } catch (t: Throwable) {
                    Ksl.pkeyFree(pkey)
                    throw t
                }
                return InMemory(chain.map { Certificate(it) }, pkey)
            } finally {
                keyDer.fill(0)
            }
        }

        /** Lets `ksl` (OpenSSL) confirm that the key belongs to the leaf; the temporary context is freed immediately. */
        private fun checkKeyMatches(
            chain: List<ByteArray>,
            pkey: Long,
        ) {
            val ctx = Ksl.ctxNew(KslConst.SERVER)
            try {
                Ksl.ctxSetIdentityKey(ctx, chain, pkey)
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

    /**
     * The `-----BEGIN [type]-----` blocks of [pem] decoded straight from the `CharArray`, for key material: no `String` of
     * the text is created, and the decoded arrays are wiped if any block fails. The caller wipes the returned arrays and [pem].
     */
    fun secretBlocks(
        pem: CharArray,
        type: String,
    ): List<ByteArray> {
        val begin = "-----BEGIN $type-----"
        val end = "-----END $type-----"
        val out = ArrayList<ByteArray>()
        try {
            var from = 0
            while (true) {
                val b = pem.find(begin, from)
                if (b < 0) break
                val e = pem.find(end, b)
                if (e < 0) throw TlsException.Config("unterminated PEM block $type")
                out += decodeBase64(pem, b + begin.length, e)
                from = e + end.length
            }
            return out
        } catch (t: Throwable) {
            out.forEach { it.fill(0) }
            throw t
        }
    }

    private fun CharArray.find(
        needle: String,
        from: Int,
    ): Int {
        var i = from
        while (i <= size - needle.length) {
            var j = 0
            while (j < needle.length && this[i + j] == needle[j]) j++
            if (j == needle.length) return i
            i++
        }
        return -1
    }

    private fun sextet(c: Char): Int =
        when (c) {
            in 'A'..'Z' -> c - 'A'
            in 'a'..'z' -> c - 'a' + 26
            in '0'..'9' -> c - '0' + 52
            '+' -> 62
            '/' -> 63
            else -> -1
        }

    /** Base64 of `chars[from, to)`, whitespace skipped, `=` padding only at the end. */
    private fun decodeBase64(
        chars: CharArray,
        from: Int,
        to: Int,
    ): ByteArray {
        var digits = 0
        var pad = 0
        for (i in from until to) {
            val c = chars[i]
            when {
                c == ' ' || c == '\t' || c == '\r' || c == '\n' -> {}

                c == '=' -> {
                    pad++
                }

                pad == 0 && sextet(c) >= 0 -> {
                    digits++
                }

                else -> {
                    throw TlsException.Config("bad Base64 in the PEM block")
                }
            }
        }
        if ((digits + pad) % 4 != 0 || pad > 2 || digits % 4 == 1) throw TlsException.Config("bad Base64 length in the PEM block")
        val out = ByteArray(digits * 3 / 4)
        var acc = 0
        var bits = 0
        var o = 0
        for (i in from until to) {
            val v = sextet(chars[i])
            if (v < 0) continue
            acc = (acc shl 6) or v
            bits += 6
            if (bits >= 8) {
                bits -= 8
                out[o++] = (acc shr bits).toByte()
                acc = acc and ((1 shl bits) - 1)
            }
        }
        return out
    }
}
