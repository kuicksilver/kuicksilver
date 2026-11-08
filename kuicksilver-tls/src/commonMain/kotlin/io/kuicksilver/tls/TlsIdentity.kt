// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(InternalKuicksilverApi::class, ExperimentalAtomicApi::class)

package io.kuicksilver.tls

import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.annotations.InternalKuicksilverApi
import io.kuicksilver.native.Ksl
import io.kuicksilver.native.KslConst
import io.kuicksilver.native.KslException
import io.kuicksilver.native.KslLoader
import kotlin.concurrent.atomics.AtomicInt
import kotlin.concurrent.atomics.AtomicReference
import kotlin.concurrent.atomics.ExperimentalAtomicApi
import kotlin.io.encoding.Base64

/**
 * A certificate chain (leaf first, RFC 9846 section 4.5.1) and the matching private key. Sealed: the kinds are [InMemory] and,
 * since 0.3.0, [Reloadable] (an [InMemory] that can be replaced at run time); identities whose key stays in a keystore or HSM
 * may be added later, so do not match on it exhaustively.
 */
public sealed interface TlsIdentity {
    /** The certificates sent to the peer, leaf first; the leaf's public key matches the private key. */
    public val chain: List<Certificate>

    /**
     * v1: the key is parsed once into OpenSSL (a native `ksl_pkey`) and checked against `chain[0]` on creation; Kotlin keeps
     * only the handle, never the key bytes (threat model 1, 3.7). Every context built from this identity holds its own
     * reference, so [close] frees the key once those contexts are gone too; closing is safe while connections still run.
     * Building a context after [close] throws [IllegalStateException].
     *
     * Since 0.3.0 the handshakes of one server configuration share one context built from this identity (an OpenSSL
     * `SSL_CTX`: built once instead of per connection); the identity keeps it, and at most seven more of other server
     * configurations, until [close]. A context in use stays until its last connection is gone. An identity that is never closed
     * keeps those contexts (up to eight `SSL_CTX`s) and the [TlsConfig]s they were built for for the life of the process, as it
     * keeps its key.
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
            if (!tryAcquire()) throw IllegalStateException("identity closed")
            try {
                return block(pkey)
            } finally {
                release()
            }
        }

        /**
         * Takes a use of the native key unless the last reference is already gone (then false, and nothing to release).
         * A true result is paired with one [release]; meanwhile [keyHandle] stays valid.
         */
        internal fun tryAcquire(): Boolean {
            while (true) {
                val r = refs.load()
                if (r == 0) return false
                if (refs.compareAndSet(r, r + 1)) return true
            }
        }

        /** The native key handle; valid only between a successful [tryAcquire] and its [release]. */
        internal val keyHandle: Long get() = pkey

        internal fun release() {
            if (refs.addAndFetch(-1) == 0) Ksl.pkeyFree(pkey)
        }

        /** True once [close] ran (the native key may still serve contexts built before). */
        internal val isClosed: Boolean get() = closed.load() != 0

        /** The server contexts built from this identity, shared by the handshakes of each configuration (`KslContext.acquire`). */
        internal val serverContexts = SharedServerContexts()

        /** Releases the identity; the server contexts built from it go with the last connection that uses each. */
        override fun close() {
            if (closed.compareAndSet(0, 1)) {
                serverContexts.close() // each goes with its last connection
                release()
            }
        }
    }

    /**
     * A server (or client) identity that can be replaced while the process runs: certificate rotation without a restart.
     * Made by [TlsIdentity.reloadable]; use it as `TlsConfig.identity` (or a connector's identity) like an [InMemory].
     *
     * **One identity per handshake.** Every TLS handshake (TCP connections and QUIC sessions alike) takes the [current]
     * snapshot when it starts and runs on an OpenSSL context built from that snapshot's chain and key, so a handshake presents
     * a consistent pair (RFC 9846 section 4.5.1, Certificate, and 4.5.2, CertificateVerify, are made from the same identity)
     * whatever [reload] does meanwhile. The handshakes of one server configuration share one context per snapshot: the first
     * handshake after a [reload] builds one from the new identity, and the old one is freed when its last connection is gone.
     * Handshakes in progress and established connections keep the identity they started with; [reload] affects only
     * handshakes that start after it returns.
     *
     * **Ownership.** The reloadable identity owns the [InMemory] it was made with and each one [reload] accepted: [reload]
     * closes the identity it replaces, and [close] closes [current]. A closed [InMemory] frees its native key only when the
     * last context built from it is gone, so replacing an identity never pulls the key out from under a running connection.
     * Do not close [current] yourself. An identity [reload] refused stays the caller's to close.
     *
     * **Resumption and 0-RTT.** Every server binds its session tickets to the leaf certificate they were issued under (RFC
     * 9846 section 4.7.1): after a [reload] to another certificate, a ticket from before it resumes nothing, the client runs
     * a full handshake and sees the new certificate, and 0-RTT of such a ticket is refused (the replay register is not
     * reset). Independently of reloads, a chain of renewed tickets ends 7 days after the full handshake that authenticated
     * it, and at the leaf's notAfter. A resumed connection presents no certificate (RFC 9846 section 2.2): it keeps the
     * identity of the session it resumes, which is the current one. After a key compromise, a reload is enough to stop new
     * handshakes and resumptions with the old key; connections already established run on until they close.
     *
     * **Checks.** [reload] refuses a closed identity, one whose leaf certificate has expired, and one whose leaf is not valid
     * yet (notBefore more than 5 minutes ahead of the clock: a certificate staged for later is never served early); the
     * pairing of key and chain was already checked when the [InMemory] was built ([fromPem], [fromDer]), so a mismatched
     * pair never gets here. `next` must not be closed by anyone else: an identity closed during the reload is refused.
     */
    @ExperimentalKuicksilverApi
    public class Reloadable internal constructor(
        initial: InMemory,
        private val now: () -> Long = ::nowSeconds,
    ) : TlsIdentity,
        AutoCloseable {
        init {
            validate(initial)
        }

        private val ref = AtomicReference(initial)
        private val closed = AtomicInt(0)

        /**
         * The identity new handshakes use now, a snapshot: a later [reload] does not change the value already read. Owned by
         * this object; do not close it.
         */
        public val current: InMemory get() = ref.load()

        /** The chain of [current]. */
        override val chain: List<Certificate> get() = ref.load().chain

        /**
         * Makes [next] the identity of every handshake that starts from now on, and closes the one it replaces (connections
         * built from that one keep working). Reloading [current] itself does nothing.
         *
         * @throws TlsException.Config when [next] is closed (also when closed during the reload), its leaf certificate
         *   expired or is not valid yet, or its validity cannot be read; [current] stays and [next] stays the caller's.
         * @throws IllegalStateException when this identity was closed; [next] stays the caller's.
         */
        public fun reload(next: InMemory) {
            if (closed.load() != 0) throw IllegalStateException("identity closed")
            validate(next)
            val old = ref.exchange(next)
            if (old === next) return
            afterExchangeForTest?.invoke()
            if (next.isClosed) {
                // closed by someone else meanwhile (it is ours now): never leave a closed identity current
                if (ref.compareAndSet(next, old)) {
                    // a close() that ran meanwhile closed `next`, then current; `old` is current again and must be closed too
                    if (closed.load() != 0) old.close()
                    throw TlsException.Config("the new identity was closed during reload; the old one stays")
                }
                old.close() // a concurrent reload replaced `next` already, so `old` is no longer served
                throw TlsException.Config("the new identity was closed during reload")
            }
            old.close()
            // a close() that ran meanwhile may have closed `old` instead of `next`: close `next` too (close is idempotent)
            if (closed.load() != 0) next.close()
        }

        /** Closes [current]: handshakes that start afterwards fail with [IllegalStateException]; running connections are not affected. */
        override fun close() {
            if (closed.compareAndSet(0, 1)) ref.load().close()
        }

        /**
         * Runs [block] with one snapshot of the identity and its native key, held for the duration: chain and key always
         * come from the same [InMemory]. A snapshot replaced (and closed) between the load and the use is retried with the
         * new [current].
         */
        internal fun <T> withCurrentKey(block: (InMemory, Long) -> T): T {
            while (true) {
                if (closed.load() != 0) throw IllegalStateException("identity closed")
                val cur = ref.load()
                beforeAcquireForTest?.invoke(cur)
                if (cur.tryAcquire()) {
                    try {
                        return block(cur, cur.keyHandle)
                    } finally {
                        cur.release()
                    }
                }
                // closed while still current: closed from outside (or by close() of this object); nothing newer to retry with
                if (ref.load() === cur) throw IllegalStateException("identity closed")
            }
        }

        /**
         * Runs [block] with the [current] snapshot until it gives a result: null means that snapshot's key was gone (replaced and
         * closed between the load and the use), and the new current one is tried, as [withCurrentKey] does.
         *
         * @throws IllegalStateException when this identity is closed.
         */
        internal fun <T : Any> withCurrentSnapshot(block: (InMemory) -> T?): T {
            while (true) {
                if (closed.load() != 0) throw IllegalStateException("identity closed")
                val cur = ref.load()
                beforeAcquireForTest?.invoke(cur)
                block(cur)?.let { return it }
                // closed while still current: closed from outside (or by close() of this object); nothing newer to retry with
                if (ref.load() === cur) throw IllegalStateException("identity closed")
            }
        }

        /** Test seam: runs in [reload] right after the swap, before the new identity is checked again. */
        internal var afterExchangeForTest: (() -> Unit)? = null

        /** Test seam: runs in [withCurrentKey] between loading the snapshot and taking its key. */
        internal var beforeAcquireForTest: ((InMemory) -> Unit)? = null

        private fun validate(id: InMemory) {
            if (id.isClosed) throw TlsException.Config("the new identity is closed")
            val leaf = id.chain[0]
            val t = now() // read once; the messages carry no time, so a watcher's repeated failure reads the same
            if (leaf.notAfterEpochSeconds < t) {
                throw TlsException.Config("the leaf certificate expired (notAfter ${leaf.notAfterEpochSeconds})")
            }
            if (leaf.notBeforeEpochSeconds > t + NOT_BEFORE_SKEW_SECONDS) {
                throw TlsException.Config("the leaf certificate is not valid yet (notBefore ${leaf.notBeforeEpochSeconds})")
            }
        }

        private companion object {
            /** How far a leaf's notBefore may lie ahead of our clock (a CA's clock running ahead): 5 minutes. */
            const val NOT_BEFORE_SKEW_SECONDS: Long = 300
        }
    }

    /**
     * Factories: [fromPem], [fromDer], and on the JVM `fromKeyStore` and `fromPkcs12`. Each throws [TlsException.Config] on bad
     * input. [reloadable] wraps one for certificate rotation.
     */
    public companion object {
        /**
         * A [Reloadable] identity that starts with [initial] and owns it from now on (see [Reloadable] for ownership,
         * resumption and the checks).
         *
         * @throws TlsException.Config when [initial] is closed or its leaf certificate expired or is not valid yet; [initial]
         *   stays the caller's.
         */
        @ExperimentalKuicksilverApi
        public fun reloadable(initial: InMemory): Reloadable = Reloadable(initial)

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

        /**
         * Lets `ksl` (OpenSSL) confirm that the key belongs to the leaf and that the chain meets security level 2 (RFC 9325
         * section 4.5: keys of at least 112 bits, no SHA-1 or MD5 signature but a self-signed root's own); the temporary
         * context is freed immediately.
         */
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
                val why = e.message.orEmpty()
                throw TlsException.Config(
                    if (why.contains("identity rejected: ")) {
                        "the certificate chain is refused: ${why.substringAfter("identity rejected: ")}"
                    } else {
                        "private key does not match chain[0] or the chain is invalid: $why"
                    },
                )
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
