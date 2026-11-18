// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(InternalKuicksilverApi::class)

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
 * An ECHConfigList (RFC 9849 section 4): the Encrypted Client Hello configurations of a server, as the `ech` parameter of its
 * HTTPS record carries them (RFC 9848), as a server sends them in `retry_configs`, or as an application got them out of band.
 * [parse] checks the framing and keeps the configurations this OpenSSL can use: one of another version, with an unsupported
 * key encapsulation, cipher suite or mandatory extension, or whose `public_name` is no DNS name or could be read as an IPv4
 * address is ignored, as RFC 9849 sections 4, 4.2 and 6.1.7 require. A list that parses but keeps nothing is not [isUsable]: a
 * client then offers no ECH with it (and sends GREASE ECH instead, [TlsConfig.Builder.echGrease]).
 */
@ExperimentalKuicksilverApi
public class EchConfigList private constructor(
    private val wire: ByteArray,
    private val usable: ByteArray,
) {
    /** The list as given, wire format. */
    public val bytes: ByteArray get() = wire.copyOf()

    /** Whether at least one ECHConfig of the list can be used. */
    public val isUsable: Boolean get() = usable.isNotEmpty()

    /** The usable ECHConfigs as an ECHConfigList, what a client offers. */
    internal val offered: ByteArray get() = usable

    override fun equals(other: Any?): Boolean = other is EchConfigList && wire.contentEquals(other.wire)

    override fun hashCode(): Int = wire.contentHashCode()

    override fun toString(): String = "EchConfigList(${wire.size} bytes${if (isUsable) "" else ", none usable"})"

    /** Parsers. */
    public companion object {
        /** The list in [bytes] (copied); throws [TlsException.Config] when its framing does not parse. */
        public fun parse(bytes: ByteArray): EchConfigList {
            KslLoader.ensureLoaded()
            val copy = bytes.copyOf()
            val kept = Ksl.echConfigListCheck(copy) ?: throw TlsException.Config("ECHConfigList does not parse (RFC 9849 section 4)")
            return EchConfigList(copy, kept)
        }

        /** The list in base64 [text] (the presentation of the HTTPS record `ech` parameter, RFC 9848 section 3). */
        public fun parseBase64(text: String): EchConfigList =
            parse(
                try {
                    Base64.decode(text.trim())
                } catch (e: IllegalArgumentException) {
                    throw TlsException.Config("ECHConfigList is not base64: ${e.message}")
                },
            )
    }
}

/** The Encrypted Client Hello outcome of a handshake (RFC 9849). */
@ExperimentalKuicksilverApi
public enum class EchStatus {
    /** No ECH: a client without a configuration or GREASE; a server that saw none in the ClientHello. */
    None,

    /** The server accepted ECH: the handshake ran on the inner ClientHello, whose server name the path never saw. */
    Accepted,

    /** Client: GREASE ECH was sent (RFC 9849 section 6.2.1); nothing was hidden, nothing was negotiated. */
    Grease,

    /**
     * Client: the server rejected ECH; the outer handshake was authenticated for the configuration's `public_name` and ended
     * with `ech_required` ([TlsException.EchRejected]). Server: the ClientHello's ECH was not decrypted (another key, or
     * GREASE), and the server answered with its retry configurations.
     */
    Rejected,

    /**
     * Client: ECH was offered and neither accepted nor rejected with an authenticated outer handshake: the handshake has not
     * reached the ServerHello, or failed first (a certificate not valid for the `public_name`).
     */
    Offered,
    ;

    internal companion object {
        fun of(code: Int): EchStatus =
            when (code) {
                KslConst.ECH_ACCEPTED -> Accepted
                KslConst.ECH_GREASE -> Grease
                KslConst.ECH_REJECTED -> Rejected
                KslConst.ECH_OFFERED -> Offered
                else -> None
            }
    }
}

/**
 * One Encrypted Client Hello key of a server: the PEM `openssl ech -public_name <name>` writes, a PKCS#8 `PRIVATE KEY`
 * block followed by the `ECHCONFIG` block of its ECHConfigList (publish that block's base64 in the HTTPS record's `ech`
 * parameter). [inRetryConfigs]: whether a server that rejects ECH sends this key's configuration in `retry_configs` (RFC
 * 9849 section 7.1); during a rotation the new key is, the old one is kept only to decrypt clients that still hold it.
 */
@ExperimentalKuicksilverApi
public class EchKey(
    pem: String,
    public val inRetryConfigs: Boolean = true,
) {
    internal val pem: ByteArray = pem.encodeToByteArray()

    override fun toString(): String = "EchKey(inRetryConfigs=$inRetryConfigs)"
}

/**
 * A server's Encrypted Client Hello keys (RFC 9849 section 7.1, shared mode), for [TlsConfig.Builder.echKeys]. The keys are
 * parsed into native memory when given and stay there; at least one is [EchKey.inRetryConfigs], and 1 to 16 are kept at once.
 * [rotate] replaces the set: handshakes that start afterwards decrypt with the new one, also under contexts already built
 * from a configuration that holds this object, and handshakes in progress keep the set they started with. The last set stays
 * in native memory for the life of the process.
 *
 * @throws TlsException.Config when a key does not read, none is for retry_configs, or ECH is not available in this build.
 */
@ExperimentalKuicksilverApi
@OptIn(ExperimentalAtomicApi::class)
public class EchServerKeys(
    keys: List<EchKey>,
) {
    private val current = AtomicReference(Native(parse(keys), 1))

    /**
     * Replaces the whole set (see the class); the old set is freed once no context still uses it. Concurrent rotations are
     * ordered: each one's set gets a version above the set it replaced, so a context never takes an older set for a newer one.
     */
    public fun rotate(keys: List<EchKey>) {
        val handle = parse(keys)
        while (true) {
            val old = current.load()
            val next = Native(handle, old.version + 1)
            beforeSwapForTest?.invoke()
            if (current.compareAndSet(old, next)) {
                old.release()
                return
            }
        }
    }

    /** Test hook: runs in [rotate] between reading the current set and replacing it. */
    internal var beforeSwapForTest: (() -> Unit)? = null

    /** Test hook: runs in [applyTo] before (true) and after (false) the native context takes the set of that version. */
    internal var applyHookForTest: ((Boolean, Int) -> Unit)? = null

    /** The version of the current set: a context applies a set once ([applyTo]). */
    internal val version: Int get() = current.load().version

    /** Gives the current set to the server context [ctx] (which takes its own native reference); returns its version. */
    internal fun applyTo(ctx: Long): Int {
        while (true) {
            val n = current.load()
            if (!n.tryAcquire()) continue // rotated and freed between the load and the acquire: take the newer one
            try {
                applyHookForTest?.invoke(true, n.version)
                Ksl.ctxSetEchKeys(ctx, n.handle)
                applyHookForTest?.invoke(false, n.version)
                return n.version
            } catch (e: KslException.Internal) {
                throw TlsException.Config("ECH keys refused: ${e.message}")
            } finally {
                n.release()
            }
        }
    }

    private class Native(
        val handle: Long,
        val version: Int,
    ) {
        private val refs = AtomicInt(1)

        fun tryAcquire(): Boolean {
            while (true) {
                val r = refs.load()
                if (r <= 0) return false
                if (refs.compareAndSet(r, r + 1)) return true
            }
        }

        fun release() {
            if (refs.addAndFetch(-1) == 0) Ksl.echKeysFree(handle)
        }
    }

    private companion object {
        fun parse(keys: List<EchKey>): Long {
            if (keys.isEmpty() || keys.size > 16) throw TlsException.Config("ECH keys: 1 to 16, not ${keys.size}")
            if (keys.none { it.inRetryConfigs }) {
                throw TlsException.Config("ECH keys: at least one goes into retry_configs (RFC 9849 section 7.1)")
            }
            KslLoader.ensureLoaded()
            var size = 0
            for (k in keys) size += 5 + k.pem.size
            val framed = ByteArray(size)
            var at = 0
            for (k in keys) {
                val l = k.pem.size + 1
                framed[at] = (l ushr 24).toByte()
                framed[at + 1] = (l ushr 16).toByte()
                framed[at + 2] = (l ushr 8).toByte()
                framed[at + 3] = l.toByte()
                framed[at + 4] = if (k.inRetryConfigs) 1 else 0
                k.pem.copyInto(framed, at + 5)
                at += 4 + l
            }
            try {
                return Ksl.echKeysNew(framed)
            } catch (e: KslException.Internal) {
                throw TlsException.Config("ECH keys refused: ${e.message}")
            } finally {
                framed.fill(0)
            }
        }
    }
}

/**
 * The failure of a client handshake that ended with our `ech_required` (121): [TlsException.EchRejected] with the server's
 * retry configurations; null for any other failure.
 */
@OptIn(ExperimentalKuicksilverApi::class)
internal fun echRejection(
    ssl: Long,
    e: KslException.Internal,
): TlsException.EchRejected? {
    if (e.alert and 0x1ff != ECH_REQUIRED) return null // ours (bit 8 is a received one)
    if (EchStatus.of(Ksl.sslGet(ssl, KslConst.GET_ECH_STATUS).firstOrNull()?.toInt() ?: 0) != EchStatus.Rejected) return null
    val retry = Ksl.sslGet(ssl, KslConst.GET_ECH_RETRY_CONFIGS).takeIf { it.isNotEmpty() }?.let(EchConfigList::parse)
    return TlsException.EchRejected(retry)
}

/** The ECH outcome of [ssl]. */
@OptIn(ExperimentalKuicksilverApi::class)
internal fun echStatusOf(ssl: Long): EchStatus = EchStatus.of(Ksl.sslGet(ssl, KslConst.GET_ECH_STATUS).firstOrNull()?.toInt() ?: 0)

/**
 * The name a server certificate is checked against on [ssl] now: [reference], or after an ECH rejection the configuration's
 * `public_name` (RFC 9849 section 6.1.7), which the paused path (platform verifiers, a custom verifier, pins) must check.
 */
internal fun verifyNameOf(
    ssl: Long,
    reference: HostName,
    echOffered: Boolean,
): HostName {
    if (!echOffered) return reference
    val name = Ksl.sslGet(ssl, KslConst.GET_VERIFY_NAME).decodeToString()
    return if (name.isEmpty() || name == reference.value) reference else HostName.normalize(name)
}

private const val ECH_REQUIRED = 121

/** The alert a client sends when it ends a handshake whose ECH the server rejected (RFC 9849 section 11.2). */
internal const val ECH_REQUIRED_ALERT: Int = ECH_REQUIRED

/** Sets [config]'s usable ECH configuration on the client session [ssl]; returns whether it did. */
@OptIn(ExperimentalKuicksilverApi::class)
internal fun offerEch(
    ssl: Long,
    config: TlsConfig,
): Boolean {
    val list = config.echConfigList?.takeIf { it.isUsable } ?: return false
    try {
        Ksl.sslSet(ssl, KslConst.SET_ECH_CONFIG_LIST, list.offered)
    } catch (e: KslException.Internal) {
        throw TlsException.Config("ECH configuration refused: ${e.message}")
    }
    return true
}
