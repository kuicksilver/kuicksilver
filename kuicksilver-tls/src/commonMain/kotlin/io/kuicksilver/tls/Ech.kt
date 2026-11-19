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
 * address is ignored, as RFC 9849 sections 4, 4.2 and 6.1.7 require. A list that parses but keeps nothing is not [isUsable]
 * (in a build without ECH no list is): [TlsConfig.Builder.build] refuses it, so a configuration given explicitly never
 * silently turns into a connection that sends the real name in the clear.
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
 *
 * Prefer the `ByteArray` and `CharArray` constructors: the array given is zeroed at once, the key keeps its own copy only
 * until an [EchServerKeys] (or its [EchServerKeys.rotate]) has read it into native memory, then zeroes that copy too, so
 * such a key is used once (a second use throws [TlsException.Config]). A `String` cannot be wiped: a key made from one
 * keeps that text for its life (and can be used again).
 */
@ExperimentalKuicksilverApi
@OptIn(ExperimentalAtomicApi::class)
public class EchKey private constructor(
    private val text: String?,
    bytes: ByteArray?,
    public val inRetryConfigs: Boolean,
) {
    /** The PEM as text, which stays in memory as long as this key (prefer the `ByteArray` or `CharArray` constructor). */
    public constructor(pem: String, inRetryConfigs: Boolean = true) : this(pem, null, inRetryConfigs)

    /** The PEM as bytes (ASCII); [pem] is zeroed before this returns. */
    public constructor(pem: ByteArray, inRetryConfigs: Boolean = true) : this(null, pem.copyOf().also { pem.fill(0) }, inRetryConfigs)

    /** The PEM as characters (ASCII; no `String` of it is made); [pem] is zeroed before this returns. */
    public constructor(pem: CharArray, inRetryConfigs: Boolean = true) :
        this(null, ByteArray(pem.size) { pem[it].code.toByte() }.also { pem.fill('\u0000') }, inRetryConfigs)

    // the bytes of an array key until they are read (then null: zeroed by the reader)
    private val bytes = AtomicReference(bytes)

    /**
     * The PEM bytes, for the caller to zero after use: a new array for a `String` key; for an array key its copy, taken out
     * of the key (a second take throws).
     */
    internal fun takePem(): ByteArray {
        text?.let { return it.encodeToByteArray() }
        return bytes.exchange(null)
            ?: throw TlsException.Config("ECH key already used: its key material was wiped after it was read; make a new EchKey")
    }

    override fun toString(): String = "EchKey(inRetryConfigs=$inRetryConfigs)"
}

/**
 * A server's Encrypted Client Hello keys (RFC 9849 section 7.1, shared mode), for [TlsConfig.Builder.echKeys]. The keys are
 * parsed into native memory when given and stay there; at least one is [EchKey.inRetryConfigs], and 1 to 16 are kept at once.
 * [rotate] replaces the set: handshakes that start afterwards decrypt with the new one, also under contexts already built
 * from a configuration that holds this object, and handshakes in progress keep the set they started with. The last set stays
 * in native memory for the life of the process.
 *
 * The keys of one set need distinct config_ids (RFC 9849 section 4.1): OpenSSL 4.1 tries only the first key of a
 * config_id and does not go on to the next one (section 7.1 has it go on), so a client of the other key would be rejected.
 * Two keys made apart share one in 1 case of 256; such a set is refused with "two ECH keys share a config_id", and
 * running `openssl ech` again for the newer key gives it another one.
 *
 * @throws TlsException.Config when a key does not read, none is for retry_configs, two keys share a config_id, or ECH is
 *   not available in this build.
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
            val pems = ArrayList<ByteArray>(keys.size)
            var framed: ByteArray? = null
            try {
                for (k in keys) pems += k.takePem()
                var size = 0
                for (p in pems) size += 5 + p.size
                val f = ByteArray(size)
                framed = f
                var at = 0
                for ((i, p) in pems.withIndex()) {
                    val l = p.size + 1
                    f[at] = (l ushr 24).toByte()
                    f[at + 1] = (l ushr 16).toByte()
                    f[at + 2] = (l ushr 8).toByte()
                    f[at + 3] = l.toByte()
                    f[at + 4] = if (keys[i].inRetryConfigs) 1 else 0
                    p.copyInto(f, at + 5)
                    at += 4 + l
                }
                return Ksl.echKeysNew(f)
            } catch (e: KslException.Internal) {
                throw TlsException.Config("ECH keys refused: ${e.message}")
            } finally {
                // the key material lives on in native memory only
                framed?.fill(0)
                pems.forEach { it.fill(0) }
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

/**
 * Whether this build has ECH (the bundled OpenSSL 4; a system OpenSSL has none): `ksl` keeps a well-formed ECHConfigList of
 * RFC 9849's mandatory suite (X25519, HKDF-SHA256, AES-128-GCM) exactly when it can offer ECH.
 */
internal val echInThisBuild: Boolean by lazy {
    KslLoader.ensureLoaded()
    val publicName = "ech.probe.test".encodeToByteArray()
    val body =
        byteArrayOf(7, 0, 0x20, 0, 32) + ByteArray(32) { (9 + it).toByte() } +
            byteArrayOf(0, 4, 0, 1, 0, 1, 0, publicName.size.toByte()) + publicName + byteArrayOf(0, 0)
    val config = byteArrayOf(0xfe.toByte(), 0x0d, (body.size ushr 8).toByte(), body.size.toByte()) + body
    val list = byteArrayOf((config.size ushr 8).toByte(), config.size.toByte()) + config
    Ksl.echConfigListCheck(list)?.isNotEmpty() == true
}

/**
 * Why an explicitly configured ECHConfigList cannot be offered: [hasEch] false, this build has no ECH at all; else the list
 * holds no ECHConfig this OpenSSL can use.
 */
internal fun unusableEchMessage(hasEch: Boolean): String =
    if (!hasEch) {
        "ECH: this build has no Encrypted Client Hello (it needs the bundled OpenSSL 4; a system OpenSSL has none), " +
            "so echConfigList cannot be offered"
    } else {
        "ECH: no ECHConfig of echConfigList is usable (another version, an unsupported key encapsulation, cipher suite or " +
            "mandatory extension, or a public_name that is no DNS name; RFC 9849 sections 4, 4.2, 6.1.7)"
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
