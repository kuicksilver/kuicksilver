// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.tls

import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.annotations.InternalKuicksilverApi
import io.kuicksilver.native.Ksl
import io.kuicksilver.native.KslConst

/**
 * The key-exchange groups of a TLS configuration (RFC 9846 sections 4.3.7 and 4.3.8), most preferred first, and the groups a client
 * sends a key share for in its first ClientHello. Every invalid value throws [TlsException.Config] here; a group the OpenSSL in
 * use does not provide throws it when the configuration is built ([TlsConfig.Builder.build]).
 *
 * - A client offers [groups] in this order in `supported_groups` and key shares for [keyShares], in the same order. A server it
 *   shares no group with ends the handshake with `handshake_failure` (40; over QUIC, CRYPTO_ERROR 0x0128); one that takes a
 *   group the client sent no share for answers with a HelloRetryRequest (RFC 9846 section 4.2.1), which costs a round trip and
 *   rejects 0-RTT (RFC 9001 section 4.6.2).
 * - A server picks by its own order: among the groups the client sent a key share for, the first of [groups]; with none of them,
 *   a HelloRetryRequest for the first of [groups] the client supports; with no group in common, `handshake_failure`. It ignores
 *   [keyShares]. An `sniSelector` answer may bring its own ([ServerTlsOverride.keyExchangeGroups]).
 * - TLS 1.2 ([TlsVersions.Tls12And13], TCP) takes the elliptic curves of [groups] ([X25519], [X448], [SECP256R1], [SECP384R1],
 *   [SECP521R1]) in the same order; the hybrids are TLS 1.3 only. There the list also names the curves of the peer's ECDSA
 *   certificates an endpoint accepts (RFC 8422 section 5.1): a client without [SECP256R1] refuses a TLS 1.2 server's P-256
 *   certificate with `handshake_failure`, and a server without it refuses a P-256 client certificate with `illegal_parameter`
 *   (47; OpenSSL holds client certificates to the server's own list). TLS 1.3 negotiates signatures apart.
 *
 * A session ticket does not depend on the group: a resumption runs a fresh key exchange (`psk_dhe_ke`) under the groups in effect.
 *
 * @param groups the group names, most preferred first: the constants of the companion, in any case; never empty, each at most once
 *   (RFC 9846 section 4.3.7: "The "named_group_list" MUST NOT contain any duplicate entries").
 * @param keyShares the groups of [groups] a client sends key shares for, 1 to 4 of them (each share is sent whole: an
 *   [X25519MLKEM768] share alone is 1,216 bytes). Null: the first group, and the first later one of the other kind (hybrid or
 *   classical) when the first is of one, so a client offers a post-quantum and a classical share as BoringSSL does. Servers
 *   refuse a configuration that sets it.
 */
@ExperimentalKuicksilverApi
public class KeyExchangeGroups(
    groups: List<String>,
    keyShares: Set<String>? = null,
) {
    /** The groups in their canonical spelling (the companion's constants), most preferred first. */
    public val groups: List<String>

    /** The groups a client sends a key share for in its first ClientHello, in the order of [groups]. */
    public val keyShares: List<String>

    /** Whether [keyShares] was given (a server refuses that), not derived from [groups]. */
    internal val sharesGiven: Boolean = keyShares != null

    init {
        if (groups.isEmpty()) throw TlsException.Config("at least one key-exchange group")
        val canonical = groups.map { canonicalGroup(it) }
        canonical.groupingBy { it }.eachCount().filterValues { it > 1 }.keys.firstOrNull()?.let {
            throw TlsException.Config("key-exchange group $it is listed twice (RFC 9846 section 4.3.7)")
        }
        this.groups = canonical
        val shares =
            if (keyShares == null) {
                val first = canonical.first()
                listOfNotNull(first, canonical.drop(1).firstOrNull { (it in HYBRIDS) != (first in HYBRIDS) })
            } else {
                if (keyShares.isEmpty()) throw TlsException.Config("keyShares names at least one group")
                val wanted = keyShares.map { canonicalGroup(it) }.toSet()
                wanted.firstOrNull { it !in canonical }?.let {
                    // RFC 9846 section 4.3.8: "Clients MUST NOT offer any KeyShareEntry values for groups not listed in the
                    // client's "supported_groups" extension"
                    throw TlsException.Config("key share for $it, which is not in the groups")
                }
                canonical.filter { it in wanted }
            }
        if (shares.size > MAX_KEY_SHARES) throw TlsException.Config("at most $MAX_KEY_SHARES key shares (${shares.size} given)")
        this.keyShares = shares
    }

    /** Whether TLS 1.2 has a group in it: an elliptic curve. */
    internal val hasTls12Group: Boolean get() = groups.any { it !in HYBRIDS }

    /** The list for `ksl_ctx_set_groups`: a client's key shares marked `*`. */
    internal fun kslList(role: TlsRole): String = groups.joinToString(":") { if (role == TlsRole.Client && it in keyShares) "*$it" else it }

    /**
     * Equal for the same groups and key shares, given or derived alike: a list with given key shares is a client's setting a server
     * refuses, so it never equals one without, though the shares match (an sniSelector answer is cached by its list).
     */
    override fun equals(other: Any?): Boolean =
        other is KeyExchangeGroups && other.groups == groups && other.keyShares == keyShares && other.sharesGiven == sharesGiven

    /** Consistent with [equals]: the groups, the key shares and whether the shares were given. */
    override fun hashCode(): Int = (groups.hashCode() * 31 + keyShares.hashCode()) * 31 + sharesGiven.hashCode()

    /** The groups in order and the key shares, for logs and error messages. */
    override fun toString(): String = "KeyExchangeGroups($groups, keyShares=$keyShares)"

    /** The group names this stack supports (RFC 9846 section 4.3.7 and the IANA TLS Supported Groups registry) and the default. */
    public companion object {
        /** X25519 with ML-KEM-768 (0x11EC), the post-quantum hybrid OpenSSL 3.5 and BoringSSL put first by default. */
        public const val X25519MLKEM768: String = "X25519MLKEM768"

        /** P-256 with ML-KEM-768 (0x11EB). */
        public const val SECP256R1MLKEM768: String = "SecP256r1MLKEM768"

        /** P-384 with ML-KEM-1024 (0x11ED). */
        public const val SECP384R1MLKEM1024: String = "SecP384r1MLKEM1024"

        /** X25519 (0x001D, RFC 7748), which RFC 9325 section 4.2.1 says implementations SHOULD support. */
        public const val X25519: String = "x25519"

        /** X448 (0x001E, RFC 7748). */
        public const val X448: String = "x448"

        /** NIST P-256 (0x0017), mandatory to implement in TLS 1.3 (RFC 9846 section 9.1). */
        public const val SECP256R1: String = "secp256r1"

        /** NIST P-384 (0x0018). */
        public const val SECP384R1: String = "secp384r1"

        /** NIST P-521 (0x0019). */
        public const val SECP521R1: String = "secp521r1"

        /**
         * X25519MLKEM768, X25519, P-256, X448, P-384, P-521, a client sending key shares for the first two: post-quantum with
         * any server that has the hybrid, X25519 in one flight with one that does not.
         */
        public val Default: KeyExchangeGroups = KeyExchangeGroups(listOf(X25519MLKEM768, X25519, SECP256R1, X448, SECP384R1, SECP521R1))

        /** The name of the group with IANA code point [codePoint], null for one this stack does not know. */
        internal fun nameOf(codePoint: Int): String? = CODE_POINTS.entries.firstOrNull { it.value == codePoint }?.key
    }
}

/** The key shares a client sends at most (OpenSSL's `OPENSSL_CLIENT_MAX_KEY_SHARES`). */
private const val MAX_KEY_SHARES = 4

private val CODE_POINTS: Map<String, Int> =
    linkedMapOf(
        KeyExchangeGroups.X25519MLKEM768 to 0x11EC,
        KeyExchangeGroups.SECP256R1MLKEM768 to 0x11EB,
        KeyExchangeGroups.SECP384R1MLKEM1024 to 0x11ED,
        KeyExchangeGroups.X25519 to 0x001D,
        KeyExchangeGroups.X448 to 0x001E,
        KeyExchangeGroups.SECP256R1 to 0x0017,
        KeyExchangeGroups.SECP384R1 to 0x0018,
        KeyExchangeGroups.SECP521R1 to 0x0019,
    )

private val HYBRIDS = setOf(KeyExchangeGroups.X25519MLKEM768, KeyExchangeGroups.SECP256R1MLKEM768, KeyExchangeGroups.SECP384R1MLKEM1024)

private fun canonicalGroup(name: String): String =
    CODE_POINTS.keys.firstOrNull { it.equals(name, ignoreCase = true) }
        ?: throw TlsException.Config(
            "unknown key-exchange group \"$name\" (supported: ${CODE_POINTS.keys.joinToString(", ")})",
        )

/** The [KeyExchangeGroups] name of the group a `ksl` session's handshake used (`KSL_GET_GROUP`), null for none or one unknown here. */
@OptIn(ExperimentalKuicksilverApi::class, InternalKuicksilverApi::class)
internal fun groupOf(ssl: Long): String? {
    val b = Ksl.sslGet(ssl, KslConst.GET_GROUP)
    return if (b.size == 2) KeyExchangeGroups.nameOf(((b[0].toInt() and 0xff) shl 8) or (b[1].toInt() and 0xff)) else null
}
