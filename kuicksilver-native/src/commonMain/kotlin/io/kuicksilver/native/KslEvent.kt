// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.native

import io.kuicksilver.annotations.InternalKuicksilverApi

/** Constants mirroring ksl.h. Values are part of the native ABI and must not change without bumping `KSL_ABI_VERSION`. */
@InternalKuicksilverApi
public object KslConst {
    public const val OK: Int = 0
    public const val WANT_READ: Int = 1
    public const val WANT_VERIFY: Int = 2
    public const val WANT_SNI: Int = 3
    public const val EOF: Int = 4
    public const val ERROR: Int = -1

    public const val CLIENT: Int = 0
    public const val SERVER: Int = 1
    public const val MODE_QUIC: Int = 0
    public const val EKEY_TOKEN: Int = 1
    public const val EKEY_RESET: Int = 2

    /** AES-128 block key for QUIC-LB connection IDs ([Ksl.keyLb], or random via [Ksl.keyRandom]); used with [Ksl.keyEcb16]. */
    public const val EKEY_LB: Int = 3
    public const val MODE_TCP: Int = 1
    public const val VERIFY_NONE: Int = 0
    public const val VERIFY_PAUSE: Int = 1
    public const val VERIFY_OPENSSL: Int = 2
    public const val CLIENT_CERT_NONE: Int = 0
    public const val CLIENT_CERT_OPTIONAL: Int = 1
    public const val CLIENT_CERT_REQUIRED: Int = 2
    public const val TLS1_2: Int = 0x0303
    public const val TLS1_3: Int = 0x0304

    public const val OPT_VERIFY_MODE: Int = 1
    public const val OPT_CLIENT_CERT: Int = 2
    public const val OPT_MIN_VERSION: Int = 3
    public const val OPT_MAX_VERSION: Int = 4
    public const val OPT_NUM_TICKETS: Int = 5
    public const val OPT_KEYLOG: Int = 6
    public const val OPT_SNI_PAUSE: Int = 7
    public const val OPT_GENERIC_ALERTS: Int = 8
    public const val OPT_TICKET_LIFETIME: Int = 9

    /** Server context: QUIC sessions accept 0-RTT (ABI 6, ADR-0015). */
    public const val OPT_EARLY_DATA: Int = 10

    /**
     * Client context, pause mode: the presented chain is not held to the security level before the pause; the caller holds
     * the path its verifier built to it with [Ksl.chainLevel] (ABI 7, T.5b).
     */
    public const val OPT_LEVEL_AFTER_PAUSE: Int = 11

    /**
     * Client context: `REVOCATION_*`, the stapled OCSP response asked for and checked where ksl's own verifier runs (ABI 7,
     * additive; RFC 9325 section 7.5). [E_NOT_SUPPORTED] for anything but off in a build without OpenSSL's ocsp module.
     */
    public const val OPT_REVOCATION: Int = 12
    public const val REVOCATION_OFF: Int = 0
    public const val REVOCATION_STAPLED_IF_PRESENT: Int = 1
    public const val REVOCATION_REQUIRE_STAPLED: Int = 2

    /**
     * Server context: `ALPN_POLICY_*` for TLS-over-TCP sessions (ABI 7, additive; RFC 7301 section 3.2), applied at every
     * ClientHello under the context in effect (the SNI override once applied) and again when the handshake completes. A present
     * ALPN extension that is malformed is `decode_error` (50) in both modes, whatever the policy.
     */
    public const val OPT_ALPN_POLICY: Int = 13

    /**
     * Both roles: 1 (the default) offers and accepts TLS certificate compression (RFC 8879; brotli, then zlib) and compresses
     * a server's chain at [Ksl.ctxFreeze], 0 turns it off (ABI 7, additive).
     */
    public const val OPT_CERT_COMPRESSION: Int = 14

    /** A ClientHello without ALPN completes without it: the default. */
    public const val ALPN_POLICY_OPEN: Int = 0

    /** A ClientHello without the ALPN extension gets `no_application_protocol` (120). */
    public const val ALPN_POLICY_REQUIRED: Int = 1

    /** Nothing is served over TCP: every ClientHello gets `no_application_protocol` (120). */
    public const val ALPN_POLICY_REFUSE: Int = 2

    /**
     * Client context: 1 = a session without an ECH configuration sends a GREASE `encrypted_client_hello` extension (RFC 9849
     * section 6.2.1; ABI 7, additive). Default 0.
     */
    public const val OPT_ECH_GREASE: Int = 15

    /** 1 byte, `ECH_*`: the session's Encrypted Client Hello outcome, also after a failed handshake (ABI 7, additive). */
    public const val GET_ECH_STATUS: Int = 15

    /**
     * Client: the ECHConfigList of the server's retry configurations after an authenticated rejection ([ECH_REJECTED]), only
     * its usable ECHConfigs; 0 bytes otherwise, GREASE included (RFC 9849 sections 6.1.6 and 6.2.1; ABI 7, additive).
     */
    public const val GET_ECH_RETRY_CONFIGS: Int = 16

    /**
     * Client: the name the server certificate is checked against now: the verify name, or after an ECH rejection the
     * ECHConfig's public_name (RFC 9849 section 6.1.7; ABI 7, additive). The paused path verifies this name.
     */
    public const val GET_VERIFY_NAME: Int = 17

    /** Client, before the handshake, once: an ECHConfigList (RFC 9849 section 4), binary (ABI 7, additive). */
    public const val SET_ECH_CONFIG_LIST: Int = 15

    /** [GET_ECH_STATUS]: no ECH (none configured and no GREASE; a server saw none). */
    public const val ECH_NONE: Int = 0

    /** [GET_ECH_STATUS]: the server accepted ECH. */
    public const val ECH_ACCEPTED: Int = 1

    /** [GET_ECH_STATUS]: the client sent GREASE ECH. */
    public const val ECH_GREASE: Int = 2

    /**
     * [GET_ECH_STATUS]: client: the server rejected ECH and the outer handshake was authenticated for the public_name; the
     * client ended it with `ech_required` (121). Server: the ClientHello's ECH was not decrypted.
     */
    public const val ECH_REJECTED: Int = 3

    /** [GET_ECH_STATUS]: client: offered, and neither accepted nor rejected with an authenticated outer handshake. */
    public const val ECH_OFFERED: Int = 4

    /** [Ksl.ocspCheck] results (`KSL_OCSP_*`). */
    public const val OCSP_GOOD: Int = 0
    public const val OCSP_REVOKED: Int = 1
    public const val OCSP_UNKNOWN: Int = 2
    public const val OCSP_INVALID: Int = 3
    public const val OCSP_MISMATCH: Int = 4
    public const val OCSP_STALE: Int = 5

    public const val GET_ALPN: Int = 1
    public const val GET_VERSION: Int = 2
    public const val GET_CHANNEL_BINDING: Int = 4
    public const val GET_KEYLOG: Int = 5
    public const val GET_SESSION_REUSED: Int = 6
    public const val GET_EMS: Int = 7
    public const val GET_QUIC_VERSION: Int = 8

    /** 1 byte: 0 not attempted, 1 rejected, 2 accepted. */
    public const val GET_EARLY_DATA: Int = 9

    /** 16 bytes: per encryption level 0..3, 4 bytes big-endian, CRYPTO bytes provided and not yet read by TLS (additive in ABI 6). */
    public const val GET_QUIC_PENDING: Int = 10

    /**
     * TCP, 1 byte: 1 once the peer attempted a TLS 1.2 renegotiation on the established session, which OpenSSL refused with a
     * no_renegotiation warning (RFC 9113 section 9.2.1; additive in ABI 7). The read that refused it answers 0 bytes.
     */
    public const val GET_RENEGOTIATION: Int = 11

    /**
     * Client, 9 bytes: the `OCSP_*` of the stapled response the handshake accepted ([OCSP_GOOD] or [OCSP_UNKNOWN]), 0xff when
     * none was checked, then the epoch second (8 bytes big-endian) until which it is fresh (additive in ABI 7).
     */
    public const val GET_OCSP_STATUS: Int = 12

    /**
     * 2 bytes big-endian: the IANA code point of the key-exchange group the handshake used, once the ServerHello is sent or read;
     * 0 bytes before, and for a resumption without key exchange (additive in ABI 7; RFC 9846 section 4.3.7).
     */
    public const val GET_GROUP: Int = 13

    /**
     * 2 bytes big-endian: the algorithm (1 zlib, 2 brotli) of the CompressedCertificate the peer sent its certificate in (RFC
     * 8879), 0 for a plain Certificate or none (additive in ABI 7).
     */
    public const val GET_CERT_COMPRESSION: Int = 14

    /**
     * 1 byte, the same for every session: the algorithms this OpenSSL compresses certificates with, bit 0 zlib, bit 1 brotli
     * (RFC 8879; the bundled OpenSSL of Android and iOS: zlib only, ADR-0025). Additive in ABI 7.
     */
    public const val GET_CERT_COMPRESSORS: Int = 18
    public const val SET_SNI: Int = 1
    public const val SET_VERIFY_NAME: Int = 2
    public const val SET_QUIC_VERSION: Int = 3

    /** Server: 1..64 bytes bound into issued tickets and compared on resumption. */
    public const val SET_EARLY_CONTEXT: Int = 4

    /** 1 byte: client requests 0-RTT; server admits early data for this hello. */
    public const val SET_EARLY_DATA: Int = 5

    /** Server, before the first drive: the DER OCSP response stapled when it is for the leaf sent and fresh (additive in ABI 7). */
    public const val SET_OCSP_RESPONSE: Int = 6

    public const val CHAIN_PRESENTED: Int = 0
    public const val CHAIN_VALIDATED: Int = 1

    public const val AEAD_AES_128_GCM: Int = 1
    public const val AEAD_AES_256_GCM: Int = 2
    public const val AEAD_CHACHA20_POLY1305: Int = 3
    public const val HASH_SHA256: Int = 1
    public const val HASH_SHA384: Int = 2
    public const val SIG_ECDSA_P256: Int = 1
    public const val SIG_ED25519: Int = 2
    public const val DIR_READ: Int = 0
    public const val DIR_WRITE: Int = 1

    public const val LEVEL_INITIAL: Int = 0
    public const val LEVEL_EARLY: Int = 1
    public const val LEVEL_HANDSHAKE: Int = 2
    public const val LEVEL_APPLICATION: Int = 3
    public const val EV_CRYPTO_SEND: Int = 1
    public const val EV_KEY: Int = 2
    public const val EV_TRANSPORT_PARAMS: Int = 3
    public const val EV_HANDSHAKE_DONE: Int = 4

    public const val E_NO_VERIFY_NAME: Int = 0xff0001
    public const val E_SERVER_PAUSE_FORBIDDEN: Int = 0xff0002
    public const val E_NOT_PAUSED: Int = 0xff0003
    public const val E_CTX_FROZEN: Int = 0xff0004
    public const val E_BAD_ARG: Int = 0xff0005
    public const val E_HOSTNAME_MISMATCH: Int = 0xff0006
    public const val E_EMS_REQUIRED: Int = 0xff0007
    public const val E_NOT_SUPPORTED: Int = 0xff0008

    // ksl_udp
    public const val UDP_ECN: Int = 1
    public const val UDP_GSO: Int = 2
    public const val UDP_GRO: Int = 4
    public const val UDP_DF: Int = 8
    public const val UDP_REUSEPORT: Int = 16

    /** `KSL_UDP_PKTINFO` (ABI 7): a wildcard socket reports each datagram's destination address and sends from a named source. */
    public const val UDP_PKTINFO: Int = 32
    public const val UDP_ADDR_LEN: Int = 20

    /** `Ksl.dnsQuery` answer kind: a whole DNS message follows (`KSL_DNS_MESSAGE`). */
    public const val DNS_MESSAGE: Int = 1

    /** `Ksl.dnsQuery` answer kind: `ttl:4 | owner length:1 | owner | rdata length:2 | rdata` records follow (`KSL_DNS_RECORDS`). */
    public const val DNS_RECORDS: Int = 2

    /** `Ksl.resolve` family: IPv4 (`KSL_ADDR_V4`). */
    public const val ADDR_V4: Int = 4

    /** `Ksl.resolve` family: IPv6 (`KSL_ADDR_V6`). */
    public const val ADDR_V6: Int = 6

    /** `Ksl.resolve` entry length: `family:1 | address:16 | scope id:4` (`KSL_RESOLVE_ENTRY_LEN`). */
    public const val RESOLVE_ENTRY_LEN: Int = 21

    /** `Ksl.addrInfo` flag: a deprecated address, RFC 4862 (`KSL_ADDR_DEPRECATED`). */
    public const val ADDR_DEPRECATED: Int = 1

    /** `Ksl.addrInfo` flag: the address's interface is an encapsulating tunnel (`KSL_ADDR_TUNNEL`). */
    public const val ADDR_TUNNEL: Int = 2

    // ksl_live_objects indices (KSL_LIVE_*)
    public const val LIVE_CTX: Int = 0
    public const val LIVE_SSL: Int = 1
    public const val LIVE_KEY: Int = 2
    public const val LIVE_PKEY: Int = 3
    public const val LIVE_SESSION: Int = 4
    public const val LIVE_UDP: Int = 5
    public const val LIVE_WAKE: Int = 6

    /** ECH key sets from `ksl_ech_keys_new` not yet freed (`KSL_LIVE_ECH_KEYS`, ABI 7, additive). */
    public const val LIVE_ECH_KEYS: Int = 7
    public const val LIVE_COUNT: Int = 8
    public const val UDP_GET_FD: Int = 1
    public const val UDP_GET_CAPS: Int = 2
    public const val UDP_GET_LOCAL: Int = 3
    public const val UDP_GET_ERROR: Int = 4
    public const val UDP_GET_STATS: Int = 5

    /** `ksl_udp_get`: the waits a receive began for a datagram (4 bytes BE), counted before each one on every platform (ABI 7). */
    public const val UDP_GET_WAITS: Int = 6
    public const val UDP_MAX_BATCH: Int = 64

    /** The largest ICMP Packet Too Big `ksl_icmp_ptb_build` writes (`KSL_ICMP_PTB_MAX`, ABI 7, additive). */
    public const val ICMP_PTB_MAX: Int = 1240

    /** Bytes of the quoted datagram a Packet Too Big keeps (`KSL_UDP_PTB_QUOTE`, ABI 7). */
    public const val UDP_PTB_QUOTE: Int = 64

    /** An ICMP port unreachable (`KSL_UNREACH_PORT`, `ksl_udp_take_unreachable`). */
    public const val UNREACH_PORT: Int = 1

    /** An ICMP host (ICMPv6 address) unreachable (`KSL_UNREACH_HOST`, `ksl_udp_take_unreachable`). */
    public const val UNREACH_HOST: Int = 2
    public const val E_TRUNCATED: Int = 0xff0009
    public const val E_TOO_LATE: Int = 0xff000a

    /** quicProvide: a level TLS no longer reads (RFC 9001 section 4.1.3), or more than 256 KiB unread at one level. */
    public const val E_CRYPTO_LEVEL: Int = 0xff000b

    /** udpOpen: the bind was refused (a port in use, an address not on this host). */
    public const val E_BIND: Int = 0xff000c

    /** `ksl_udp_open`, `ksl_udp_sender`: an allocation failed (additive in ABI 7; `ksl_udp_open` answered [E_BAD_ARG] before). */
    public const val E_NO_MEMORY: Int = 0xff000d

    /** Event wire layout produced by the bindings: 6 x int32 header then the payload. */
    public const val EVENT_HEADER_BYTES: Int = 24
}

/** A mutable event slot filled by [Ksl.quicNextEvent]; reused by the caller to avoid allocation. */
@InternalKuicksilverApi
public class KslEvent {
    public var type: Int = 0
    public var level: Int = 0
    public var direction: Int = 0
    public var aead: Int = 0

    /** Key handle for [KslConst.EV_KEY]; ownership moves to the caller (free with [Ksl.keyFree]). */
    public var key: Long = 0

    /** Payload for CRYPTO_SEND and TRANSPORT_PARAMS; a fresh copy per event. */
    public var payload: ByteArray = EMPTY

    /** Binding-private scratch (the JVM keeps its direct event buffer here, one per session, never shared). */
    public var scratch: Any? = null

    private companion object {
        val EMPTY = ByteArray(0)
    }
}

/** ClientHello details available during the SNI pause. */
@InternalKuicksilverApi
public class KslClientHello(
    public val serverName: String?,
    public val alpnWire: ByteArray,
    public val signatureAlgorithmsWire: ByteArray,
)

/** Error snapshot read from the native object right after a failing call. */
@InternalKuicksilverApi
public class KslError(
    public val packed: Int,
    public val alert: Int,
    public val message: String,
)
