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

    public const val SET_SNI: Int = 1
    public const val SET_VERIFY_NAME: Int = 2
    public const val SET_QUIC_VERSION: Int = 3

    /** Server: 1..64 bytes bound into issued tickets and compared on resumption. */
    public const val SET_EARLY_CONTEXT: Int = 4

    /** 1 byte: client requests 0-RTT; server admits early data for this hello. */
    public const val SET_EARLY_DATA: Int = 5

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
    public const val UDP_ADDR_LEN: Int = 20

    // ksl_live_objects indices (KSL_LIVE_*)
    public const val LIVE_CTX: Int = 0
    public const val LIVE_SSL: Int = 1
    public const val LIVE_KEY: Int = 2
    public const val LIVE_PKEY: Int = 3
    public const val LIVE_SESSION: Int = 4
    public const val LIVE_UDP: Int = 5
    public const val LIVE_WAKE: Int = 6
    public const val LIVE_COUNT: Int = 7
    public const val UDP_GET_FD: Int = 1
    public const val UDP_GET_CAPS: Int = 2
    public const val UDP_GET_LOCAL: Int = 3
    public const val UDP_GET_ERROR: Int = 4
    public const val UDP_GET_STATS: Int = 5
    public const val UDP_MAX_BATCH: Int = 64

    /** Bytes of the quoted datagram a Packet Too Big keeps (`KSL_UDP_PTB_QUOTE`, ABI 7). */
    public const val UDP_PTB_QUOTE: Int = 64
    public const val E_TRUNCATED: Int = 0xff0009
    public const val E_TOO_LATE: Int = 0xff000a

    /** quicProvide: a level TLS no longer reads (RFC 9001 section 4.1.3), or more than 256 KiB unread at one level. */
    public const val E_CRYPTO_LEVEL: Int = 0xff000b

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
