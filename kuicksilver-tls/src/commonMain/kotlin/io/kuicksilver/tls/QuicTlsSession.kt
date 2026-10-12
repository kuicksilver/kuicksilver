// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.tls

import io.kuicksilver.native.PacketBuffer
import kotlinx.io.IOException

/** QUIC encryption levels (RFC 9001 section 2.1), numbered as OpenSSL's protection levels. */
public enum class EncryptionLevel(
    internal val ksl: Int,
) {
    /** Initial packets, protected with keys derived from the client's first Destination Connection ID (RFC 9001 section 5.2). */
    Initial(0),

    /** 0-RTT packets; never used in v1, where 0-RTT is disabled (ADR-0008). */
    EarlyData(1),

    /** Handshake packets, protected with the handshake traffic secrets. */
    Handshake(2),

    /** 1-RTT packets, protected with the application traffic secrets and subject to key updates. */
    Application(3),
    ;

    internal companion object {
        fun of(ksl: Int): EncryptionLevel = entries.first { it.ksl == ksl }
    }
}

/** Which way a set of packet protection keys works. */
public enum class Direction {
    /** Removes protection from packets received from the peer. */
    Read,

    /** Protects packets sent to the peer. */
    Write,
}

/**
 * The AEAD that protects QUIC packets (RFC 9001 section 5.3), fixed by the negotiated cipher suite; Initial packets always
 * use [AES_128_GCM].
 *
 * @property keyLength the key length in bytes.
 */
public enum class Aead(
    internal val ksl: Int,
    public val keyLength: Int,
) {
    /** AEAD_AES_128_GCM, 16-byte key (`TLS_AES_128_GCM_SHA256`). */
    AES_128_GCM(1, 16),

    /** AEAD_AES_256_GCM, 32-byte key (`TLS_AES_256_GCM_SHA384`). */
    AES_256_GCM(2, 32),

    /** AEAD_CHACHA20_POLY1305, 32-byte key (`TLS_CHACHA20_POLY1305_SHA256`). */
    CHACHA20_POLY1305(3, 32),
    ;

    internal companion object {
        fun of(ksl: Int): Aead = entries.first { it.ksl == ksl }
    }
}

/** Result of one [QuicTlsSession.drive] call. */
public sealed interface DriveResult {
    /** The handshake advanced or is complete; collect the output with [QuicTlsSession.nextEvent]. */
    public object Progress : DriveResult

    /** TLS needs more CRYPTO data from the peer; call [QuicTlsSession.provide] when it arrives, then drive again. */
    public object WantRead : DriveResult

    /**
     * The handshake is paused for certificate verification; call [QuicTlsSession.resumeVerify]. [chain] is the presented chain, leaf first.
     *
     * @property chain the certificates the peer presented, leaf first, not yet trusted.
     */
    public class WantVerify(
        public val chain: List<Certificate>,
    ) : DriveResult

    /**
     * Fatal; [alert] is the TLS alert the transport sends as `CONNECTION_CLOSE 0x0100 + alert` (null when none applies).
     * Every later [QuicTlsSession.drive] returns the same result.
     *
     * @property exception what failed, for the application.
     * @property alert the TLS alert code (RFC 8446 section 6), already `handshake_failure` with [TlsConfig.genericAlerts].
     */
    public class Failed(
        public val exception: TlsException,
        public val alert: Int?,
    ) : DriveResult
}

/** Events produced by the TLS layer for the QUIC transport (RFC 9001 section 4). */
public sealed interface TlsEvent {
    /**
     * Handshake bytes for the peer, to send in CRYPTO frames at [level] (RFC 9001 section 4.1.3).
     *
     * @property level the encryption level whose packets carry the data.
     * @property data the bytes, in order; a fresh array the receiver owns.
     */
    public class CryptoData(
        public val level: EncryptionLevel,
        public val data: ByteArray,
    ) : TlsEvent

    /**
     * New packet protection keys became available (RFC 9001 section 4.1.4).
     *
     * @property level the encryption level the keys belong to.
     * @property direction whether they protect sent or received packets.
     * @property protector the keys as a native handle; the receiver owns it and must close it when the level is discarded.
     */
    public class Keys(
        public val level: EncryptionLevel,
        public val direction: Direction,
        public val protector: PacketProtector,
    ) : TlsEvent

    /**
     * The peer's transport parameters and the QUIC version the keys of this connection use from here on (RFC 9368):
     * the server's choice, or the client's [QuicTlsSession.setQuicVersion].
     *
     * @property encoded the body of the peer's `quic_transport_parameters` extension, still encoded (RFC 9000 section 18).
     * @property negotiatedVersion the QUIC version number in use from here on.
     */
    public class PeerTransportParameters(
        public val encoded: ByteArray,
        public val negotiatedVersion: Int,
    ) : TlsEvent

    /**
     * The TLS handshake completed and every trust check, pins included, passed (RFC 9001 section 4.1.1); a failed check
     * yields [DriveResult.Failed] instead.
     */
    public object HandshakeDone : TlsEvent
}

/** Whether 0-RTT data is used (RFC 9001 section 4.6); the enumeration is closed and grows in a later version (ADR-0013). */
public enum class EarlyDataState {
    /** No 0-RTT: never sent, and received 0-RTT packets are dropped. The only state in v1 (ADR-0008). */
    Disabled,
}

/**
 * The TLS handshake of one QUIC connection, driven by the transport without any I/O of its own (RFC 9001 section 4).
 *
 * A call in the wrong state throws [IllegalStateException]; an error reported by TLS itself throws [TlsException] (most
 * failures arrive as [DriveResult.Failed] instead). The native layer's exceptions never escape.
 */
public interface QuicTlsSession : AutoCloseable {
    /**
     * Sets the local transport parameters, already encoded (RFC 9000 section 18), carried in the
     * `quic_transport_parameters` extension (RFC 9001 section 8.2); call it before the first [drive].
     */
    public fun setTransportParameters(encoded: ByteArray)

    /**
     * The QUIC version whose labels derive the Handshake and 1-RTT keys (RFC 9369 section 3.3). A client sets its
     * Original Version before the first [drive] and the server's version (from its Initial header) before providing
     * the ServerHello; a server lets `ksl` choose per RFC 9368. Unknown version: IllegalArgumentException; once
     * Handshake keys exist: IllegalStateException.
     */
    public fun setQuicVersion(version: Int)

    /**
     * Hands TLS the CRYPTO data `data[offset, +length)` received at [level], in stream order without gaps (the transport
     * reassembles it, RFC 9001 section 4.1.3); then call [drive]. Throws [IndexOutOfBoundsException] for a bad range.
     */
    public fun provide(
        level: EncryptionLevel,
        data: ByteArray,
        offset: Int = 0,
        length: Int = data.size - offset,
    )

    /**
     * Advances the handshake with the data provided so far and reports what it needs next; poll [nextEvent] after every
     * call. Not thread-safe: one session is driven by one connection loop.
     */
    public fun drive(): DriveResult

    /**
     * Resumes a handshake paused at [DriveResult.WantVerify] with the verdict, usually from [verifyPeer]; then call [drive].
     * A [VerifyResult.Rejected] makes TLS send its alert and the next [drive] return [DriveResult.Failed]. Throws
     * [IllegalStateException] when no verification is pending.
     */
    public fun resumeVerify(result: VerifyResult)

    /** Runs the configured trust (platform, custom, TOFU, pins) for a [DriveResult.WantVerify]; the caller then passes the result to [resumeVerify]. */
    public suspend fun verifyPeer(chain: List<Certificate>): VerifyResult

    /** The next queued event, or null when there is none; call until null after each [provide] and [drive]. A failed session has none. */
    public fun nextEvent(): TlsEvent?

    /** The chain the peer presented, leaf first; empty before its Certificate message arrives or when it sent none. */
    public val peerCertificates: List<Certificate>

    /** The application protocol agreed through ALPN (RFC 7301), or null before the handshake completes. */
    public val negotiatedAlpn: String?

    /** Always [EarlyDataState.Disabled] in v1 (ADR-0008). */
    public val earlyData: EarlyDataState

    /**
     * The RFC 8446 section 7.5 exporter: [length] bytes for [label] and [context] (null for none); only after the handshake,
     * before it [IllegalStateException].
     * The result is secret material on the heap by design (threat model 3.7); wipe it after use.
     */
    public fun exportKeyingMaterial(
        label: String,
        context: ByteArray?,
        length: Int,
    ): ByteArray
}

/** Thrown by [PacketProtector.open] when the authentication tag does not verify. */
public class PacketProtectionException(
    message: String,
) : IOException(message)

/** Packet protection for one level and direction (RFC 9001 section 5); key material lives in native memory. */
public interface PacketProtector : AutoCloseable {
    /** The AEAD of these keys; it fixes the 16-byte tag and the header protection cipher. */
    public val aead: Aead

    /** Encrypts in place; returns the payload length including the 16-byte tag. */
    public fun seal(
        packetNumber: Long,
        header: PacketBuffer,
        headerLength: Int,
        payload: PacketBuffer,
        payloadLength: Int,
    ): Int = seal(packetNumber, header, 0, headerLength, payload, 0, payloadLength)

    /** Decrypts in place; returns the plaintext length ([payloadLength] - 16). */
    public fun open(
        packetNumber: Long,
        header: PacketBuffer,
        headerLength: Int,
        payload: PacketBuffer,
        payloadLength: Int,
    ): Int = open(packetNumber, header, 0, headerLength, payload, 0, payloadLength)

    /** As [seal], with the header and payload at offsets, so a packet is protected in place inside one datagram buffer (no copies). */
    public fun seal(
        packetNumber: Long,
        header: PacketBuffer,
        headerOffset: Int,
        headerLength: Int,
        payload: PacketBuffer,
        payloadOffset: Int,
        payloadLength: Int,
    ): Int

    /** As [open], with offsets. */
    public fun open(
        packetNumber: Long,
        header: PacketBuffer,
        headerOffset: Int,
        headerLength: Int,
        payload: PacketBuffer,
        payloadOffset: Int,
        payloadLength: Int,
    ): Int

    /**
     * Writes the 5-byte header protection mask for the 16-byte ciphertext sample at `sample[sampleOffset]` into `mask[0, 5)`
     * (RFC 9001 section 5.4); [IndexOutOfBoundsException] when the sample or the mask does not fit.
     */
    public fun headerMask(
        sample: PacketBuffer,
        sampleOffset: Int,
        mask: ByteArray,
    )

    /** Next key-update generation: new key and IV, the same header-protection key (RFC 9001 section 5.4). */
    public fun next(): PacketProtector
}

/** An AEAD key for Retry tokens (RFC 9000 section 8.1.4): random, lives inside the native layer, one per endpoint loop (ADR-0003). */
public interface TokenKey : AutoCloseable {
    /** `ciphertext || tag(16)` of [plaintext] under [nonce] (a 64-bit value the token carries) and [aad] (what binds the token to its client). */
    public fun seal(
        nonce: Long,
        aad: ByteArray,
        plaintext: ByteArray,
    ): ByteArray

    /** The plaintext, or null when the tag does not verify. */
    public fun open(
        nonce: Long,
        aad: ByteArray,
        sealed: ByteArray,
    ): ByteArray?
}

/** A keyed MAC for stateless reset tokens (RFC 9000 section 10.3.2): the token of a connection ID is derived, never stored. */
public interface ResetKey : AutoCloseable {
    /** Writes the 16-byte token of `cid[offset, +length)` at `out[outOffset]`. */
    public fun token(
        cid: PacketBuffer,
        offset: Int,
        length: Int,
        out: ByteArray,
        outOffset: Int,
    )
}

/** The crypto provider the QUIC core sees (ADR-0002). */
public interface QuicCrypto {
    /**
     * A new handshake for one QUIC connection; the caller closes it. Throws [TlsException.Config] unless [config] suits QUIC:
     * TLS 1.3 only, a non-empty ALPN list, no CCM_8 suite and no `sniSelector` in v1 (RFC 9001 sections 4.2, 5.3, 8.1).
     */
    public fun newSession(config: TlsConfig): QuicTlsSession

    /** A fresh random Retry-token key; the material never reaches Kotlin (ADR-0003). */
    public fun newTokenKey(): TokenKey

    /** A fresh random stateless-reset key, independent of the connection ID generator (RFC 9000 section 10.3, ADR-0003). */
    public fun newResetKey(): ResetKey

    /** (read, write) Initial protectors for [role] derived from the client's first Destination Connection ID. */
    public fun initialProtectors(
        dcid: ByteArray,
        version: Int,
        role: TlsRole,
    ): Pair<PacketProtector, PacketProtector>

    /**
     * The 16-byte Retry Integrity Tag (RFC 9001 section 5.8) of [retryPseudoPacket] for the Original Destination Connection
     * ID [odcid], under the fixed key and nonce of QUIC [version].
     */
    public fun retryIntegrityTag(
        version: Int,
        odcid: ByteArray,
        retryPseudoPacket: ByteArray,
    ): ByteArray
}
