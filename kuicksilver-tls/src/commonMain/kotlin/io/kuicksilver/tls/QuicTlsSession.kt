// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(io.kuicksilver.annotations.InternalKuicksilverApi::class)

package io.kuicksilver.tls

import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.native.PacketBuffer
import kotlinx.io.IOException

/** QUIC encryption levels (RFC 9001 section 2.1), numbered as OpenSSL's protection levels. */
public enum class EncryptionLevel(
    internal val ksl: Int,
) {
    /** Initial packets, protected with keys derived from the client's first Destination Connection ID (RFC 9001 section 5.2). */
    Initial(0),

    /** 0-RTT packets (RFC 9001 section 4.6): written by a client resuming with early data, read by a server that accepted it (ADR-0015). */
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
    public class WantVerify
        @ExperimentalKuicksilverApi
        constructor(
            public val chain: List<Certificate>,
        ) : DriveResult

    /**
     * Fatal; [alert] is the TLS alert the transport sends as `CONNECTION_CLOSE 0x0100 + alert` (null when none applies).
     * Every later [QuicTlsSession.drive] returns the same result.
     *
     * @property exception what failed, for the application.
     * @property alert the TLS alert code (RFC 9846 section 6), already `handshake_failure` with [TlsConfig.genericAlerts].
     */
    public class Failed
        @ExperimentalKuicksilverApi
        constructor(
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
    public class CryptoData
        @ExperimentalKuicksilverApi
        constructor(
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
    public class Keys
        @ExperimentalKuicksilverApi
        constructor(
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
    public class PeerTransportParameters
        @ExperimentalKuicksilverApi
        constructor(
            public val encoded: ByteArray,
            public val negotiatedVersion: Int,
        ) : TlsEvent

    /**
     * The TLS handshake completed and every trust check, pins included, passed (RFC 9001 section 4.1.1); a failed check
     * yields [DriveResult.Failed] instead.
     */
    public object HandshakeDone : TlsEvent

    /**
     * Client: the server sent a NewSessionTicket (RFC 9846 section 4.7.1); only for sessions created with early data
     * (`QuicCrypto.newSession(config, earlyData = true)`). The receiver owns [ticket] and closes it or stores it.
     *
     * @property ticket the resumable session.
     */
    @ExperimentalKuicksilverApi
    public class SessionTicket
        @ExperimentalKuicksilverApi
        constructor(
            public val ticket: QuicSessionTicket,
        ) : TlsEvent
}

/**
 * Whether a client uses 0-RTT (RFC 9001 section 4.6, ADR-0015). 0-RTT data can be replayed by an attacker (RFC 9846
 * section 8): send early only what is safe to execute twice. Entries may be added; keep an `else` branch in `when`.
 * Experimental, as the rest of the 0-RTT API.
 */
@ExperimentalKuicksilverApi
public enum class EarlyDataState {
    /** No resumption and no 0-RTT (the default). */
    Disabled,

    /**
     * Resume with a stored ticket and send 0-RTT when the ticket allows it. A rejection of 0-RTT that carried anything
     * closes the connection (QUIC: `ZeroRttRejected`; RFC 9001 section 4.6.2), and nothing is sent again in 1-RTT.
     */
    Allowed,

    /** As [Allowed], but a missing ticket or a rejection fails the connection instead of falling back to 1-RTT. */
    Required,
}

/**
 * The server's replay register for 0-RTT (RFC 9846 section 8, ADR-0015): consulted once per ClientHello that offers
 * early data, keyed by the identity of the ticket it resumes (`key_name ‖ iv`, 32 bytes). Implementations are called on
 * connection loops and must be thread-safe when several loops share one.
 */
@ExperimentalKuicksilverApi
public interface EarlyDataAdmission {
    /** True to let this hello's early data through (and remember [ticketId]); false when it was seen within the window. */
    public fun admit(ticketId: ByteArray): Boolean

    /** The admitted hello did not get early data after all (bad binder, stale ticket, other configuration): forget it. */
    public fun release(ticketId: ByteArray)
}

/**
 * A client's resumable QUIC session (RFC 9846 section 4.7.1): the ticket and its resumption secret stay in native memory.
 * Single use (RFC 9846 appendix C.4): [QuicTlsSession.resume] consumes it. [remembered] holds what the transport stores
 * with it (the server's transport parameters, RFC 9000 section 7.4.1).
 */
@ExperimentalKuicksilverApi
public class QuicSessionTicket internal constructor(
    internal val entry: SessionCache.Entry,
) : AutoCloseable {
    /** Opaque bytes the transport keeps with the ticket; never secret. */
    public var remembered: ByteArray?
        get() = entry.remembered
        set(value) {
            entry.remembered = value
        }

    /** True once the native session was released (closed or consumed). */
    public val closed: Boolean get() = entry.closed

    /** Releases the native session; a consumed ticket is already released. */
    override fun close(): Unit = entry.close()
}

/**
 * The TLS handshake of one QUIC connection, driven by the transport without any I/O of its own (RFC 9001 section 4).
 *
 * A call in the wrong state throws [IllegalStateException]; an error reported by TLS itself throws [TlsException] (most
 * failures arrive as [DriveResult.Failed] instead). The native layer's exceptions never escape.
 */
@SubclassOptInRequired(ExperimentalKuicksilverApi::class)
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

    /**
     * Client: true when the server accepted our 0-RTT, false when it rejected it, null when none was attempted or the
     * answer has not arrived (RFC 9001 section 4.6.2). Server: true when 0-RTT of this connection was accepted, false
     * when the client offered it and we refused, null otherwise.
     */
    @ExperimentalKuicksilverApi
    public val earlyDataAccepted: Boolean? get() = null

    /**
     * CRYPTO bytes [provide]d at [level] that TLS has not read yet. The transport counts them toward the memory of an
     * unfinished handshake and, once TLS reads a higher level, treats any left at a lower one as a PROTOCOL_VIOLATION
     * (RFC 9001 section 4.1.3). TLS holds at most 256 KiB unread per level: [provide] beyond that, or at a level below the
     * one TLS reads, throws [TlsException]. Zero for a closed or failed session.
     */
    @ExperimentalKuicksilverApi
    public fun pendingCryptoBytes(level: EncryptionLevel): Int = 0

    /**
     * Client: resume [ticket] (it is consumed and closed by this session); call before the first [drive]. False when TLS
     * refused it, or when the check below failed (the handshake then is a full one).
     *
     * What is verified again (ADR-0011: a resumed handshake carries no Certificate, so its trust comes from the chain cached
     * with the ticket). With the OpenSSL verifier ([TrustConfig.AnchoredCa], and [TrustConfig.Platform] on Linux, also under
     * [TrustConfig.Pinned] or [TrustConfig.ExpectedName]) this call verifies the cached chain again against the current
     * anchors, time, host name and purpose and returns false when it no longer passes; the pins are checked again on the
     * cached validated chain when the resumed handshake completes. With any other trust (the platform verifier on the JVM,
     * Android, Apple platforms and Windows, a custom verifier, TOFU) this call checks nothing: the verdict is run again on the
     * cached chain only by [SessionCache.takeQuic], which hands out a ticket only after it passed. A ticket kept by the caller,
     * or taken for another [TlsConfig] than this session's, resumes on the verdict of the handshake that issued it.
     */
    @ExperimentalKuicksilverApi
    public fun resume(ticket: QuicSessionTicket): Boolean {
        ticket.close()
        return false
    }

    /**
     * Call before the first [drive]. Client ([context] and [admission] null): requests 0-RTT with the resumed ticket and
     * returns false when there is none or it does not allow early data. Server (session created with early data):
     * [context] (1..64 bytes, the configuration digest of RFC 9001 section 4.6.3) is bound into issued tickets and must
     * match the resumed one, and [admission] decides each hello's early data; returns true.
     */
    @ExperimentalKuicksilverApi
    public fun enableEarlyData(
        context: ByteArray?,
        admission: EarlyDataAdmission?,
    ): Boolean = false

    /**
     * The RFC 9846 section 7.5 exporter: [length] bytes for [label] and [context] (null for none); only after the handshake,
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
@SubclassOptInRequired(ExperimentalKuicksilverApi::class)
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
@SubclassOptInRequired(ExperimentalKuicksilverApi::class)
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
@SubclassOptInRequired(ExperimentalKuicksilverApi::class)
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
@SubclassOptInRequired(ExperimentalKuicksilverApi::class)
public interface QuicCrypto {
    /**
     * A new handshake for one QUIC connection; the caller closes it. Throws [TlsException.Config] unless [config] suits QUIC:
     * TLS 1.3 only, a non-empty ALPN list, no CCM_8 suite and no `sniSelector` in v1 (RFC 9001 sections 4.2, 5.3, 8.1).
     */
    public fun newSession(config: TlsConfig): QuicTlsSession

    /**
     * As [newSession]; with [earlyData] a server issues tickets that allow 0-RTT and can accept it, and a client reports
     * the tickets it receives as [TlsEvent.SessionTicket] (ADR-0015). A provider without 0-RTT ignores the flag.
     */
    @ExperimentalKuicksilverApi
    public fun newSession(
        config: TlsConfig,
        earlyData: Boolean,
    ): QuicTlsSession = newSession(config)

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
