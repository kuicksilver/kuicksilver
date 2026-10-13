// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.native

import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.annotations.InternalKuicksilverApi

/**
 * Thin, platform-neutral bindings over `ksl.h`. Handles are `Long` on every platform (JNI `jlong`, cinterop pointer value).
 *
 * Every call that `ksl` answers with `KSL_ERROR` throws [KslException.Internal] built from the object's error buffer in the
 * same call; `WANT_*`/`EOF` outcomes are returned as [KslConst] codes. Callers own handles and must free them exactly once.
 */
@InternalKuicksilverApi
public expect object Ksl {
    public fun abiVersion(): Int

    public fun version(): String

    // context
    public fun ctxNew(role: Int): Long

    public fun ctxFree(ctx: Long)

    public fun ctxSetAlpn(
        ctx: Long,
        wire: ByteArray,
    )

    public fun ctxSetIdentity(
        ctx: Long,
        chainDer: List<ByteArray>,
        keyDer: ByteArray,
    )

    /**
     * Sets the identity from a key parsed by [pkeyNew]; the context takes its own reference, so [pkey] may be freed right
     * after. The key bytes never come back to Kotlin.
     */
    public fun ctxSetIdentityKey(
        ctx: Long,
        chainDer: List<ByteArray>,
        pkey: Long,
    )

    /**
     * Parses a PKCS#8 DER private key into a native `ksl_pkey` handle (freed with [pkeyFree]); throws
     * [KslException.Internal] if [der] is not exactly one key. The caller wipes [der]; the JNI copy is wiped here.
     */
    public fun pkeyNew(der: ByteArray): Long

    /** Drops one reference to a `ksl_pkey`; the last one frees and cleanses the key. `0` is ignored. */
    public fun pkeyFree(pkey: Long)

    public fun ctxSetRoots(
        ctx: Long,
        rootsDer: List<ByteArray>,
    )

    public fun ctxSetCiphers(
        ctx: Long,
        tls13: String?,
        tls12: String?,
    )

    public fun ctxSetTicketKeys(
        ctx: Long,
        keys: List<ByteArray>,
    )

    /** Server: 1..32 bytes; a session resumes only under a context with the same bytes (otherwise a full handshake). */
    public fun ctxSetSessionContext(
        ctx: Long,
        sidCtx: ByteArray,
    )

    public fun ctxSetOption(
        ctx: Long,
        option: Int,
        value: Int,
    )

    public fun ctxFreeze(ctx: Long)

    public fun ctxLastError(ctx: Long): KslError

    // session
    public fun sslNew(
        ctx: Long,
        mode: Int,
    ): Long

    public fun sslFree(ssl: Long)

    /** [KslConst.SET_SNI], [KslConst.SET_VERIFY_NAME] (ASCII name bytes) or [KslConst.SET_QUIC_VERSION] (4-byte big-endian). */
    public fun sslSet(
        ssl: Long,
        what: Int,
        data: ByteArray,
    )

    public fun sslGet(
        ssl: Long,
        what: Int,
    ): ByteArray

    public fun sslPeerChain(
        ssl: Long,
        which: Int,
    ): List<ByteArray>

    public fun sslVerifyResume(
        ssl: Long,
        accept: Boolean,
        alert: Int,
    )

    public fun sslClientHello(ssl: Long): KslClientHello

    public fun sslSniResume(
        ssl: Long,
        overrideCtx: Long,
        alert: Int,
    )

    public fun sslExportKeyingMaterial(
        ssl: Long,
        label: String,
        context: ByteArray?,
        length: Int,
    ): ByteArray

    /** A client's resumable session as a native handle (0 if none yet): a new reference, freed with [sessionFree]; the same handle while the session does not change. The ticket and its secret never leave native memory. */
    public fun sslGet1Session(ssl: Long): Long

    /** Offers [session] for resumption (client, before the handshake); the caller keeps its reference. */
    public fun sslSetSession(
        ssl: Long,
        session: Long,
    )

    public fun sessionFree(session: Long)

    public fun sslNewSessionTicket(ssl: Long)

    public fun sslKeyUpdate(
        ssl: Long,
        requestPeer: Boolean,
    )

    public fun sslLastError(ssl: Long): KslError

    public fun drive(ssl: Long): Int

    // QUIC
    public fun quicSetTransportParams(
        ssl: Long,
        tp: ByteArray,
    )

    public fun quicProvide(
        ssl: Long,
        level: Int,
        data: ByteArray,
        offset: Int,
        length: Int,
    )

    /** Fills [out] and returns true, or returns false when the queue is empty. An event never fits? It is still delivered: the binding grows its buffer. */
    public fun quicNextEvent(
        ssl: Long,
        out: KslEvent,
    ): Boolean

    // TCP
    public fun tcpFeed(
        ssl: Long,
        data: ByteArray,
        offset: Int,
        length: Int,
    ): Int

    public fun tcpDrain(
        ssl: Long,
        into: ByteArray,
        offset: Int,
        capacity: Int,
    ): Int

    public fun tcpWrite(
        ssl: Long,
        data: ByteArray,
        offset: Int,
        length: Int,
    ): Int

    public fun tcpRead(
        ssl: Long,
        into: ByteArray,
        offset: Int,
        capacity: Int,
    ): Int

    public fun tcpShutdown(ssl: Long): Int

    // keys
    public fun keyInitial(
        dcid: ByteArray,
        isServer: Boolean,
        direction: Int,
        version: Int,
    ): Long

    public fun keyNext(key: Long): Long

    public fun keyFree(key: Long)

    /** An endpoint key made inside ksl: [KslConst.EKEY_TOKEN] (AES-256-GCM for Retry tokens, used with [seal]/[open]) or [KslConst.EKEY_RESET] (HMAC-SHA256 for stateless reset tokens). */
    public fun keyRandom(kind: Int): Long

    /** First 16 bytes of HMAC-SHA256 over `input[offset, +length)` with a reset key, written at `out[outOffset]`. */
    public fun keyMac16(
        key: Long,
        input: PacketBuffer,
        offset: Int,
        length: Int,
        out: ByteArray,
        outOffset: Int,
    )

    /** AEAD over `payload[payloadOffset, +payloadLength)` with `header[headerOffset, +headerLength)` as AAD; the tag is written after the payload. */
    public fun seal(
        key: Long,
        packetNumber: Long,
        header: PacketBuffer,
        headerOffset: Int,
        headerLength: Int,
        payload: PacketBuffer,
        payloadOffset: Int,
        payloadLength: Int,
    ): Int

    public fun open(
        key: Long,
        packetNumber: Long,
        header: PacketBuffer,
        headerOffset: Int,
        headerLength: Int,
        payload: PacketBuffer,
        payloadOffset: Int,
        payloadLength: Int,
    ): Int

    public fun headerMask(
        key: Long,
        sample: PacketBuffer,
        sampleOffset: Int,
        mask: ByteArray,
    )

    public fun retryTag(
        version: Int,
        odcid: ByteArray,
        pseudoPacket: ByteArray,
    ): ByteArray

    // crypto
    public fun rand(n: Int): ByteArray

    public fun sha2(
        bits: Int,
        data: ByteArray,
    ): ByteArray

    public fun hkdfExpandLabel(
        hash: Int,
        secret: ByteArray,
        label: String,
        context: ByteArray,
        length: Int,
    ): ByteArray

    public fun sign(
        alg: Int,
        keyDer: ByteArray,
        message: ByteArray,
    ): ByteArray

    public fun verify(
        alg: Int,
        publicKeyDer: ByteArray,
        message: ByteArray,
        signature: ByteArray,
    ): Boolean

    public fun spkiSha256(certDer: ByteArray): ByteArray

    // accelerated UDP (Linux; ADR-0006). Slots are [PacketBuffer]s read and written in place; at most [KslConst.UDP_MAX_BATCH] per call.

    /** Opens and binds; throws [KslException.Internal] with [KslConst.E_NOT_SUPPORTED] where `ksl_udp` is not available (a target that is neither Linux, Android, Apple nor Windows). */
    public fun udpOpen(
        addr: ByteArray,
        flags: Int,
    ): Long

    /** Datagrams sent (slots skipped for EMSGSIZE or a bad destination count); `lens[i] <= bufs[i].capacity`; throws on a socket error. */
    public fun udpSend(
        udp: Long,
        bufs: Array<PacketBuffer>,
        lens: IntArray,
        addrs: ByteArray,
        ecn: ByteArray,
        n: Int,
    ): Int

    /** Datagrams received into the first slots, 0 on timeout; -1 once the socket was shut down. */
    public fun udpRecv(
        udp: Long,
        bufs: Array<PacketBuffer>,
        lens: IntArray,
        addrs: ByteArray,
        ecn: ByteArray,
        n: Int,
        timeoutMs: Int,
    ): Int

    public fun udpGet(
        udp: Long,
        what: Int,
    ): ByteArray

    public fun udpShutdown(udp: Long)

    public fun udpClose(udp: Long)

    /**
     * `ksl_live_objects`: the process-wide counts of native objects alive now, indexed by `KslConst.LIVE_*` (contexts,
     * sessions, keys, key and session handles, UDP sockets, wake descriptors). For soak and leak tests; a snapshot, never
     * a synchronisation point.
     */
    public fun liveObjects(): LongArray
}

/** The ABI the Kotlin side was written against; checked against [Ksl.abiVersion] on load. */
public const val KSL_ABI_VERSION: Int = 6

/**
 * Loads the native library once per process and checks the ABI. [availability] answers without throwing whether the
 * library can be used; [ensureLoaded] throws [KslException] when it cannot.
 */
public expect object KslLoader {
    /**
     * Loads and initializes `libksl` unless this process already tried, then checks [KSL_ABI_VERSION]. The TLS layer calls it
     * before its first native call; an application may call it at startup to fail fast on a missing or tampered library
     * (threat model, supply chain). Thread-safe and cheap after the first attempt. A failure throws [KslException]
     * ([KslException.NativeLoad], [KslException.AbiMismatch], or on system-OpenSSL builds [KslException.Version] and
     * [KslException.MissingSymbol]). The outcome of the first attempt is kept for the life of the process, shared with
     * [availability]: after a failure every later call throws the same exception instance without loading again (a fixed
     * installation needs a restart). The library is never unloaded.
     */
    public fun ensureLoaded()

    /**
     * Whether `libksl` can be used in this process; never throws (except for fatal VM errors such as
     * [OutOfMemoryError][kotlin.OutOfMemoryError]). Performs the same single load attempt as [ensureLoaded] (whichever is
     * called first loads, the other reuses the outcome) and keeps the outcome for the life of the process, both
     * [NativeAvailability.Available] and [NativeAvailability.Unavailable]: a later call never retries. Thread-safe: every
     * caller sees the same outcome (on the JVM and Android concurrent first calls wait for the one attempt).
     *
     * Use it at startup when the application must also run where Kuicksilver ships no native build (another OS or CPU
     * architecture), to choose a fallback transport instead of catching [KslException]:
     * `if (!KslLoader.isAvailable()) fallBackToTcp()`. On Kotlin/Native the library is linked statically, so the answer is
     * [NativeAvailability.Available] unless initialization or the ABI check fails.
     */
    @ExperimentalKuicksilverApi
    public fun availability(): NativeAvailability

    /** `availability() is NativeAvailability.Available`: the same cached, non-throwing check as [availability]. */
    @ExperimentalKuicksilverApi
    public fun isAvailable(): Boolean
}

/** Length-prefixed framing shared by the bindings: `(uint32 BE length || DER)*`. */
@InternalKuicksilverApi
public fun frameDerList(items: List<ByteArray>): ByteArray {
    val out = ByteArray(items.sumOf { it.size + 4 })
    var off = 0
    for (d in items) {
        out[off] = (d.size ushr 24).toByte()
        out[off + 1] = (d.size ushr 16).toByte()
        out[off + 2] = (d.size ushr 8).toByte()
        out[off + 3] =
            d.size.toByte()
        d.copyInto(out, off + 4)
        off += 4 + d.size
    }
    return out
}
