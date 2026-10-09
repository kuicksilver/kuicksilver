// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.native

import java.nio.ByteBuffer

/** JNI entry points registered by `JNI_OnLoad` (RegisterNatives). Return conventions: negative = `KSL_ERROR` unless documented. */
internal object KslNative {
    @JvmStatic external fun abiVersion(): Int

    /** ksl_init: 0, or KSL_INIT_* (-2 version, -3 missing symbol, -4 keylog environment) */
    @JvmStatic external fun init(): Int

    @JvmStatic external fun version(): String

    @JvmStatic external fun ctxNew(role: Int): Long

    @JvmStatic external fun ctxFree(ctx: Long)

    @JvmStatic external fun ctxSetAlpn(
        ctx: Long,
        wire: ByteArray,
    ): Int

    @JvmStatic external fun ctxSetIdentity(
        ctx: Long,
        chain: ByteArray,
        key: ByteArray,
    ): Int

    @JvmStatic external fun ctxSetRoots(
        ctx: Long,
        roots: ByteArray,
    ): Int

    @JvmStatic external fun ctxSetCiphers(
        ctx: Long,
        tls13: String?,
        tls12: String?,
    ): Int

    @JvmStatic external fun ctxSetTicketKeys(
        ctx: Long,
        keys: ByteArray,
    ): Int

    @JvmStatic external fun ctxSetSessionContext(
        ctx: Long,
        sidCtx: ByteArray,
    ): Int

    @JvmStatic external fun ctxSetOption(
        ctx: Long,
        option: Int,
        value: Int,
    ): Int

    @JvmStatic external fun ctxFreeze(ctx: Long): Int

    /** out[0] = packed code */
    @JvmStatic external fun ctxLastError(
        ctx: Long,
        out: IntArray,
    ): String

    @JvmStatic external fun sslNew(
        ctx: Long,
        mode: Int,
    ): Long

    @JvmStatic external fun sslFree(ssl: Long)

    @JvmStatic external fun sslSet(
        ssl: Long,
        what: Int,
        data: ByteArray,
    ): Int

    /** null on error */
    @JvmStatic external fun sslGet(
        ssl: Long,
        what: Int,
    ): ByteArray?

    @JvmStatic external fun sslPeerChainCount(
        ssl: Long,
        which: Int,
    ): Int

    @JvmStatic external fun sslPeerChainItem(
        ssl: Long,
        which: Int,
        idx: Int,
    ): ByteArray?

    @JvmStatic external fun sslVerifyResume(
        ssl: Long,
        accept: Int,
        alert: Int,
    ): Int

    /** framing: u16 sniLen | sni | u16 alpnLen | alpn | u16 sigLen | sig; sniLen 0xffff = absent. null on error */
    @JvmStatic external fun sslClientHello(ssl: Long): ByteArray?

    @JvmStatic external fun sslSniResume(
        ssl: Long,
        overrideCtx: Long,
        alert: Int,
    ): Int

    @JvmStatic external fun sslExportKeyingMaterial(
        ssl: Long,
        label: String,
        context: ByteArray?,
        length: Int,
    ): ByteArray?

    /** 0 when there is no resumable session */
    @JvmStatic external fun sslGet1Session(ssl: Long): Long

    @JvmStatic external fun sslSetSession(
        ssl: Long,
        session: Long,
    ): Int

    @JvmStatic external fun sessionFree(session: Long)

    @JvmStatic external fun sslNewSessionTicket(ssl: Long): Int

    @JvmStatic external fun sslKeyUpdate(
        ssl: Long,
        requestPeer: Int,
    ): Int

    /** out[0] = packed code, out[1] = alert */
    @JvmStatic external fun sslLastError(
        ssl: Long,
        out: IntArray,
    ): String

    @JvmStatic external fun drive(ssl: Long): Int

    @JvmStatic external fun quicSetTransportParams(
        ssl: Long,
        tp: ByteArray,
    ): Int

    @JvmStatic external fun quicProvide(
        ssl: Long,
        level: Int,
        data: ByteArray,
        offset: Int,
        length: Int,
    ): Int

    /** 1 = event copied (header 24 bytes + payload), 0 = none, -(24+n) = buffer too small (event stays queued), -1 = error */
    @JvmStatic external fun quicNextEvent(
        ssl: Long,
        out: ByteBuffer,
        capacity: Int,
    ): Int

    /** feed/drain: bytes moved, -1 error. write/read: bytes, -2 WANT_READ, -3 EOF, -1 error. shutdown: KSL code. */
    @JvmStatic external fun tcpFeed(
        ssl: Long,
        data: ByteArray,
        offset: Int,
        length: Int,
    ): Int

    @JvmStatic external fun tcpDrain(
        ssl: Long,
        into: ByteArray,
        offset: Int,
        capacity: Int,
    ): Int

    @JvmStatic external fun tcpWrite(
        ssl: Long,
        data: ByteArray,
        offset: Int,
        length: Int,
    ): Int

    @JvmStatic external fun tcpRead(
        ssl: Long,
        into: ByteArray,
        offset: Int,
        capacity: Int,
    ): Int

    @JvmStatic external fun tcpShutdown(ssl: Long): Int

    @JvmStatic external fun keyInitial(
        dcid: ByteArray,
        isServer: Int,
        direction: Int,
        version: Int,
    ): Long

    @JvmStatic external fun keyNext(key: Long): Long

    @JvmStatic external fun keyFree(key: Long)

    @JvmStatic external fun keyRandom(kind: Int): Long

    @JvmStatic external fun keyMac16(
        key: Long,
        input: ByteBuffer,
        offset: Int,
        length: Int,
        out: ByteArray,
        outOffset: Int,
    ): Int

    @JvmStatic external fun seal(
        key: Long,
        pn: Long,
        header: ByteBuffer,
        headerOff: Int,
        headerLen: Int,
        payload: ByteBuffer,
        payloadOff: Int,
        payloadLen: Int,
        capacity: Int,
    ): Int

    @JvmStatic external fun open(
        key: Long,
        pn: Long,
        header: ByteBuffer,
        headerOff: Int,
        headerLen: Int,
        payload: ByteBuffer,
        payloadOff: Int,
        payloadLen: Int,
    ): Int

    @JvmStatic external fun headerMask(
        key: Long,
        sample: ByteBuffer,
        sampleOffset: Int,
        mask: ByteArray,
    ): Int

    @JvmStatic external fun retryTag(
        version: Int,
        odcid: ByteArray,
        pseudo: ByteArray,
    ): ByteArray?

    @JvmStatic external fun rand(n: Int): ByteArray?

    @JvmStatic external fun sha2(
        bits: Int,
        data: ByteArray,
    ): ByteArray?

    @JvmStatic external fun hkdfExpandLabel(
        hash: Int,
        secret: ByteArray,
        label: String,
        context: ByteArray,
        length: Int,
    ): ByteArray?

    @JvmStatic external fun sign(
        alg: Int,
        keyDer: ByteArray,
        message: ByteArray,
    ): ByteArray?

    @JvmStatic external fun verify(
        alg: Int,
        publicKeyDer: ByteArray,
        message: ByteArray,
        signature: ByteArray,
    ): Int

    @JvmStatic external fun spkiSha256(certDer: ByteArray): ByteArray?

    @JvmStatic external fun udpOpen(
        addr: ByteArray,
        flags: Int,
        err: IntArray,
        msg: Array<String?>,
    ): Long

    /** sent, or -1 */
    @JvmStatic external fun udpSend(
        udp: Long,
        bufs: Array<PacketBuffer>,
        lens: IntArray,
        addrs: ByteArray,
        ecn: ByteArray,
        n: Int,
    ): Int

    /** received, -2 on timeout, -1 on error */
    @JvmStatic external fun udpRecv(
        udp: Long,
        bufs: Array<PacketBuffer>,
        lens: IntArray,
        addrs: ByteArray,
        ecn: ByteArray,
        n: Int,
        timeoutMs: Int,
    ): Int

    @JvmStatic external fun udpGet(
        udp: Long,
        what: Int,
    ): ByteArray?

    @JvmStatic external fun udpShutdown(udp: Long)

    @JvmStatic external fun udpClose(udp: Long)
}
