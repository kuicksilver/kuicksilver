// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.native

import io.kuicksilver.annotations.InternalKuicksilverApi
import java.nio.ByteBuffer
import java.nio.ByteOrder

@InternalKuicksilverApi
public actual object Ksl {
    private fun ctxCheck(
        ctx: Long,
        rc: Int,
    ) {
        if (rc < 0) throw ctxError(ctx)
    }

    private fun sslCheck(
        ssl: Long,
        rc: Int,
    ): Int {
        if (rc < 0) throw sslError(ssl)
        return rc
    }

    private fun ctxError(ctx: Long): KslException.Internal {
        val o = IntArray(1)
        val m = KslNative.ctxLastError(ctx, o)
        return KslException.Internal(o[0], 0, m)
    }

    private fun sslError(ssl: Long): KslException.Internal {
        val o = IntArray(2)
        val m = KslNative.sslLastError(ssl, o)
        return KslException.Internal(o[0], o[1], m)
    }

    private fun <T : Any> notNull(
        v: T?,
        ssl: Long,
    ): T = v ?: throw sslError(ssl)

    private fun internal(msg: String): Nothing = throw KslException.Internal(KslConst.E_NOT_SUPPORTED, 0, msg)

    public actual fun abiVersion(): Int = KslNative.abiVersion()

    public actual fun version(): String = KslNative.version()

    public actual fun ctxNew(role: Int): Long = KslNative.ctxNew(role).also { if (it == 0L) internal("ksl_ctx_new failed") }

    public actual fun ctxFree(ctx: Long): Unit = KslNative.ctxFree(ctx)

    public actual fun ctxSetAlpn(
        ctx: Long,
        wire: ByteArray,
    ): Unit = ctxCheck(ctx, KslNative.ctxSetAlpn(ctx, wire))

    public actual fun ctxSetIdentity(
        ctx: Long,
        chainDer: List<ByteArray>,
        keyDer: ByteArray,
    ): Unit = ctxCheck(ctx, KslNative.ctxSetIdentity(ctx, frameDerList(chainDer), keyDer))

    public actual fun ctxSetRoots(
        ctx: Long,
        rootsDer: List<ByteArray>,
    ): Unit = ctxCheck(ctx, KslNative.ctxSetRoots(ctx, frameDerList(rootsDer)))

    public actual fun ctxSetCiphers(
        ctx: Long,
        tls13: String?,
        tls12: String?,
    ): Unit = ctxCheck(ctx, KslNative.ctxSetCiphers(ctx, tls13, tls12))

    public actual fun ctxSetTicketKeys(
        ctx: Long,
        keys: List<ByteArray>,
    ) {
        require(keys.all { it.size == 80 }) { "each ticket key is 80 bytes" }
        ctxCheck(ctx, KslNative.ctxSetTicketKeys(ctx, keys.fold(ByteArray(0)) { a, b -> a + b }))
    }

    public actual fun ctxSetSessionContext(
        ctx: Long,
        sidCtx: ByteArray,
    ): Unit = ctxCheck(ctx, KslNative.ctxSetSessionContext(ctx, sidCtx))

    public actual fun ctxSetOption(
        ctx: Long,
        option: Int,
        value: Int,
    ): Unit = ctxCheck(ctx, KslNative.ctxSetOption(ctx, option, value))

    public actual fun ctxFreeze(ctx: Long): Unit = ctxCheck(ctx, KslNative.ctxFreeze(ctx))

    public actual fun ctxLastError(ctx: Long): KslError {
        val o = IntArray(1)
        val m = KslNative.ctxLastError(ctx, o)
        return KslError(o[0], 0, m)
    }

    public actual fun sslNew(
        ctx: Long,
        mode: Int,
    ): Long = KslNative.sslNew(ctx, mode).also { if (it == 0L) internal("ksl_ssl_new failed") }

    public actual fun sslFree(ssl: Long): Unit = KslNative.sslFree(ssl)

    public actual fun sslSet(
        ssl: Long,
        what: Int,
        data: ByteArray,
    ) {
        sslCheck(ssl, KslNative.sslSet(ssl, what, data))
    }

    public actual fun sslGet(
        ssl: Long,
        what: Int,
    ): ByteArray = notNull(KslNative.sslGet(ssl, what), ssl)

    public actual fun sslPeerChain(
        ssl: Long,
        which: Int,
    ): List<ByteArray> =
        List(sslCheck(ssl, KslNative.sslPeerChainCount(ssl, which))) {
            notNull(KslNative.sslPeerChainItem(ssl, which, it), ssl)
        }

    public actual fun sslVerifyResume(
        ssl: Long,
        accept: Boolean,
        alert: Int,
    ) {
        sslCheck(ssl, KslNative.sslVerifyResume(ssl, if (accept) 1 else 0, alert))
    }

    public actual fun sslClientHello(ssl: Long): KslClientHello {
        val b = notNull(KslNative.sslClientHello(ssl), ssl)
        var off = 0

        fun u16(): Int = ((b[off].toInt() and 0xff) shl 8 or (b[off + 1].toInt() and 0xff)).also { off += 2 }

        fun bytes(n: Int): ByteArray = b.copyOfRange(off, off + n).also { off += n }
        val sniLen = u16()
        val sni = if (sniLen == 0xffff) null else bytes(sniLen).decodeToString()
        val alpn = bytes(u16())
        val sig = bytes(u16())
        return KslClientHello(sni, alpn, sig)
    }

    public actual fun sslSniResume(
        ssl: Long,
        overrideCtx: Long,
        alert: Int,
    ) {
        sslCheck(ssl, KslNative.sslSniResume(ssl, overrideCtx, alert))
    }

    public actual fun sslExportKeyingMaterial(
        ssl: Long,
        label: String,
        context: ByteArray?,
        length: Int,
    ): ByteArray = notNull(KslNative.sslExportKeyingMaterial(ssl, label, context, length), ssl)

    public actual fun sslGet1Session(ssl: Long): Long = KslNative.sslGet1Session(ssl)

    public actual fun sslSetSession(
        ssl: Long,
        session: Long,
    ) {
        sslCheck(ssl, KslNative.sslSetSession(ssl, session))
    }

    public actual fun sessionFree(session: Long): Unit = KslNative.sessionFree(session)

    public actual fun sslNewSessionTicket(ssl: Long) {
        sslCheck(ssl, KslNative.sslNewSessionTicket(ssl))
    }

    public actual fun sslKeyUpdate(
        ssl: Long,
        requestPeer: Boolean,
    ) {
        sslCheck(ssl, KslNative.sslKeyUpdate(ssl, if (requestPeer) 1 else 0))
    }

    public actual fun sslLastError(ssl: Long): KslError {
        val o = IntArray(2)
        val m = KslNative.sslLastError(ssl, o)
        return KslError(o[0], o[1], m)
    }

    public actual fun drive(ssl: Long): Int = sslCheck(ssl, KslNative.drive(ssl))

    public actual fun quicSetTransportParams(
        ssl: Long,
        tp: ByteArray,
    ) {
        sslCheck(ssl, KslNative.quicSetTransportParams(ssl, tp))
    }

    public actual fun quicProvide(
        ssl: Long,
        level: Int,
        data: ByteArray,
        offset: Int,
        length: Int,
    ) {
        checkRange(data.size, offset, length, "quicProvide")
        sslCheck(ssl, KslNative.quicProvide(ssl, level, data, offset, length))
    }

    public actual fun quicNextEvent(
        ssl: Long,
        out: KslEvent,
    ): Boolean {
        // the direct buffer belongs to the caller's KslEvent: sessions on different threads never share it
        var buffer = out.scratch as? ByteBuffer ?: ByteBuffer.allocateDirect(8192).order(ByteOrder.nativeOrder()).also { out.scratch = it }
        var r = KslNative.quicNextEvent(ssl, buffer, buffer.capacity())
        if (r <
            -1
        ) {
            buffer = ByteBuffer.allocateDirect(-r).order(ByteOrder.nativeOrder()).also { out.scratch = it }
            r =
                KslNative.quicNextEvent(ssl, buffer, buffer.capacity())
        }
        if (r == -1) throw sslError(ssl)
        if (r == 0) return false
        val b = buffer
        out.type = b.getInt(0)
        out.level = b.getInt(4)
        out.direction = b.getInt(8)
        out.aead = b.getInt(12)
        val n = b.getInt(16)
        out.key = b.getLong(24)
        out.payload =
            ByteArray(n).also {
                b.position(32)
                b.get(it)
                b.position(0)
            }
        return true
    }

    // the JNI side checks too (answering -1); checking here gives every platform the same IndexOutOfBoundsException
    public actual fun tcpFeed(
        ssl: Long,
        data: ByteArray,
        offset: Int,
        length: Int,
    ): Int {
        checkRange(data.size, offset, length, "tcpFeed")
        return sslCheck(ssl, KslNative.tcpFeed(ssl, data, offset, length))
    }

    public actual fun tcpDrain(
        ssl: Long,
        into: ByteArray,
        offset: Int,
        capacity: Int,
    ): Int {
        checkRange(into.size, offset, capacity, "tcpDrain")
        return sslCheck(ssl, KslNative.tcpDrain(ssl, into, offset, capacity))
    }

    public actual fun tcpWrite(
        ssl: Long,
        data: ByteArray,
        offset: Int,
        length: Int,
    ): Int {
        checkRange(data.size, offset, length, "tcpWrite")
        return tcpCode(ssl, KslNative.tcpWrite(ssl, data, offset, length))
    }

    public actual fun tcpRead(
        ssl: Long,
        into: ByteArray,
        offset: Int,
        capacity: Int,
    ): Int {
        checkRange(into.size, offset, capacity, "tcpRead")
        return tcpCode(ssl, KslNative.tcpRead(ssl, into, offset, capacity))
    }

    public actual fun tcpShutdown(ssl: Long): Int = sslCheck(ssl, KslNative.tcpShutdown(ssl))

    /** write/read: bytes >= 0, or the negated KslConst code (-WANT_READ, -EOF) for the caller to act on. */
    private fun tcpCode(
        ssl: Long,
        r: Int,
    ): Int =
        when (r) {
            -1 -> throw sslError(ssl)
            -2 -> -KslConst.WANT_READ
            -3 -> -KslConst.EOF
            else -> r
        }

    public actual fun keyInitial(
        dcid: ByteArray,
        isServer: Boolean,
        direction: Int,
        version: Int,
    ): Long =
        KslNative.keyInitial(dcid, if (isServer) 1 else 0, direction, version).also {
            if (it ==
                0L
            ) {
                internal("ksl_key_initial failed (unsupported version?)")
            }
        }

    public actual fun keyNext(key: Long): Long = KslNative.keyNext(key).also { if (it == 0L) internal("ksl_key_next failed") }

    public actual fun keyFree(key: Long): Unit = KslNative.keyFree(key)

    public actual fun keyRandom(kind: Int): Long =
        KslNative.keyRandom(kind).also {
            if (it ==
                0L
            ) {
                throw KslException.Internal(KslConst.E_BAD_ARG, 0, "ksl_key_random failed (kind $kind)")
            }
        }

    public actual fun keyMac16(
        key: Long,
        input: PacketBuffer,
        offset: Int,
        length: Int,
        out: ByteArray,
        outOffset: Int,
    ) {
        if (offset < 0 || length < 0 || offset + length > input.capacity || outOffset < 0 ||
            outOffset + 16 > out.size
        ) {
            throw IndexOutOfBoundsException("mac16 $offset+$length > ${input.capacity} or out $outOffset+16 > ${out.size}")
        }
        if (KslNative.keyMac16(key, input.direct(), offset, length, out, outOffset) !=
            KslConst.OK
        ) {
            throw KslException.Internal(KslConst.E_BAD_ARG, 0, "ksl_key_mac16 failed: not a reset key?")
        }
    }

    private fun bounds(
        header: PacketBuffer,
        headerOffset: Int,
        headerLength: Int,
        payload: PacketBuffer,
        payloadOffset: Int,
        payloadLength: Int,
    ) {
        if (headerOffset < 0 || headerLength < 0 ||
            headerOffset + headerLength > header.capacity
        ) {
            throw IndexOutOfBoundsException("header $headerOffset+$headerLength > ${header.capacity}")
        }
        if (payloadOffset < 0 || payloadLength < 0 ||
            payloadOffset + payloadLength > payload.capacity
        ) {
            throw IndexOutOfBoundsException("payload $payloadOffset+$payloadLength > ${payload.capacity}")
        }
    }

    public actual fun seal(
        key: Long,
        packetNumber: Long,
        header: PacketBuffer,
        headerOffset: Int,
        headerLength: Int,
        payload: PacketBuffer,
        payloadOffset: Int,
        payloadLength: Int,
    ): Int {
        bounds(header, headerOffset, headerLength, payload, payloadOffset, payloadLength)
        return KslNative
            .seal(
                key,
                packetNumber,
                header.direct(),
                headerOffset,
                headerLength,
                payload.direct(),
                payloadOffset,
                payloadLength,
                payload.capacity - payloadOffset,
            ).also { if (it < 0) internal("seal failed: no room for the tag?") }
    }

    public actual fun open(
        key: Long,
        packetNumber: Long,
        header: PacketBuffer,
        headerOffset: Int,
        headerLength: Int,
        payload: PacketBuffer,
        payloadOffset: Int,
        payloadLength: Int,
    ): Int {
        bounds(header, headerOffset, headerLength, payload, payloadOffset, payloadLength)
        return KslNative
            .open(
                key,
                packetNumber,
                header.direct(),
                headerOffset,
                headerLength,
                payload.direct(),
                payloadOffset,
                payloadLength,
            ).also {
                if (it <
                    0
                ) {
                    throw KslException.Internal(KslConst.E_BAD_ARG, 0, "open failed: authentication tag mismatch")
                }
            }
    }

    public actual fun headerMask(
        key: Long,
        sample: PacketBuffer,
        sampleOffset: Int,
        mask: ByteArray,
    ) {
        if (mask.size < 5 || sampleOffset < 0 ||
            sampleOffset + 16 > sample.capacity
        ) {
            throw IndexOutOfBoundsException("sample $sampleOffset+16 > ${sample.capacity}")
        }
        if (KslNative.headerMask(key, sample.direct(), sampleOffset, mask) < 0) internal("header mask failed")
    }

    public actual fun retryTag(
        version: Int,
        odcid: ByteArray,
        pseudoPacket: ByteArray,
    ): ByteArray = KslNative.retryTag(version, odcid, pseudoPacket) ?: internal("retry tag failed")

    public actual fun rand(n: Int): ByteArray = KslNative.rand(n) ?: internal("RAND_bytes failed")

    public actual fun sha2(
        bits: Int,
        data: ByteArray,
    ): ByteArray = KslNative.sha2(bits, data) ?: internal("unsupported hash")

    public actual fun hkdfExpandLabel(
        hash: Int,
        secret: ByteArray,
        label: String,
        context: ByteArray,
        length: Int,
    ): ByteArray = KslNative.hkdfExpandLabel(hash, secret, label, context, length) ?: internal("hkdf failed")

    public actual fun sign(
        alg: Int,
        keyDer: ByteArray,
        message: ByteArray,
    ): ByteArray = KslNative.sign(alg, keyDer, message) ?: internal("sign failed: key does not match the algorithm")

    public actual fun verify(
        alg: Int,
        publicKeyDer: ByteArray,
        message: ByteArray,
        signature: ByteArray,
    ): Boolean =
        when (val r = KslNative.verify(alg, publicKeyDer, message, signature)) {
            1 -> true
            0 -> false
            else -> internal("verify failed: key does not match the algorithm ($r)")
        }

    public actual fun spkiSha256(certDer: ByteArray): ByteArray = KslNative.spkiSha256(certDer) ?: internal("not a certificate")

    private fun udpError(udp: Long): KslException.Internal {
        val b =
            KslNative.udpGet(udp, KslConst.UDP_GET_ERROR) ?: return KslException.Internal(KslConst.E_BAD_ARG, 0, "ksl_udp: bad arguments")
        val errno =
            ((b[0].toInt() and 0xff) shl 24) or ((b[1].toInt() and 0xff) shl 16) or ((b[2].toInt() and 0xff) shl 8) or
                (b[3].toInt() and 0xff)
        return KslException.Internal(KslConst.E_BAD_ARG, errno, if (b.size > 4) b.decodeToString(4) else "ksl_udp: closed or bad arguments")
    }

    private fun udpArgs(
        bufs: Array<PacketBuffer>,
        lens: IntArray,
        addrs: ByteArray,
        ecn: ByteArray,
        n: Int,
    ) {
        if (n < 0 || n > KslConst.UDP_MAX_BATCH || bufs.size < n || lens.size < n || addrs.size < n * KslConst.UDP_ADDR_LEN ||
            ecn.size < n
        ) {
            throw IllegalArgumentException(
                "udp batch $n with ${bufs.size} slots, ${lens.size} lens, ${addrs.size} addr bytes, ${ecn.size} marks",
            )
        }
    }

    public actual fun udpOpen(
        addr: ByteArray,
        flags: Int,
    ): Long {
        require(addr.size == KslConst.UDP_ADDR_LEN) { "address is ${KslConst.UDP_ADDR_LEN} bytes" }
        val err = IntArray(1)
        val msg = arrayOfNulls<String>(1)
        val h = KslNative.udpOpen(addr, flags, err, msg)
        if (h == 0L) throw KslException.Internal(if (err[0] == 0) KslConst.E_BAD_ARG else err[0], 0, msg[0] ?: "ksl_udp_open failed")
        return h
    }

    public actual fun udpSend(
        udp: Long,
        bufs: Array<PacketBuffer>,
        lens: IntArray,
        addrs: ByteArray,
        ecn: ByteArray,
        n: Int,
    ): Int {
        udpArgs(bufs, lens, addrs, ecn, n)
        if (n == 0) return 0
        val r = KslNative.udpSend(udp, bufs, lens, addrs, ecn, n)
        if (r < 0) throw udpError(udp)
        return r
    }

    public actual fun udpRecv(
        udp: Long,
        bufs: Array<PacketBuffer>,
        lens: IntArray,
        addrs: ByteArray,
        ecn: ByteArray,
        n: Int,
        timeoutMs: Int,
    ): Int {
        udpArgs(bufs, lens, addrs, ecn, n)
        if (n == 0) return 0
        return when (val r = KslNative.udpRecv(udp, bufs, lens, addrs, ecn, n, timeoutMs)) {
            -2 -> 0
            -1 -> -1
            else -> r
        }
    }

    public actual fun udpGet(
        udp: Long,
        what: Int,
    ): ByteArray = KslNative.udpGet(udp, what) ?: throw KslException.Internal(KslConst.E_BAD_ARG, 0, "ksl_udp_get($what) failed")

    public actual fun udpShutdown(udp: Long): Unit = KslNative.udpShutdown(udp)

    public actual fun udpClose(udp: Long): Unit = KslNative.udpClose(udp)
}
