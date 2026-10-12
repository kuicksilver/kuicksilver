// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(ExperimentalForeignApi::class)

package io.kuicksilver.native

import cnames.structs.ksl_ctx
import cnames.structs.ksl_key
import cnames.structs.ksl_pkey
import cnames.structs.ksl_session
import cnames.structs.ksl_ssl
import cnames.structs.ksl_udp
import io.kuicksilver.annotations.InternalKuicksilverApi
import io.kuicksilver.native.cinterop.*
import kotlinx.cinterop.*

@InternalKuicksilverApi
public actual object Ksl {
    // opaque (forward-declared) structs cannot be reified: interpret the raw value directly
    private fun ctx(h: Long): CPointer<ksl_ctx>? = if (h == 0L) null else interpretCPointer(nativeNullPtr + h)

    private fun ssl(h: Long): CPointer<ksl_ssl>? = if (h == 0L) null else interpretCPointer(nativeNullPtr + h)

    private fun key(h: Long): CPointer<ksl_key>? = if (h == 0L) null else interpretCPointer(nativeNullPtr + h)

    private fun udp(h: Long): CPointer<ksl_udp>? = if (h == 0L) null else interpretCPointer(nativeNullPtr + h)

    private fun CPointer<*>?.h(): Long = this?.rawValue?.toLong() ?: 0L

    private fun ctxError(c: Long): KslException.Internal =
        memScoped {
            val code = alloc<UIntVar>()
            val buf = allocArray<ByteVar>(512)
            ksl_ctx_last_error(ctx(c), code.ptr, buf, 512u)
            KslException.Internal(code.value.toInt(), 0, buf.toKString())
        }

    private fun sslError(s: Long): KslException.Internal =
        memScoped {
            val code = alloc<UIntVar>()
            val alert = alloc<IntVar>()
            val buf = allocArray<ByteVar>(512)
            ksl_ssl_last_error(ssl(s), code.ptr, alert.ptr, buf, 512u)
            KslException.Internal(code.value.toInt(), alert.value, buf.toKString())
        }

    private fun ctxCheck(
        c: Long,
        rc: Int,
    ) {
        if (rc < 0) throw ctxError(c)
    }

    private fun sslCheck(
        s: Long,
        rc: Int,
    ): Int {
        if (rc < 0) throw sslError(s)
        return rc
    }

    private fun internal(msg: String): Nothing = throw KslException.Internal(KslConst.E_NOT_SUPPORTED, 0, msg)

    private inline fun <R> ByteArray.pin(block: (CPointer<UByteVar>?, ULong) -> R): R =
        if (isEmpty()) block(null, 0u) else usePinned { block(it.addressOf(0).reinterpret(), size.toULong()) }

    public actual fun abiVersion(): Int = ksl_abi_version().toInt()

    public actual fun version(): String = ksl_version()?.toKString() ?: ""

    public actual fun ctxNew(role: Int): Long = ksl_ctx_new(role).h().also { if (it == 0L) internal("ksl_ctx_new failed") }

    public actual fun ctxFree(ctx: Long): Unit = ksl_ctx_free(ctx(ctx))

    public actual fun ctxSetAlpn(
        ctx: Long,
        wire: ByteArray,
    ): Unit = wire.pin { p, n -> ctxCheck(ctx, ksl_ctx_set_alpn(ctx(ctx), p, n)) }

    public actual fun ctxSetIdentity(
        ctx: Long,
        chainDer: List<ByteArray>,
        keyDer: ByteArray,
    ): Unit = frameDerList(chainDer).pin { c, cn -> keyDer.pin { k, kn -> ctxCheck(ctx, ksl_ctx_set_identity(ctx(ctx), c, cn, k, kn)) } }

    private fun pkey(h: Long): CPointer<ksl_pkey>? = if (h == 0L) null else interpretCPointer(nativeNullPtr + h)

    public actual fun ctxSetIdentityKey(
        ctx: Long,
        chainDer: List<ByteArray>,
        pkey: Long,
    ): Unit = frameDerList(chainDer).pin { c, cn -> ctxCheck(ctx, ksl_ctx_set_identity_pkey(ctx(ctx), c, cn, pkey(pkey))) }

    // pinned, not copied: the only key bytes are the caller's array, which the caller wipes
    public actual fun pkeyNew(der: ByteArray): Long =
        der.pin { p, n -> ksl_pkey_new(p, n) }.h().also {
            if (it ==
                0L
            ) {
                internal("not a private key")
            }
        }

    public actual fun pkeyFree(pkey: Long): Unit = ksl_pkey_free(pkey(pkey))

    public actual fun ctxSetRoots(
        ctx: Long,
        rootsDer: List<ByteArray>,
    ): Unit = frameDerList(rootsDer).pin { p, n -> ctxCheck(ctx, ksl_ctx_set_roots(ctx(ctx), p, n)) }

    public actual fun ctxSetCiphers(
        ctx: Long,
        tls13: String?,
        tls12: String?,
    ): Unit = ctxCheck(ctx, ksl_ctx_set_ciphers(ctx(ctx), tls13, tls12))

    public actual fun ctxSetTicketKeys(
        ctx: Long,
        keys: List<ByteArray>,
    ) {
        require(keys.all { it.size == 80 }) { "each ticket key is 80 bytes" }
        keys.fold(ByteArray(0)) { a, b -> a + b }.pin { p, n -> ctxCheck(ctx, ksl_ctx_set_ticket_keys(ctx(ctx), p, (n / 80u))) }
    }

    public actual fun ctxSetSessionContext(
        ctx: Long,
        sidCtx: ByteArray,
    ): Unit = sidCtx.pin { p, n -> ctxCheck(ctx, ksl_ctx_set_session_context(ctx(ctx), p, n)) }

    public actual fun ctxSetOption(
        ctx: Long,
        option: Int,
        value: Int,
    ): Unit = ctxCheck(ctx, ksl_ctx_set_option(ctx(ctx), option, value))

    public actual fun ctxFreeze(ctx: Long): Unit = ctxCheck(ctx, ksl_ctx_freeze(ctx(ctx)))

    public actual fun ctxLastError(ctx: Long): KslError = ctxError(ctx).let { KslError(it.packed, it.alert, it.message ?: "") }

    public actual fun sslNew(
        ctx: Long,
        mode: Int,
    ): Long =
        ksl_ssl_new(ctx(ctx), mode).h().also {
            if (it ==
                0L
            ) {
                internal("ksl_ssl_new failed")
            }
        }

    public actual fun sslFree(ssl: Long): Unit = ksl_ssl_free(ssl(ssl))

    public actual fun sslSet(
        ssl: Long,
        what: Int,
        data: ByteArray,
    ) {
        if (data.isEmpty()) {
            sslCheck(ssl, ksl_ssl_set(ssl(ssl), what, null, 0u))
        } else {
            data.usePinned {
                sslCheck(ssl, ksl_ssl_set(ssl(ssl), what, it.addressOf(0).reinterpret(), data.size.toULong()))
            }
        }
    }

    /** Zeroes native scratch that held secrets (keylog, exporter output) before the scope frees it. */
    private fun CPointer<UByteVar>.wipe(n: Int) {
        for (i in 0 until n) this[i] = 0u
    }

    public actual fun sslGet(
        ssl: Long,
        what: Int,
    ): ByteArray =
        memScoped {
            val len = alloc<ULongVar>()
            val small = allocArray<UByteVar>(512)
            try {
                if (ksl_ssl_get(ssl(ssl), what, small, 512u, len.ptr) ==
                    KSL_OK
                ) {
                    return small.readBytes(len.value.toInt())
                }
            } finally {
                small.wipe(512)
            }
            val need = len.value.toInt()
            if (need <= 512) throw sslError(ssl)
            val big = allocArray<UByteVar>(need)
            try {
                if (ksl_ssl_get(ssl(ssl), what, big, need.toULong(), len.ptr) !=
                    KSL_OK
                ) {
                    throw sslError(ssl)
                }
                big.readBytes(len.value.toInt())
            } finally {
                big.wipe(need)
            }
        }

    public actual fun sslPeerChain(
        ssl: Long,
        which: Int,
    ): List<ByteArray> =
        memScoped {
            val count = sslCheck(ssl, ksl_ssl_get_peer_chain(ssl(ssl), which, -1, null, 0u, null))
            List(count) { i ->
                val len = alloc<ULongVar>()
                ksl_ssl_get_peer_chain(ssl(ssl), which, i, null, 0u, len.ptr)
                val buf = allocArray<UByteVar>(len.value.toInt().coerceAtLeast(1))
                if (ksl_ssl_get_peer_chain(ssl(ssl), which, i, buf, len.value, len.ptr) !=
                    KSL_OK
                ) {
                    throw sslError(ssl)
                }
                buf.readBytes(len.value.toInt())
            }
        }

    public actual fun sslVerifyResume(
        ssl: Long,
        accept: Boolean,
        alert: Int,
    ) {
        sslCheck(ssl, ksl_ssl_verify_resume(ssl(ssl), if (accept) 1 else 0, alert))
    }

    public actual fun sslClientHello(ssl: Long): KslClientHello =
        memScoped {
            val ch = alloc<ksl_client_hello>()
            sslCheck(ssl, ksl_ssl_client_hello(ssl(ssl), ch.ptr))
            KslClientHello(
                ch.sni?.readBytes(ch.sni_len.toInt())?.decodeToString(),
                ch.alpn?.readBytes(ch.alpn_len.toInt()) ?: ByteArray(0),
                ch.sig_algs?.readBytes(ch.sig_algs_len.toInt()) ?: ByteArray(0),
            )
        }

    public actual fun sslSniResume(
        ssl: Long,
        overrideCtx: Long,
        alert: Int,
    ) {
        sslCheck(ssl, ksl_ssl_sni_resume(ssl(ssl), ctx(overrideCtx), alert))
    }

    public actual fun sslExportKeyingMaterial(
        ssl: Long,
        label: String,
        context: ByteArray?,
        length: Int,
    ): ByteArray =
        memScoped {
            val out = allocArray<UByteVar>(length)
            val lbl = label.encodeToByteArray()
            val rc =
                lbl.pin { lp, ln ->
                    if (context ==
                        null
                    ) {
                        ksl_ssl_export_keying_material(ssl(ssl), out, length.toULong(), lp?.reinterpret(), ln, null, 0u)
                    } else {
                        context.pin {
                            cp,
                            cn,
                            ->
                            ksl_ssl_export_keying_material(ssl(ssl), out, length.toULong(), lp?.reinterpret(), ln, cp, cn)
                        }
                    }
                }
            try {
                sslCheck(ssl, rc)
                out.readBytes(length)
            } finally {
                out.wipe(length)
            }
        }

    private fun session(h: Long): CPointer<ksl_session>? = if (h == 0L) null else interpretCPointer(nativeNullPtr + h)

    public actual fun sslGet1Session(ssl: Long): Long = ksl_ssl_get1_session(ssl(ssl)).h()

    public actual fun sslSetSession(
        ssl: Long,
        session: Long,
    ) {
        sslCheck(ssl, ksl_ssl_set_session(ssl(ssl), session(session)))
    }

    public actual fun sessionFree(session: Long): Unit = ksl_session_free(session(session))

    public actual fun sslNewSessionTicket(ssl: Long) {
        sslCheck(ssl, ksl_ssl_new_session_ticket(ssl(ssl)))
    }

    public actual fun sslKeyUpdate(
        ssl: Long,
        requestPeer: Boolean,
    ) {
        sslCheck(ssl, ksl_ssl_key_update(ssl(ssl), if (requestPeer) 1 else 0))
    }

    public actual fun sslLastError(ssl: Long): KslError = sslError(ssl).let { KslError(it.packed, it.alert, it.message ?: "") }

    public actual fun drive(ssl: Long): Int = sslCheck(ssl, ksl_drive(ssl(ssl)))

    public actual fun quicSetTransportParams(
        ssl: Long,
        tp: ByteArray,
    ) {
        tp.pin { p, n -> sslCheck(ssl, ksl_quic_set_transport_params(ssl(ssl), p, n)) }
    }

    public actual fun quicProvide(
        ssl: Long,
        level: Int,
        data: ByteArray,
        offset: Int,
        length: Int,
    ) {
        checkRange(data.size, offset, length, "quicProvide")
        if (length == 0) {
            sslCheck(ssl, ksl_quic_provide(ssl(ssl), level, null, 0u))
            return
        }
        data.usePinned { sslCheck(ssl, ksl_quic_provide(ssl(ssl), level, it.addressOf(offset).reinterpret(), length.toULong())) }
    }

    public actual fun quicNextEvent(
        ssl: Long,
        out: KslEvent,
    ): Boolean =
        memScoped {
            val ev = alloc<ksl_event>()
            if (ksl_quic_next_event(ssl(ssl), ev.ptr) == 0) return false
            out.type = ev.type
            out.level = ev.level
            out.direction = ev.direction
            out.aead = ev.aead
            out.key = ev.key.h()
            out.payload = ev.buf?.readBytes(ev.len.toInt()) ?: ByteArray(0)
            true
        }

    private fun rw(
        ssl: Long,
        rc: Int,
        n: ULong,
    ): Int =
        when (rc) {
            KSL_OK -> n.toInt()
            KSL_WANT_READ -> -KslConst.WANT_READ
            KSL_EOF -> -KslConst.EOF
            else -> throw sslError(ssl)
        }

    public actual fun tcpFeed(
        ssl: Long,
        data: ByteArray,
        offset: Int,
        length: Int,
    ): Int =
        memScoped {
            checkRange(data.size, offset, length, "tcpFeed")
            val used = alloc<ULongVar>()
            if (length == 0) return 0
            data.usePinned { sslCheck(ssl, ksl_tcp_feed(ssl(ssl), it.addressOf(offset).reinterpret(), length.toULong(), used.ptr)) }
            used.value.toInt()
        }

    public actual fun tcpDrain(
        ssl: Long,
        into: ByteArray,
        offset: Int,
        capacity: Int,
    ): Int =
        memScoped {
            checkRange(into.size, offset, capacity, "tcpDrain")
            val n = alloc<ULongVar>()
            if (capacity == 0) return 0
            into.usePinned { sslCheck(ssl, ksl_tcp_drain(ssl(ssl), it.addressOf(offset).reinterpret(), capacity.toULong(), n.ptr)) }
            n.value.toInt()
        }

    public actual fun tcpWrite(
        ssl: Long,
        data: ByteArray,
        offset: Int,
        length: Int,
    ): Int =
        memScoped {
            checkRange(data.size, offset, length, "tcpWrite")
            val n = alloc<ULongVar>()
            if (length == 0) return 0
            val rc = data.usePinned { ksl_tcp_write(ssl(ssl), it.addressOf(offset).reinterpret(), length.toULong(), n.ptr) }
            rw(ssl, rc, n.value)
        }

    public actual fun tcpRead(
        ssl: Long,
        into: ByteArray,
        offset: Int,
        capacity: Int,
    ): Int =
        memScoped {
            checkRange(into.size, offset, capacity, "tcpRead")
            val n = alloc<ULongVar>()
            if (capacity == 0) return 0
            val rc = into.usePinned { ksl_tcp_read(ssl(ssl), it.addressOf(offset).reinterpret(), capacity.toULong(), n.ptr) }
            rw(ssl, rc, n.value)
        }

    public actual fun tcpShutdown(ssl: Long): Int = sslCheck(ssl, ksl_tcp_shutdown(ssl(ssl)))

    public actual fun keyInitial(
        dcid: ByteArray,
        isServer: Boolean,
        direction: Int,
        version: Int,
    ): Long =
        dcid.pin { p, n -> ksl_key_initial(p, n, if (isServer) 1 else 0, direction, version.toUInt()).h() }.also {
            if (it ==
                0L
            ) {
                internal("ksl_key_initial failed (unsupported version?)")
            }
        }

    public actual fun keyNext(key: Long): Long = ksl_key_next(key(key)).h().also { if (it == 0L) internal("ksl_key_next failed") }

    public actual fun keyFree(key: Long): Unit = ksl_key_free(key(key))

    public actual fun keyRandom(kind: Int): Long =
        ksl_key_random(kind).h().also {
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
        val rc =
            out.usePinned {
                ksl_key_mac16(
                    key(key),
                    input.address() + offset,
                    length.toULong(),
                    it.addressOf(outOffset).reinterpret(),
                )
            }
        if (rc != KSL_OK) throw KslException.Internal(KslConst.E_BAD_ARG, 0, "ksl_key_mac16 failed: not a reset key?")
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
        return ksl_seal(
            key(key),
            packetNumber.toULong(),
            header.address() + headerOffset,
            headerLength.toULong(),
            payload.address() + payloadOffset,
            payloadLength.toULong(),
            (payload.capacity - payloadOffset).toULong(),
        ).also {
            if (it <
                0
            ) {
                internal("seal failed: no room for the tag?")
            }
        }
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
        return ksl_open(
            key(key),
            packetNumber.toULong(),
            header.address() + headerOffset,
            headerLength.toULong(),
            payload.address() + payloadOffset,
            payloadLength.toULong(),
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
        mask.usePinned {
            if (ksl_header_mask(key(key), sample.address() + sampleOffset, it.addressOf(0).reinterpret()) !=
                KSL_OK
            ) {
                internal("header mask failed")
            }
        }
    }

    public actual fun retryTag(
        version: Int,
        odcid: ByteArray,
        pseudoPacket: ByteArray,
    ): ByteArray =
        memScoped {
            val tag = allocArray<UByteVar>(16)
            val rc = odcid.pin { op, on -> pseudoPacket.pin { pp, pn -> ksl_retry_tag(version.toUInt(), op, on, pp, pn, tag) } }
            if (rc != KSL_OK) internal("retry tag failed")
            tag.readBytes(16)
        }

    public actual fun rand(n: Int): ByteArray =
        ByteArray(n).also { b ->
            b.pin { p, l ->
                if (ksl_rand(p, l) !=
                    KSL_OK
                ) {
                    internal("RAND_bytes failed")
                }
            }
        }

    public actual fun sha2(
        bits: Int,
        data: ByteArray,
    ): ByteArray =
        memScoped {
            if (bits != 256 && bits != 384) internal("unsupported hash")
            val out = allocArray<UByteVar>(48)
            data.pin { p, n -> if (ksl_sha2(bits, p, n, out) != KSL_OK) internal("hash failed") }
            out.readBytes(bits / 8)
        }

    public actual fun hkdfExpandLabel(
        hash: Int,
        secret: ByteArray,
        label: String,
        context: ByteArray,
        length: Int,
    ): ByteArray =
        memScoped {
            val out = allocArray<UByteVar>(length)
            val rc =
                secret.pin {
                    sp,
                    sn,
                    ->
                    context.pin { cp, cn -> ksl_hkdf_expand_label(hash, sp, sn, label, cp, cn, out, length.toULong()) }
                }
            try {
                if (rc != KSL_OK) internal("hkdf failed")
                out.readBytes(length)
            } finally {
                out.wipe(length)
            }
        }

    public actual fun sign(
        alg: Int,
        keyDer: ByteArray,
        message: ByteArray,
    ): ByteArray =
        memScoped {
            val sig = allocArray<UByteVar>(512)
            val sl = alloc<ULongVar>()
            sl.value = 512u
            val rc = keyDer.pin { kp, kn -> message.pin { mp, mn -> ksl_sign(alg, kp, kn, mp, mn, sig, sl.ptr) } }
            if (rc != KSL_OK) internal("sign failed: key does not match the algorithm")
            sig.readBytes(sl.value.toInt())
        }

    public actual fun verify(
        alg: Int,
        publicKeyDer: ByteArray,
        message: ByteArray,
        signature: ByteArray,
    ): Boolean {
        val r = publicKeyDer.pin { pp, pn -> message.pin { mp, mn -> signature.pin { sp, sn -> ksl_verify(alg, pp, pn, mp, mn, sp, sn) } } }
        return when (r) {
            1 -> true
            0 -> false
            else -> internal("verify failed: key does not match the algorithm")
        }
    }

    public actual fun spkiSha256(certDer: ByteArray): ByteArray =
        memScoped {
            val out = allocArray<UByteVar>(32)
            certDer.pin { p, n ->
                if (ksl_spki_sha256(p, n, out) !=
                    KSL_OK
                ) {
                    internal("not a certificate")
                }
            }
            out.readBytes(32)
        }

    private fun udpError(udp: Long): KslException.Internal {
        val b =
            runCatching { udpGet(udp, KslConst.UDP_GET_ERROR) }.getOrNull()
                ?: return KslException.Internal(KslConst.E_BAD_ARG, 0, "ksl_udp: bad arguments")
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
        return memScoped {
            val err = alloc<UIntVar>()
            val buf = allocArray<ByteVar>(512)
            val h = addr.usePinned { ksl_udp_open(it.addressOf(0).reinterpret(), flags, err.ptr, buf, 512u) }.h()
            if (h == 0L) throw KslException.Internal(if (err.value == 0u) KslConst.E_BAD_ARG else err.value.toInt(), 0, buf.toKString())
            h
        }
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
        return memScoped {
            val ptrs = allocArray<CPointerVar<UByteVar>>(n)
            val ul = allocArray<UIntVar>(n)
            val sent = alloc<UIntVar>()
            for (i in 0 until n) {
                if (lens[i] < 0 ||
                    lens[i] > bufs[i].capacity
                ) {
                    throw IndexOutOfBoundsException("slot $i: ${lens[i]} > ${bufs[i].capacity}")
                }
                ptrs[i] =
                    bufs[i].address()
                ul[i] = lens[i].toUInt()
            }
            val rc =
                addrs.usePinned { a ->
                    ecn.usePinned { e ->
                        ksl_udp_send(udp(udp), ptrs, ul, a.addressOf(0).reinterpret(), e.addressOf(0).reinterpret(), n.toUInt(), sent.ptr)
                    }
                }
            if (rc != KSL_OK) throw udpError(udp)
            sent.value.toInt()
        }
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
        return memScoped {
            val ptrs = allocArray<CPointerVar<UByteVar>>(n)
            val caps = allocArray<UIntVar>(n)
            val ul = allocArray<UIntVar>(n)
            val got = alloc<UIntVar>()
            for (i in 0 until n) {
                ptrs[i] = bufs[i].address()
                caps[i] = bufs[i].capacity.toUInt()
            }
            val rc =
                addrs.usePinned { a ->
                    ecn.usePinned { e ->
                        ksl_udp_recv(
                            udp(udp),
                            ptrs,
                            caps,
                            ul,
                            a.addressOf(0).reinterpret(),
                            e.addressOf(0).reinterpret(),
                            n.toUInt(),
                            got.ptr,
                            timeoutMs,
                        )
                    }
                }
            when (rc) {
                KSL_WANT_READ -> {
                    0
                }

                KSL_OK -> {
                    for (i in 0 until got.value.toInt()) lens[i] = ul[i].toInt()
                    got.value.toInt()
                }

                else -> {
                    -1
                }
            }
        }
    }

    public actual fun udpGet(
        udp: Long,
        what: Int,
    ): ByteArray =
        memScoped {
            val out = allocArray<UByteVar>(300)
            val n = alloc<ULongVar>()
            if (ksl_udp_get(udp(udp), what, out, 300u, n.ptr) !=
                KSL_OK
            ) {
                throw KslException.Internal(KslConst.E_BAD_ARG, 0, "ksl_udp_get($what) failed")
            }
            ByteArray(n.value.toInt()) { out[it].toByte() }
        }

    public actual fun udpShutdown(udp: Long): Unit = ksl_udp_shutdown(udp(udp))

    public actual fun udpClose(udp: Long): Unit = ksl_udp_close(udp(udp))
}
