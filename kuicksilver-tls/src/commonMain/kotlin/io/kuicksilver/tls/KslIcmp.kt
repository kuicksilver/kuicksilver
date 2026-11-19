// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.tls

import io.kuicksilver.annotations.InternalKuicksilverApi
import io.kuicksilver.native.Ksl
import io.kuicksilver.native.KslConst
import io.kuicksilver.native.KslLoader

/**
 * The `ksl_icmp_*` functions for kuicksilver-quic, which imports nothing of kuicksilver-native but buffers (ADR-0004): the
 * ICMP Packet Too Big of a CONNECT-UDP proxy (RFC 9298 section 6.1). Addresses are `ksl` addresses (family, port, 16
 * address bytes, pad).
 */
@InternalKuicksilverApi
public object KslIcmp {
    /** The largest message [ptbBuild] writes. */
    public val PTB_MAX: Int get() = KslConst.ICMP_PTB_MAX

    /** The length of a `ksl` address. */
    public val ADDR_LEN: Int get() = KslConst.UDP_ADDR_LEN

    /** The error [open] reports where no raw socket is offered (not Linux or Android). */
    public val E_NOT_SUPPORTED: Int get() = KslConst.E_NOT_SUPPORTED

    /** Loads the native library; throws when it cannot be. */
    public fun ensureLoaded(): Unit = KslLoader.ensureLoaded()

    public fun ptbBuild(
        out: ByteArray,
        target: ByteArray,
        local: ByteArray,
        payload: ByteArray,
        len: Int,
        mtu: Int,
    ): Int = Ksl.icmpPtbBuild(out, target, local, payload, len, mtu)

    public fun open(
        family: Int,
        err: IntArray,
    ): Int = Ksl.icmpOpen(family, err)

    public fun send(
        fd: Int,
        msg: ByteArray,
        len: Int,
        target: ByteArray,
        local: ByteArray,
    ): Boolean = Ksl.icmpSend(fd, msg, len, target, local)

    public fun close(fd: Int): Unit = Ksl.icmpClose(fd)
}
