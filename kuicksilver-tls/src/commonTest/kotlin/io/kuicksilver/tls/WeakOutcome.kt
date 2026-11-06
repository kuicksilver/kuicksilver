// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(InternalKuicksilverApi::class)

package io.kuicksilver.tls

import io.kuicksilver.annotations.InternalKuicksilverApi
import io.kuicksilver.native.Ksl
import io.kuicksilver.native.KslConst
import io.kuicksilver.native.KslEvent

/** How a [weakHandshake] ended: its last drive result, whether the client paused for trust, whether both sides finished. */
internal class WeakOutcome(
    val result: DriveResult,
    val paused: Boolean,
    val done: Boolean,
)

/**
 * A handshake of a real client session against a raw `ksl` server at security level 0 (at the default level 2 OpenSSL
 * refuses to load a weak key as its own identity). A pause is answered with [verdict], by default the platform's yes, so
 * that only `ksl`'s own checks can refuse the chain. The certificates come from `tools/certs/gen-weak-certs.sh`.
 */
internal fun weakHandshake(
    client: TlsConfig,
    chain: List<ByteArray>,
    key: ByteArray,
    verdict: (QuicTlsSession, List<Certificate>) -> VerifyResult = { _, presented -> VerifyResult.Accepted(presented) },
): WeakOutcome {
    val sc = Ksl.ctxNew(KslConst.SERVER)
    var s = 0L
    val c = KslQuicCrypto.newSession(client)
    val keys = ArrayList<Long>()
    val protectors = ArrayList<PacketProtector>()
    try {
        Ksl.ctxSetAlpn(sc, byteArrayOf(2, 'h'.code.toByte(), '3'.code.toByte()))
        Ksl.ctxSetCiphers(sc, null, "@SECLEVEL=0:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256")
        Ksl.ctxSetIdentity(sc, chain, key.copyOf())
        s = Ksl.sslNew(sc, KslConst.MODE_QUIC)
        Ksl.quicSetTransportParams(s, Fixtures.tp)
        c.setTransportParameters(Fixtures.tp)
        val ev = KslEvent()
        var paused = false
        var clientDone = false
        var serverDone = false
        var last: DriveResult = DriveResult.WantRead
        repeat(40) {
            last = c.drive()
            val want = last
            if (want is DriveResult.WantVerify) {
                paused = true
                c.resumeVerify(verdict(c, want.chain))
                last = c.drive()
            }
            while (true) {
                when (val e = c.nextEvent() ?: break) {
                    is TlsEvent.CryptoData -> {
                        Ksl.quicProvide(s, e.level.ksl, e.data, 0, e.data.size)
                    }

                    is TlsEvent.Keys -> {
                        protectors += e.protector
                    }

                    TlsEvent.HandshakeDone -> {
                        clientDone = true
                    }

                    else -> {}
                }
            }
            if (last is DriveResult.Failed) return WeakOutcome(last, paused, false)
            Ksl.drive(s)
            while (Ksl.quicNextEvent(s, ev)) {
                when (ev.type) {
                    KslConst.EV_CRYPTO_SEND -> c.provide(EncryptionLevel.entries.first { it.ksl == ev.level }, ev.payload)
                    KslConst.EV_KEY -> keys += ev.key
                    KslConst.EV_HANDSHAKE_DONE -> serverDone = true
                }
            }
            if (clientDone && serverDone) return WeakOutcome(last, paused, true)
        }
        return WeakOutcome(last, paused, clientDone && serverDone)
    } finally {
        protectors.forEach { it.close() }
        keys.forEach(Ksl::keyFree)
        c.close()
        if (s != 0L) Ksl.sslFree(s)
        Ksl.ctxFree(sc)
    }
}
