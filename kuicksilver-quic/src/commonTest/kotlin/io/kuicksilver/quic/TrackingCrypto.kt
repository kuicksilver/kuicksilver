// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic

import io.kuicksilver.annotations.DelicateKuicksilverApi
import io.kuicksilver.annotations.InternalKuicksilverApi
import io.kuicksilver.tls.QuicCrypto
import io.kuicksilver.tls.ResetKey
import io.kuicksilver.tls.TokenKey

/**
 * [NullCryptoProvider] that counts the reset and token keys it hands out and those closed again ([live] is the difference), and
 * that fails on request: the keys stand for the native ones a real provider makes, so a key never closed is a leak.
 */
@OptIn(DelicateKuicksilverApi::class, InternalKuicksilverApi::class)
internal class TrackingCrypto(
    var failResetKey: Boolean = false,
    var failTokenKey: Boolean = false,
) : QuicCrypto by NullCryptoProvider {
    var made = 0
        private set
    var closed = 0
        private set
    val live: Int get() = made - closed

    override fun newResetKey(): ResetKey {
        if (failResetKey) throw IllegalStateException("reset key refused (test)")
        val k = NullCryptoProvider.newResetKey()
        made++
        return object : ResetKey by k {
            private var done = false

            override fun close() {
                if (!done) closed++
                done = true
                k.close()
            }
        }
    }

    override fun newTokenKey(): TokenKey {
        if (failTokenKey) throw IllegalStateException("token key refused (test)")
        val k = NullCryptoProvider.newTokenKey()
        made++
        return object : TokenKey by k {
            private var done = false

            override fun close() {
                if (!done) closed++
                done = true
                k.close()
            }
        }
    }
}
