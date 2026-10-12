// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.endpoint

import io.ktor.network.sockets.InetSocketAddress
import io.kuicksilver.native.PacketBuffer
import io.kuicksilver.quic.TimeMark
import io.kuicksilver.quic.core.AddressClass
import io.kuicksilver.quic.wire.ConnectionId
import io.kuicksilver.tls.QuicCrypto
import io.kuicksilver.tls.TokenKey
import kotlin.random.Random
import kotlin.time.Duration
import kotlin.time.Duration.Companion.hours
import kotlin.time.Duration.Companion.seconds

/** What a token in a client Initial turned out to be. */
internal sealed interface TokenCheck {
    object Absent : TokenCheck

    /** Not one of our Retry tokens (another type byte): ignored, the address stays unvalidated (RFC 9000 section 8.1.3). */
    object NotRetry : TokenCheck

    object Invalid : TokenCheck

    object Expired : TokenCheck

    /** Our token: the client's original Destination Connection ID and the Source Connection ID of the Retry that carried it. */
    class Valid(
        val odcid: ConnectionId,
        val retryScid: ConnectionId,
    ) : TokenCheck
}

/**
 * Retry tokens (RFC 9000 section 8.1.4): `type 0x01 | nonce(8) | AEAD(issuedAt(8) | odcidLen(1) | odcid | scidLen(1) | scid)`
 * under a [TokenKey] that lives inside ksl, with the client's address, port and the QUIC version as associated data. The Retry
 * SCID binds the token to the one Initial that may carry it (section 8.1.3: the server checks it against the Destination
 * Connection ID). Keys rotate every [rotateEvery]; the previous key still checks. A token is checked by the process that minted
 * it (process time).
 */
internal class RetryTokens(
    private val crypto: QuicCrypto,
    private val random: Random,
    private val lifetime: Duration = 10.seconds,
    private val rotateEvery: Duration = 1.hours,
) : AutoCloseable {
    private var current: TokenKey = crypto.newTokenKey()
    private var previous: TokenKey? = null
    private var currentSince: TimeMark = TimeMark.NEVER

    private fun rotate(now: TimeMark) {
        if (currentSince == TimeMark.NEVER) {
            currentSince = now
            return
        }
        if (now - currentSince < rotateEvery) return
        previous?.close()
        previous = current
        current = crypto.newTokenKey()
        currentSince = now
    }

    private fun aad(
        client: InetSocketAddress,
        version: Int,
    ): ByteArray {
        val ip = AddressClass.ipBytes(client)
        val out = ByteArray(1 + ip.size + 2 + 4)
        out[0] = TYPE
        ip.copyInto(out, 1)
        out[1 + ip.size] = (client.port ushr 8).toByte()
        out[
            2 +
                ip.size,
        ] =
            client.port.toByte()
        for (i in 0 until 4) out[3 + ip.size + i] = (version ushr (8 * (3 - i))).toByte()
        return out
    }

    fun mint(
        odcid: ConnectionId,
        retryScid: ConnectionId,
        client: InetSocketAddress,
        version: Int,
        now: TimeMark,
    ): ByteArray {
        rotate(now)
        val nonce = random.nextLong()
        val plain = ByteArray(8 + 1 + odcid.length + 1 + retryScid.length)
        for (i in 0 until 8) plain[i] = (now.nanos ushr (8 * (7 - i))).toByte()
        plain[8] =
            odcid.length.toByte()
        odcid.copyToArray(plain, 9)
        plain[9 + odcid.length] = retryScid.length.toByte()
        retryScid.copyToArray(plain, 10 + odcid.length)
        val sealed = current.seal(nonce, aad(client, version), plain)
        val token = ByteArray(1 + 8 + sealed.size)
        token[0] = TYPE
        for (i in 0 until 8) token[1 + i] = (nonce ushr (8 * (7 - i))).toByte()
        sealed.copyInto(token, 9)
        return token
    }

    fun check(
        token: PacketBuffer,
        off: Int,
        len: Int,
        client: InetSocketAddress,
        version: Int,
        now: TimeMark,
    ): TokenCheck {
        if (len == 0) return TokenCheck.Absent
        if (token[off] != TYPE) return TokenCheck.NotRetry
        if (len < 1 + 8 + 16 + 10) return TokenCheck.Invalid
        rotate(now)
        var nonce = 0L
        for (i in 0 until 8) nonce = (nonce shl 8) or (token[off + 1 + i].toLong() and 0xff)
        val sealed = ByteArray(len - 9)
        token.copyTo(sealed, off + 9, 0, sealed.size)
        val a = aad(client, version)
        val plain = current.open(nonce, a, sealed) ?: previous?.open(nonce, a, sealed) ?: return TokenCheck.Invalid
        if (plain.size < 10) return TokenCheck.Invalid
        var issued = 0L
        for (i in 0 until 8) issued = (issued shl 8) or (plain[i].toLong() and 0xff)
        val odcidLen = plain[8].toInt() and 0xff
        if (odcidLen > 20 || plain.size < 10 + odcidLen) return TokenCheck.Invalid
        val scidLen = plain[9 + odcidLen].toInt() and 0xff
        if (scidLen > 20 || plain.size != 10 + odcidLen + scidLen) return TokenCheck.Invalid
        if (now.nanos - issued > lifetime.inWholeNanoseconds || now.nanos < issued) return TokenCheck.Expired
        val scidOff = 10 + odcidLen
        return TokenCheck.Valid(ConnectionId(plain.copyOfRange(9, 9 + odcidLen)), ConnectionId(plain.copyOfRange(scidOff, scidOff + scidLen)))
    }

    override fun close() {
        current.close()
        previous?.close()
        previous = null
    }

    private companion object {
        const val TYPE: Byte = 0x01
    }
}
