// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.client.h1

import io.ktor.utils.io.ByteReadChannel
import io.ktor.utils.io.ByteWriteChannel
import io.ktor.utils.io.readByte
import io.ktor.utils.io.readFully
import io.ktor.utils.io.writeFully
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.ktor.client.ProxyCredentials
import io.kuicksilver.ktor.client.ProxyException

/** The destination of a SOCKS5 CONNECT: a name the proxy resolves (ATYP 3), or an IPv4 or IPv6 address (ATYP 1, 4). */
internal sealed interface Socks5Target {
    class Domain(
        val name: String,
    ) : Socks5Target

    class Address(
        val bytes: ByteArray,
    ) : Socks5Target {
        init {
            require(bytes.size == 4 || bytes.size == 16) { "an IP address has 4 or 16 bytes" }
        }
    }
}

private const val VERSION: Byte = 5
private const val NO_AUTH: Byte = 0
private const val USER_PASS: Byte = 2
private const val NO_ACCEPTABLE: Byte = 0xFF.toByte()
private const val AUTH_VERSION: Byte = 1
private const val CMD_CONNECT: Byte = 1

/**
 * Opens a SOCKS5 CONNECT to [target]:[port] through the proxy at the other end of [input]/[output] (RFC 1928 sections
 * 3–6): the method negotiation, then username/password authentication (RFC 1929) only when the proxy picks it and only
 * if [credentials] were offered, then the request; afterwards the channels carry the connection to the destination.
 * Every read has a fixed bound (the longest is a 255-byte bound name); the caller's connect timeout bounds the wait.
 *
 * Fails with [ProxyException] when the proxy offers no method we proposed, rejects the credentials, answers with a reply
 * other than "succeeded" (its REP field as [ProxyException.replyCode]) or with a malformed reply, and with an
 * IllegalArgumentException, before anything is sent, for a user name, password or destination name longer than 255
 * bytes or an empty user name. [proxy] names the proxy in messages; the credentials never appear in them.
 */
@OptIn(ExperimentalKuicksilverApi::class)
internal suspend fun socks5Connect(
    input: ByteReadChannel,
    output: ByteWriteChannel,
    target: Socks5Target,
    port: Int,
    credentials: ProxyCredentials?,
    proxy: String,
) {
    require(port in 0..0xffff) { "port out of range: $port" }
    val user = credentials?.user?.encodeToByteArray()
    val password = credentials?.password?.encodeToByteArray()
    if (user != null) require(user.size in 1..255) { "a SOCKS5 user name has 1 to 255 bytes (RFC 1929)" }
    if (password != null) require(password.size <= 255) { "a SOCKS5 password has at most 255 bytes (RFC 1929)" }
    val name = (target as? Socks5Target.Domain)?.name?.encodeToByteArray()
    if (name != null) require(name.size in 1..255) { "a SOCKS5 destination name has 1 to 255 bytes (RFC 1928 section 5)" }

    // method negotiation (section 3): username/password only when there is something to send
    output.writeFully(if (user != null) byteArrayOf(VERSION, 2, NO_AUTH, USER_PASS) else byteArrayOf(VERSION, 1, NO_AUTH))
    output.flush()
    if (input.readByte() != VERSION) throw ProxyException("$proxy is not a SOCKS5 proxy", null)
    when (input.readByte()) {
        NO_AUTH -> {}

        USER_PASS -> {
            if (user == null || password == null) throw ProxyException("$proxy chose a method that was not offered", null)
            // RFC 1929 section 2: the credentials travel in clear to the proxy (section 5)
            output.writeFully(byteArrayOf(AUTH_VERSION, user.size.toByte()) + user + byteArrayOf(password.size.toByte()) + password)
            output.flush()
            val v = input.readByte()
            val status = input.readByte()
            // RFC 1929 says version 1; some proxies answer with the SOCKS version 5, which curl tolerates too
            if (v != AUTH_VERSION && v != VERSION) throw ProxyException("$proxy answered the authentication with version $v", null)
            if (status != 0.toByte()) throw ProxyException("$proxy rejected the credentials", null)
        }

        NO_ACCEPTABLE -> {
            throw ProxyException(
                "$proxy accepts no acceptable authentication method (offered: none${if (user != null) ", username/password" else ""})",
                null,
            )
        }

        else -> {
            throw ProxyException("$proxy chose a method that was not offered", null)
        }
    }

    // the request (section 4)
    val address =
        when (target) {
            is Socks5Target.Domain -> byteArrayOf(3, name!!.size.toByte()) + name
            is Socks5Target.Address -> byteArrayOf(if (target.bytes.size == 4) 1 else 4) + target.bytes
        }
    output.writeFully(byteArrayOf(VERSION, CMD_CONNECT, 0) + address + byteArrayOf((port shr 8).toByte(), port.toByte()))
    output.flush()

    // the reply (section 6): the bound address is read and dropped
    val head = ByteArray(4)
    input.readFully(head)
    if (head[0] != VERSION) throw ProxyException("$proxy sent a reply that is not SOCKS5", null)
    val rep = head[1].toInt() and 0xff
    if (rep != 0) throw ProxyException("$proxy failed the CONNECT: ${replyText(rep)} (SOCKS5 reply $rep)", rep)
    val boundLength =
        when (head[3].toInt()) {
            1 -> 4
            4 -> 16
            3 -> input.readByte().toInt() and 0xff
            else -> throw ProxyException("$proxy replied with an unknown address type ${head[3].toInt() and 0xff}", null)
        }
    input.readFully(ByteArray(boundLength + 2))
}

/** The REP field's meaning (RFC 1928 section 6). */
private fun replyText(rep: Int): String =
    when (rep) {
        1 -> "general SOCKS server failure"
        2 -> "connection not allowed by ruleset"
        3 -> "network unreachable"
        4 -> "host unreachable"
        5 -> "connection refused"
        6 -> "TTL expired"
        7 -> "command not supported"
        8 -> "address type not supported"
        else -> "unassigned reply"
    }
