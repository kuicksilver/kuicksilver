// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.client

import io.ktor.http.websocket.websocketServerAccept
import io.ktor.utils.io.ByteReadChannel
import io.ktor.utils.io.LineEnding
import io.ktor.utils.io.readLine

/** The fake WebSocket servers' half of the opening handshake (RFC 6455 section 4.2.2). */

/** Reads an HTTP/1.1 request head to its empty line and returns its `Sec-WebSocket-Key`, or null when it has none. */
internal suspend fun ByteReadChannel.readWebSocketKey(): String? = readRequestHead()[HEADER_KEY]?.single()

/** Reads an HTTP/1.1 request head to its empty line: its fields by lower-case name (the request line is left out). */
internal suspend fun ByteReadChannel.readRequestHead(): Map<String, List<String>> {
    val fields = LinkedHashMap<String, MutableList<String>>()
    readLine(LineEnding.Lenient) ?: return fields
    while (true) {
        val line = readLine(LineEnding.Lenient) ?: break
        if (line.isEmpty()) break
        val colon = line.indexOf(':')
        if (colon > 0) fields.getOrPut(line.substring(0, colon).trim().lowercase()) { ArrayList() } += line.substring(colon + 1).trim()
    }
    return fields
}

/** A 101 that accepts the handshake of [key], with [fields] (each a whole line with its CRLF) after the required ones. */
internal fun switchingProtocols(
    key: String?,
    fields: String = "",
): String =
    "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n" +
        "Sec-WebSocket-Accept: ${websocketServerAccept(checkNotNull(key) { "the request has no Sec-WebSocket-Key" })}\r\n$fields\r\n"

private const val HEADER_KEY = "sec-websocket-key"
