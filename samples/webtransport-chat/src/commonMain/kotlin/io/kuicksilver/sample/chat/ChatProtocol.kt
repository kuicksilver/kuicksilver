// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.sample.chat

/**
 * The chat protocol over one WebTransport session per member.
 *
 * - **Messages and membership go on a bidirectional stream** the client opens first: reliable and in order, text lines.
 *   Client to server: `HELLO <name>`, then `MSG <text>` lines, `BYE` to leave. Server to client: `WELCOME <name> <members>`
 *   (a comma-separated list, the new member included), then `JOIN <name>`, `LEAVE <name>` and `MSG <name> <text>`
 *   (the sender's own messages too: the room's order is the server's order). A refusal or a violation closes the
 *   session with one of the `CLOSE_*` codes and a reason (`name-taken`, `hello`): WT_CLOSE_SESSION is the message a
 *   client is sure to get, where bytes on a stream the close resets may be lost.
 * - **Typing indicators go as datagrams**: the client sends `TYPING` while its user types, the server sends
 *   `TYPING <name>` to the other members. One that is lost does not matter, the next one comes a moment later, and a
 *   datagram never waits behind a long message on a stream.
 */
object ChatProtocol {
    /** The WebTransport path the server serves. */
    const val PATH: String = "/chat"

    /** The application protocol both sides offer (`WT-Available-Protocols`, the server picks it). */
    const val WT_PROTOCOL: String = "chat-v1"

    /** The name the sample certificate carries besides `localhost`, `127.0.0.1` and `::1`. */
    const val SERVER_NAME: String = "chat.test"

    /** Longest line either side reads (bytes, without the line break): lines come from the network, never trust them. */
    const val MAX_LINE: Long = 1024

    /** How long the server waits for a new session's stream and its HELLO line. */
    const val HELLO_TIMEOUT_MS: Long = 10_000

    /** Members a room takes; one more is refused with [CLOSE_ROOM_FULL]. It also bounds the WELCOME line. */
    const val MAX_MEMBERS: Int = 25

    /**
     * Longest line a client reads from the server: `MSG <name> <text>` (a name of 32, the member's text of at most
     * [MAX_LINE] - 4 bytes), or `WELCOME <name> <members>` with [MAX_MEMBERS] names of 32 and their commas.
     */
    const val MAX_SERVER_LINE: Long = MAX_LINE + 64

    /** Lines queued for one member before the server drops it as too slow: one slow reader never holds the room. */
    const val OUTBOX: Int = 256

    /** The shortest gap between two typing datagrams the server relays from one member: a flood is not multiplied. */
    const val TYPING_INTERVAL_MS: Long = 250

    /** Session close codes (WT_CLOSE_SESSION, 0..2^32-1). 1 is the Ktor route's own: its handler threw. */
    const val CLOSE_OK: Long = 0
    const val CLOSE_PROTOCOL: Long = 0x10
    const val CLOSE_NAME_TAKEN: Long = 0x11
    const val CLOSE_LINE_TOO_LONG: Long = 0x12
    const val CLOSE_TOO_SLOW: Long = 0x13
    const val CLOSE_ROOM_FULL: Long = 0x14

    init {
        // the WELCOME line with a full room of the longest names must fit what a client reads
        check("WELCOME ".length + 32 + 1 + MAX_MEMBERS * 33 <= MAX_SERVER_LINE) { "MAX_SERVER_LINE is too small for MAX_MEMBERS" }
    }

    /** The typing datagram a client sends. */
    val TYPING: ByteArray = "TYPING".encodeToByteArray()

    private val nameRule = Regex("[A-Za-z0-9_-]{1,32}")

    /** A member name: 1 to 32 letters, digits, `_` or `-`, so that it never contains the separators of the lines. */
    fun isValidName(name: String): Boolean = nameRule.matches(name)

    /** A message as one line: line breaks become spaces, the rest is the user's. */
    fun oneLine(text: String): String = text.replace('\r', ' ').replace('\n', ' ')

    /**
     * What the server relays of a member's text: control characters (C0, DEL, C1) become `?`, so that no member can send
     * a terminal escape sequence to the others' consoles, or anything else that is not text.
     */
    fun printable(text: String): String = text.map { if (it < ' ' || it in '\u007f'..'\u009f') '?' else it }.joinToString("")
}

/** What a member sees happen in the room. */
sealed interface ChatEvent {
    /** [from] said [text]. */
    data class Message(val from: String, val text: String) : ChatEvent

    /** [name] entered the room. */
    data class Joined(val name: String) : ChatEvent

    /** [name] left the room (said BYE, closed its session, or its connection went away). */
    data class Left(val name: String) : ChatEvent

    /** [name] is typing (a datagram: may be lost, may come more than once). */
    data class Typing(val name: String) : ChatEvent

    /** The server is shutting down and asked the session to wind down (WT_DRAIN_SESSION or an HTTP/3 GOAWAY). */
    data object ServerDraining : ChatEvent
}

/** The server's answer to a line it reads from a client: null for anything malformed (lines come from the network). */
internal fun parseServerLine(line: String): ChatEvent? {
    val sp = line.indexOf(' ')
    if (sp <= 0) return null
    val verb = line.substring(0, sp)
    val rest = line.substring(sp + 1)
    return when (verb) {
        "JOIN" -> rest.takeIf(ChatProtocol::isValidName)?.let { ChatEvent.Joined(it) }
        "LEAVE" -> rest.takeIf(ChatProtocol::isValidName)?.let { ChatEvent.Left(it) }
        "MSG" -> {
            val at = rest.indexOf(' ')
            val from = if (at <= 0) null else rest.substring(0, at).takeIf(ChatProtocol::isValidName)
            from?.let { ChatEvent.Message(it, ChatProtocol.printable(rest.substring(at + 1))) } // the server's text is untrusted too
        }
        else -> null
    }
}
