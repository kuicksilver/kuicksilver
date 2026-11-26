// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.sample.chat

import io.ktor.client.HttpClient
import io.ktor.utils.io.charsets.TooLongLineException
import io.ktor.utils.io.readLineStrict
import io.ktor.utils.io.writeStringUtf8
import io.kuicksilver.http3.WebTransportBidiStream
import io.kuicksilver.http3.WebTransportCloseInfo
import io.kuicksilver.http3.WebTransportException
import io.kuicksilver.http3.WebTransportSession
import io.kuicksilver.ktor.client.webTransport
import io.kuicksilver.quic.DatagramSendResult
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Deferred
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.channelFlow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull

/**
 * The server did not let this member in: it closed the session before WELCOME with [code] and [reason] (`name-taken`,
 * `hello`; see [ChatProtocol]), or it does not speak the chat protocol.
 */
class ChatRefusedException(val code: Long?, val reason: String) : Exception("the chat server refused: $reason")

/**
 * A member of the room, in common code: the same class serves the JVM console client, an Android app and an iOS app
 * (any target of `kuicksilver-ktor-client`). Join with [join], collect [events] once, [say] and [typing] meanwhile, and
 * [leave] at the end.
 */
class ChatClient private constructor(
    private val session: WebTransportSession,
    private val stream: WebTransportBidiStream,
    /** This member's name. */
    val name: String,
    /** Who was in the room when this member joined (this member last). */
    val members: List<String>,
) {
    private val writeLock = Mutex()

    /** How the session ended: the server's code and reason (see [ChatProtocol]), or the cause. */
    val closed: Deferred<WebTransportCloseInfo> get() = session.closed

    /**
     * The room's events until the server's stream ends (after [leave], or when the server closes the session): messages,
     * joins and leaves from the stream, typing from the datagrams, and [ChatEvent.ServerDraining] once the server asks the
     * session to wind down. Collect it once.
     */
    val events: Flow<ChatEvent> =
        channelFlow {
            coroutineScope {
                val typing =
                    launch {
                        try {
                            while (true) {
                                val text = session.receiveDatagram().decodeToString()
                                val who = text.removePrefix("TYPING ")
                                if (text.startsWith("TYPING ") && ChatProtocol.isValidName(who)) send(ChatEvent.Typing(who))
                            }
                        } catch (e: CancellationException) {
                            throw e
                        } catch (e: Exception) { // the session is over
                        }
                    }
                val draining = launch { session.drainRequested.first { it }; send(ChatEvent.ServerDraining) }
                try {
                    while (true) {
                        val line = stream.input.readLineStrict(ChatProtocol.MAX_SERVER_LINE) ?: break
                        parseServerLine(line)?.let { send(it) }
                    }
                } catch (e: CancellationException) {
                    throw e
                } catch (e: Exception) { // the session was closed under the stream: [closed] says how
                }
                typing.cancel()
                draining.cancel()
            }
        }

    /** Sends [text] to the room (line breaks become spaces); it comes back in [events] in the room's order. */
    suspend fun say(text: String) {
        val line = ChatProtocol.oneLine(text)
        require(line.encodeToByteArray().size <= ChatProtocol.MAX_LINE - 4) { "a message is at most ${ChatProtocol.MAX_LINE - 4} bytes" }
        writeLock.withLock {
            stream.output.writeStringUtf8("MSG $line\n")
            stream.output.flush()
        }
    }

    /**
     * Tells the others this member is typing: one datagram, never waited for and never retransmitted. Call it as the user
     * types; the server relays at most one per [ChatProtocol.TYPING_INTERVAL_MS].
     */
    fun typing(): DatagramSendResult = session.trySendDatagram(ChatProtocol.TYPING)

    /**
     * Says BYE and waits (at most five seconds) for the server to close the session, which ends [events] after the lines
     * still on their way; closes the session itself when the server does not.
     */
    suspend fun leave() {
        try {
            writeLock.withLock {
                stream.output.writeStringUtf8("BYE\n")
                stream.output.flushAndClose()
            }
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) { // already closed
        }
        if (withTimeoutOrNull(LEAVE_TIMEOUT_MS) { session.closed.await() } == null) session.close(ChatProtocol.CLOSE_OK, "bye")
    }

    companion object {
        private const val LEAVE_TIMEOUT_MS: Long = 5_000
        private const val NO_WELCOME: String = "no WELCOME within ${ChatProtocol.HELLO_TIMEOUT_MS / 1000} s"

        /** A line read, or the stream's end (null): kept apart from withTimeoutOrNull's null. */
        private class Read(val line: String?)

        /**
         * Opens a WebTransport session to [url] (`https://host:port/chat`) on [http], which must use the Kuicksilver engine,
         * and joins as [name]. Throws [ChatRefusedException] when the server refuses the member (a taken name, a full room),
         * or sends no WELCOME within [ChatProtocol.HELLO_TIMEOUT_MS].
         */
        suspend fun join(http: HttpClient, url: String, name: String): ChatClient {
            require(ChatProtocol.isValidName(name)) { "a name is 1 to 32 letters, digits, '_' or '-'" }
            val session = http.webTransport(url, protocols = listOf(ChatProtocol.WT_PROTOCOL))
            try {
                if (session.protocol != ChatProtocol.WT_PROTOCOL) throw ChatRefusedException(null, "no ${ChatProtocol.WT_PROTOCOL} at $url")
                val stream = session.openBidi()
                stream.output.writeStringUtf8("HELLO $name\n")
                stream.output.flush()
                val line =
                    try {
                        // the wrapper tells a timeout (null) from the stream's end (Read(null)); only this deadline is
                        // turned into a refusal, a caller's own timeout still cancels join
                        val read =
                            withTimeoutOrNull(ChatProtocol.HELLO_TIMEOUT_MS) {
                                Read(stream.input.readLineStrict(ChatProtocol.MAX_SERVER_LINE))
                            }
                        (read ?: throw ChatRefusedException(null, NO_WELCOME)).line
                    } catch (e: TooLongLineException) {
                        throw ChatRefusedException(null, "unexpected: a line over ${ChatProtocol.MAX_SERVER_LINE} bytes")
                    } catch (e: WebTransportException) {
                        null // the session's close says why
                    }
                if (line == null) {
                    // a refusal is a session close with the reason (its streams are reset, unread bytes and all)
                    val info =
                        withTimeoutOrNull(ChatProtocol.HELLO_TIMEOUT_MS) { session.closed.await() }
                            ?: throw ChatRefusedException(null, NO_WELCOME)
                    throw ChatRefusedException(info.code, info.reason.ifEmpty { "closed" })
                }
                val welcome = line.split(' ')
                if (welcome.size != 3 || welcome[0] != "WELCOME" || welcome[1] != name) {
                    throw ChatRefusedException(null, "unexpected: $line")
                }
                return ChatClient(session, stream, name, welcome[2].split(','))
            } catch (e: Throwable) {
                withContext(NonCancellable) { session.close(ChatProtocol.CLOSE_PROTOCOL, "join failed") }
                throw e
            }
        }
    }
}
