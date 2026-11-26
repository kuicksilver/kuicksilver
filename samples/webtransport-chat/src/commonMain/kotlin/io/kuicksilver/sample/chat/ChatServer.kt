// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.sample.chat

import io.ktor.server.application.Application
import io.ktor.server.engine.EmbeddedServer
import io.ktor.server.engine.embeddedServer
import io.ktor.server.routing.routing
import io.ktor.utils.io.ByteWriteChannel
import io.ktor.utils.io.charsets.TooLongLineException
import io.ktor.utils.io.readLineStrict
import io.ktor.utils.io.writeStringUtf8
import io.kuicksilver.http3.WebTransportBidiStream
import io.kuicksilver.http3.WebTransportSession
import io.kuicksilver.ktor.server.Kuicksilver
import io.kuicksilver.ktor.server.KuicksilverApplicationEngine
import io.kuicksilver.ktor.server.webTransport
import io.kuicksilver.tls.TlsIdentity
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull
import kotlin.time.TimeSource

/**
 * The chat server on Kuicksilver's Ktor engine: one TLS connector with [identity], which serves HTTP/2 and HTTP/1.1 on
 * TCP and HTTP/3 on UDP on the same port, with WebTransport on; [chatModule] routes the sessions. Port 0 picks a free one
 * (`resolvedConnectors()`). It listens on loopback by default: binding [host] to the network needs a certificate and key
 * of your own as [identity], never the sample's public test identity.
 */
fun chatServer(
    identity: TlsIdentity,
    host: String = "127.0.0.1",
    port: Int = 4433,
    room: ChatRoom = ChatRoom(),
): EmbeddedServer<KuicksilverApplicationEngine, KuicksilverApplicationEngine.Configuration> =
    embeddedServer(Kuicksilver, configure = {
        tlsConnector {
            tls { this.identity = identity }
            this.host = host
            this.port = port
        }
        http3 { webTransport { enabled = true } } // Extended CONNECT, HTTP datagrams and the WebTransport SETTINGS on the HTTP/3 listener
    }) { chatModule(room) }

/**
 * The chat server as a Ktor module: `webTransport(ChatProtocol.PATH)` on an engine with `webTransport = true`. Every
 * session is a member of [room]; see [ChatProtocol] for what goes over the streams and the datagrams.
 */
fun Application.chatModule(room: ChatRoom = ChatRoom()) {
    routing {
        webTransport(ChatProtocol.PATH, protocols = listOf(ChatProtocol.WT_PROTOCOL)) { session -> room.serve(session) }
    }
}

/** One chat room: its members by name, each with the queue of lines still to be written to it. */
class ChatRoom {
    private class Member(val name: String, val session: WebTransportSession, val outbox: Channel<String>) {
        /** Completed when [outbox] overflowed: the member's own coroutine then closes its session. */
        val tooSlow = CompletableDeferred<Unit>()
    }

    private val lock = Mutex()
    private val members = LinkedHashMap<String, Member>()

    /**
     * Serves one session until its member leaves: HELLO, then the member's lines in, the room's lines out, typing
     * datagrams relayed. Returning closes the session with code 0 (the route does); every other end closes it with one of
     * [ChatProtocol]'s codes first.
     */
    suspend fun serve(session: WebTransportSession) {
        val (stream, name) = hello(session) ?: return
        val member = Member(name, session, Channel(ChatProtocol.OUTBOX))
        // under the lock, as every line the room sends: all members see the room's lines in one order
        val refused =
            lock.withLock {
                when {
                    name in members -> ChatProtocol.CLOSE_NAME_TAKEN to "name-taken"
                    members.size >= ChatProtocol.MAX_MEMBERS -> ChatProtocol.CLOSE_ROOM_FULL to "room-full"
                    else -> {
                        members[name] = member
                        deliver(member, "WELCOME $name ${members.keys.joinToString(",")}")
                        for (m in members.values) if (m !== member) deliver(m, "JOIN $name")
                        null
                    }
                }
            }
        // the session's close carries the reason: WT_CLOSE_SESSION is the one message a refused client is sure to get
        if (refused != null) return session.close(refused.first, refused.second)
        try {
            coroutineScope {
                val writer = launch { writeLines(stream.output, member) }
                val kick = launch { member.tooSlow.await(); session.close(ChatProtocol.CLOSE_TOO_SLOW, "too slow") }
                val typing = launch { relayTyping(member) }
                readLines(stream, member)
                typing.cancel()
                if (!member.tooSlow.isCompleted) kick.cancel() // else let its close finish
                leave(member) // the others hear it now, not after this member's last lines went out
                member.outbox.close() // the writer sends what is queued, then FIN
                // a member that said BYE but stopped reading does not keep its handler forever
                if (withTimeoutOrNull(ChatProtocol.HELLO_TIMEOUT_MS) { writer.join() } == null) writer.cancel()
            }
        } finally {
            member.outbox.close()
            leave(member) // also when the handler failed or was cancelled (the server stopping)
        }
    }

    /**
     * Takes [member] out of the room and tells the others, once: a member that stayed in the map would block its name.
     * NonCancellable, as the server's stop cancels the handlers.
     */
    private suspend fun leave(member: Member) {
        withContext(NonCancellable) {
            lock.withLock {
                if (members[member.name] !== member) return@withLock
                members.remove(member.name)
                for (m in members.values) deliver(m, "LEAVE ${member.name}")
            }
        }
    }

    /** The client's first stream and its `HELLO <name>`, or null once the session was refused. */
    private suspend fun hello(session: WebTransportSession): Pair<WebTransportBidiStream, String>? {
        val stream = withTimeoutOrNull(ChatProtocol.HELLO_TIMEOUT_MS) { session.acceptBidi() }
        val line =
            try {
                stream?.let { withTimeoutOrNull(ChatProtocol.HELLO_TIMEOUT_MS) { it.input.readLineStrict(ChatProtocol.MAX_LINE) } }
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) { // too long (TooLongLineException), or the client went away
                null
            }
        val name = line?.removePrefix("HELLO ")?.takeIf { line.startsWith("HELLO ") && ChatProtocol.isValidName(it) }
        if (stream == null || name == null) {
            session.close(ChatProtocol.CLOSE_PROTOCOL, "hello")
            return null
        }
        return stream to name
    }

    /** The member's lines until BYE or its end; a malformed or too long line closes its session. */
    private suspend fun readLines(stream: WebTransportBidiStream, member: Member) {
        while (true) {
            val line =
                try {
                    stream.input.readLineStrict(ChatProtocol.MAX_LINE) ?: return // FIN: the client left
                } catch (e: TooLongLineException) {
                    return member.session.close(ChatProtocol.CLOSE_LINE_TOO_LONG, "line too long")
                } catch (e: CancellationException) {
                    throw e
                } catch (e: Exception) {
                    return // the session or its connection ended (WebTransportException, a closed channel)
                }
            // no rate limit per member: a member may send as fast as its stream and the others' queues take, and a
            // reader that falls behind is dropped (deliver); a public room would also bound the messages per second here
            when {
                line.startsWith("MSG ") -> broadcast("MSG ${member.name} ${ChatProtocol.printable(line.removePrefix("MSG "))}")
                line == "BYE" -> return
                else -> return member.session.close(ChatProtocol.CLOSE_PROTOCOL, "unknown line")
            }
        }
    }

    /** One writer per member, so that lines from many senders never interleave on its stream. */
    private suspend fun writeLines(output: ByteWriteChannel, member: Member) {
        try {
            for (first in member.outbox) {
                var line: String? = first
                while (line != null) { // a burst goes out in one flush
                    output.writeStringUtf8(line)
                    output.writeStringUtf8("\n")
                    line = member.outbox.tryReceive().getOrNull()
                }
                output.flush()
            }
            output.flushAndClose()
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) { // the member left while lines were queued
        }
    }

    /** Typing datagrams from [member], at most one per [ChatProtocol.TYPING_INTERVAL_MS], to every other member. */
    private suspend fun relayTyping(member: Member) {
        val relayed = "TYPING ${member.name}".encodeToByteArray()
        var last: TimeSource.Monotonic.ValueTimeMark? = null
        try {
            while (true) {
                val datagram = member.session.receiveDatagram()
                if (!datagram.contentEquals(ChatProtocol.TYPING)) continue // anything else is ignored: datagrams are untrusted input
                if (last != null && last.elapsedNow().inWholeMilliseconds < ChatProtocol.TYPING_INTERVAL_MS) continue
                last = TimeSource.Monotonic.markNow()
                // trySendDatagram, never sendDatagram: an indicator is worth nothing late, and one member's full queue
                // must not stall the relay
                for (other in lock.withLock { members.values.filter { it !== member } }) other.session.trySendDatagram(relayed)
            }
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) { // WebTransportException.SessionClosed: the member is gone
        }
    }

    private suspend fun broadcast(line: String) {
        lock.withLock { for (m in members.values) deliver(m, line) }
    }

    /**
     * Queues [line] for [member] without waiting: a member whose queue is full reads too slowly and is dropped (its own
     * coroutine closes its session), so one slow reader never holds the sender or the room.
     */
    private fun deliver(member: Member, line: String) {
        val queued = member.outbox.trySend(line)
        if (queued.isFailure && !queued.isClosed) {
            member.outbox.close()
            member.tooSlow.complete(Unit)
        }
    }
}
