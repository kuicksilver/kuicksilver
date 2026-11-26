// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.sample.chat

import io.ktor.client.HttpClient
import io.ktor.utils.io.readLineStrict
import io.ktor.utils.io.writeStringUtf8
import io.kuicksilver.http3.http3Settings
import io.kuicksilver.ktor.client.Kuicksilver
import io.kuicksilver.ktor.client.webTransport
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import kotlinx.coroutines.withTimeoutOrNull
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.seconds

/** The chat server and its clients in one JVM, over real UDP on loopback: Kuicksilver's Ktor engines on both sides. */
class ChatTest {
    private fun client() = HttpClient(Kuicksilver) { engine { tls { trust = ChatTls.clientTrust() } } }

    /** A client that gives each WebTransport session 64 KiB of data credit: a reader that stops is full after that. */
    private fun smallWindowClient() =
        HttpClient(Kuicksilver) {
            engine {
                tls { trust = ChatTls.clientTrust() }
                http3 { settings { webTransport { initialMaxData = 64L * 1024 } } }
            }
        }

    /** A started server on a free port of 127.0.0.1, stopped after [block]. */
    private fun withServer(block: suspend CoroutineScope.(url: String) -> Unit) =
        runBlocking {
            val server = chatServer(sampleServerIdentity(), host = "127.0.0.1", port = 0).start(wait = false)
            try {
                val port = server.engine.resolvedConnectors().first().port
                withTimeout(60.seconds) { block("https://127.0.0.1:$port${ChatProtocol.PATH}") }
            } finally {
                server.stopSuspend(100, 2_000)
            }
        }

    /** Every event of [chat], in a channel the test reads at its own pace. */
    private fun CoroutineScope.inbox(chat: ChatClient): Channel<ChatEvent> {
        val inbox = Channel<ChatEvent>(Channel.UNLIMITED)
        launch { chat.events.collect { inbox.send(it) } }.invokeOnCompletion { inbox.close() }
        return inbox
    }

    /** The next event that is not a typing indicator (those may come at any time, or not at all). */
    private suspend fun Channel<ChatEvent>.nextReliable(): ChatEvent {
        while (true) {
            val e = withTimeout(10.seconds) { receive() }
            if (e !is ChatEvent.Typing) return e
        }
    }

    @Test fun roomOverWebTransport() =
        withServer { url ->
            client().use { aliceHttp ->
                client().use { bobHttp ->
                    val alice = ChatClient.join(aliceHttp, url, "alice")
                    assertEquals(listOf("alice"), alice.members)
                    val aliceIn = inbox(alice)
                    val bob = ChatClient.join(bobHttp, url, "bob")
                    assertEquals(listOf("alice", "bob"), bob.members)
                    val bobIn = inbox(bob)
                    assertEquals(ChatEvent.Joined("bob"), aliceIn.nextReliable())

                    // messages: on the stream, in the room's order, the sender's own included
                    bob.say("hello over HTTP/3")
                    assertEquals(ChatEvent.Message("bob", "hello over HTTP/3"), aliceIn.nextReliable())
                    alice.say("hi bob\nhow are you") // one line on the wire
                    alice.say("second")
                    for (inbox in listOf(aliceIn, bobIn)) {
                        if (inbox === bobIn) assertEquals(ChatEvent.Message("bob", "hello over HTTP/3"), inbox.nextReliable())
                        assertEquals(ChatEvent.Message("alice", "hi bob how are you"), inbox.nextReliable())
                        assertEquals(ChatEvent.Message("alice", "second"), inbox.nextReliable())
                    }

                    // the server relays text, not control characters: no member sends escape sequences to another's terminal
                    bob.say("\u001b[2Jcleared?\u0007")
                    for (inbox in listOf(aliceIn, bobIn)) assertEquals(ChatEvent.Message("bob", "?[2Jcleared??"), inbox.nextReliable())

                    // typing: a datagram, which may be lost, so the test sends again until one arrives (the server
                    // relays one per 250 ms at most); no sleep, each try waits for the event itself
                    val typing =
                        (1..20).firstNotNullOfOrNull {
                            alice.typing()
                            withTimeoutOrNull(1.seconds) {
                                var e = bobIn.receive()
                                while (e !is ChatEvent.Typing) e = bobIn.receive()
                                e
                            }
                        }
                    assertEquals(ChatEvent.Typing("alice"), typing)

                    // leaving: bob sees it on the stream, alice's session ends with code 0 after BYE
                    alice.leave()
                    assertEquals(ChatEvent.Left("alice"), bobIn.nextReliable())
                    assertEquals(ChatProtocol.CLOSE_OK, withTimeout(10.seconds) { alice.closed.await() }.code)
                    bob.leave()
                }
            }
        }

    @Test fun negative_nameTakenIsRefused() =
        withServer { url ->
            client().use { http ->
                val first = ChatClient.join(http, url, "carol")
                val e = assertFailsWith<ChatRefusedException> { ChatClient.join(http, url, "carol") }
                assertEquals(ChatProtocol.CLOSE_NAME_TAKEN to "name-taken", e.code to e.reason)
                assertEquals(listOf("carol", "dave"), ChatClient.join(http, url, "dave").members) // the room goes on
                first.leave()
            }
        }

    /** A client that skips HELLO, or sends a line past [ChatProtocol.MAX_LINE], gets its session closed with the code that says why. */
    @Test fun negative_badLinesCloseTheSession() =
        withServer { url ->
            client().use { http ->
                val noHello = http.webTransport(url, protocols = listOf(ChatProtocol.WT_PROTOCOL))
                noHello.openBidi().output.apply { writeStringUtf8("MSG hi\n"); flush() }
                assertEquals(ChatProtocol.CLOSE_PROTOCOL, withTimeout(10.seconds) { noHello.closed.await() }.code)

                val watcher = ChatClient.join(http, url, "erin")
                val watcherIn = inbox(watcher)
                val raw = http.webTransport(url, protocols = listOf(ChatProtocol.WT_PROTOCOL))
                val stream = raw.openBidi()
                stream.output.writeStringUtf8("HELLO mallory\n")
                stream.output.flush()
                assertEquals("WELCOME mallory erin,mallory", withTimeout(10.seconds) { stream.input.readLineStrict(2048) })
                assertEquals(ChatEvent.Joined("mallory"), watcherIn.nextReliable())
                stream.output.writeStringUtf8("MSG " + "x".repeat(2 * ChatProtocol.MAX_LINE.toInt()) + "\n")
                stream.output.flush()
                assertEquals(ChatProtocol.CLOSE_LINE_TOO_LONG, withTimeout(10.seconds) { raw.closed.await() }.code)
                assertEquals(ChatEvent.Left("mallory"), watcherIn.nextReliable()) // and nobody saw the line
                watcher.leave()
            }
        }

    /**
     * A member that stops reading is dropped once its queue of [ChatProtocol.OUTBOX] lines is full (its stream's flow
     * control holds the server's writer first), and the room goes on: the speaker is never held by it.
     */
    @Test fun negative_slowReaderIsDropped() =
        withServer { url ->
            client().use { http ->
                smallWindowClient().use { slowHttp -> slowReaderIsDropped(url, http, slowHttp) }
            }
        }

    private suspend fun CoroutineScope.slowReaderIsDropped(url: String, http: HttpClient, slowHttp: HttpClient) {
        val speaker = ChatClient.join(http, url, "grace")
        val speakerIn = inbox(speaker)
        val raw = slowHttp.webTransport(url, protocols = listOf(ChatProtocol.WT_PROTOCOL))
        val stream = raw.openBidi()
        stream.output.writeStringUtf8("HELLO sloth\n")
        stream.output.flush()
        assertEquals("WELCOME sloth grace,sloth", withTimeout(10.seconds) { stream.input.readLineStrict(2048) })
        // ...and never reads again
        assertEquals(ChatEvent.Joined("sloth"), speakerIn.nextReliable())
        val text = "y".repeat(1000)
        var sent = 0
        var left = false
        while (!left && sent < 2_000) {
            speaker.say(text)
            sent++
            while (true) { // the speaker's own copy comes back, never held by the slow reader; sloth's LEAVE in between
                val e = speakerIn.nextReliable()
                if (e == ChatEvent.Left("sloth")) {
                    left = true
                } else {
                    assertEquals(ChatEvent.Message("grace", text), e)
                    break
                }
            }
        }
        // what the member's 64 KiB of credit lets through, what the server's send buffer holds for the session (its
        // share of QuicConfig.maxSendBuffer, 4 MiB per connection: about 1 MiB), then the 256 lines of its queue
        assertTrue(left, "never dropped after $sent messages")
        assertTrue(sent < 1_800, "dropped only after $sent messages of 1000 bytes")
        assertEquals(ChatProtocol.CLOSE_TOO_SLOW, withTimeout(10.seconds) { raw.closed.await() }.code)
        speaker.leave()
    }

    /** The sample's public key never serves a host on the network: without files of your own the server refuses to start. */
    @Test fun negative_sampleIdentityOnlyOnLoopback() {
        val e = assertFailsWith<IllegalArgumentException> { serverIdentity("0.0.0.0", chainFile = null, keyFile = null) }
        assertTrue("not loopback" in e.message.orEmpty(), e.message)
        assertFailsWith<IllegalArgumentException> { serverIdentity("127.0.0.1", chainFile = "chain.pem", keyFile = null) }
    }

    /** A WELCOME for a full room of the longest names fits the line a client reads (ChatProtocol's init checks it too). */
    @Test fun welcomeOfAFullRoomFitsAServerLine() {
        val longest = "WELCOME ${"n".repeat(32)} " + List(ChatProtocol.MAX_MEMBERS) { "n".repeat(32) }.joinToString(",")
        assertTrue(longest.length <= ChatProtocol.MAX_SERVER_LINE, "${longest.length} > ${ChatProtocol.MAX_SERVER_LINE}")
    }

    /** A room takes [ChatProtocol.MAX_MEMBERS]; the WELCOME of the last, with every name at its longest, still fits a line. */
    @Test fun negative_roomFullIsRefused() =
        withServer { url ->
            client().use { http ->
                val members =
                    (1..ChatProtocol.MAX_MEMBERS).map { i ->
                        ChatClient.join(http, url, i.toString().padStart(32, 'm')) // names of the longest length
                    }
                assertEquals(ChatProtocol.MAX_MEMBERS, members.last().members.size)
                val e = assertFailsWith<ChatRefusedException> { ChatClient.join(http, url, "one-too-many") }
                assertEquals(ChatProtocol.CLOSE_ROOM_FULL to "room-full", e.code to e.reason)
                members.first().leave()
                ChatClient.join(http, url, "one-too-many").leave() // a free place is taken again
                for (m in members.drop(1)) m.leave()
            }
        }

    /** Stopping the server gracefully sends GOAWAY: a member hears [ChatEvent.ServerDraining] before its session ends. */
    @Test fun gracefulStopDrainsSessions() =
        runBlocking {
            val server = chatServer(sampleServerIdentity(), host = "127.0.0.1", port = 0).start(wait = false)
            try {
                val port = server.engine.resolvedConnectors().first().port
                client().use { http ->
                    val chat = ChatClient.join(http, "https://127.0.0.1:$port${ChatProtocol.PATH}", "frank")
                    val inbox = inbox(chat)
                    val stopping = launch { server.stopSuspend(5_000, 10_000) }
                    assertEquals(ChatEvent.ServerDraining, withTimeout(10.seconds) { inbox.nextReliable() })
                    chat.leave() // the member leaves when asked, and the server's stop completes without its timeout
                    withTimeout(10.seconds) { stopping.join() }
                }
            } finally {
                server.stopSuspend(100, 2_000) // after a failure above; a second stop of a stopped server does nothing
            }
        }
}
