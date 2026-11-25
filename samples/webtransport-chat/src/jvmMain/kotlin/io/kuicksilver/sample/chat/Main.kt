// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.sample.chat

import io.ktor.client.HttpClient
import io.kuicksilver.http3.WebTransportCloseInfo
import io.kuicksilver.ktor.client.Kuicksilver
import io.kuicksilver.tls.TlsException
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withContext
import java.util.concurrent.atomic.AtomicBoolean
import java.io.File
import java.io.IOException
import kotlin.system.exitProcess

/**
 * `server [port] [host] [chain.pem key.pem]` serves the room until killed, on 127.0.0.1 unless a host is given, with the
 * identity [serverIdentity] loads (the files, `CHAT_TLS_CHAIN` and `CHAT_TLS_KEY`, or on loopback only the sample's public
 * one); `client <host> <port> <name> [ca.pem]` joins it, trusting the CA of that file or `CHAT_TLS_CA` (else the
 * sample CA): every line typed is a message, `/typing` sends a typing indicator (a datagram), `/quit` leaves.
 */
fun main(args: Array<String>): Unit =
    runBlocking {
        when (args.firstOrNull()) {
            "server" -> {
                val host = args.getOrNull(2) ?: "127.0.0.1"
                if (args.size == 4 || args.size > 5) usage() // a chain without its key, or more
                val identity =
                    orExit("chat server") { if (args.size == 5) serverIdentity(host, args[3], args[4]) else serverIdentity(host) }
                val server = chatServer(identity, host = host, port = args.getOrNull(1)?.toInt() ?: 4433).start(wait = false)
                val port = server.engine.resolvedConnectors().first().port
                println("chat server: https://${urlHost(host)}:$port${ChatProtocol.PATH} (WebTransport over HTTP/3, UDP $port)")
                Runtime.getRuntime().addShutdownHook(Thread { server.stop(1_000, 5_000) }) // GOAWAY: clients see ServerDraining
                withContext(Dispatchers.IO) { Thread.currentThread().join() }
            }
            "client" -> {
                if (args.size !in 4..5) usage()
                val caFile = args.getOrNull(4) ?: System.getenv("CHAT_TLS_CA")
                val trust = orExit("chat client") { if (caFile == null) ChatTls.clientTrust() else ChatTls.clientTrust(File(caFile).readText()) }
                HttpClient(Kuicksilver) { engine { this.trust = trust } }.use { http ->
                    val chat = ChatClient.join(http, "https://${urlHost(args[1])}:${args[2]}${ChatProtocol.PATH}", args[3])
                    println("joined as ${chat.name}; in the room: ${chat.members.joinToString()}")
                    val quitting = AtomicBoolean(false)
                    val printer =
                        launch {
                            chat.events.collect { println(render(it)) }
                            // the server ended it (a stop, a refusal): the input loop leaves at the next line
                            if (!quitting.get()) println("* the session ended: ${describe(chat.closed.await())}; press Enter")
                        }
                    while (!chat.closed.isCompleted) {
                        val line = withContext(Dispatchers.IO) { readlnOrNull() } ?: "/quit"
                        if (chat.closed.isCompleted) break // the server closed the session while we waited for input
                        try {
                            when (line) {
                                "/quit" -> break
                                "/typing" -> println("(typing: ${chat.typing()})")
                                else -> chat.say(line)
                            }
                        } catch (e: IllegalArgumentException) {
                            println("(${e.message})") // a message over the line limit
                        } catch (e: CancellationException) {
                            throw e
                        } catch (e: Exception) {
                            break // the session ended under the write: closed says how
                        }
                    }
                    quitting.set(true)
                    chat.leave()
                    printer.join()
                    println("left: ${describe(chat.closed.await())}")
                }
            }
            else -> usage()
        }
    }

/**
 * [block], or a one-line message and exit code 2 for what a bad argument or file causes: a missing file or a PEM file
 * without the block it needs (IOException), a key that does not match or is encrypted (TlsException), a refused argument.
 */
private inline fun <T> orExit(who: String, block: () -> T): T =
    try {
        block()
    } catch (e: IllegalArgumentException) {
        System.err.println("$who: ${e.message}")
        exitProcess(2)
    } catch (e: IOException) {
        System.err.println("$who: ${e.message}") // a missing file names its path; a bad PEM file says what is wrong
        exitProcess(2)
    } catch (e: TlsException) {
        System.err.println("$who: ${e.message}")
        exitProcess(2)
    }

/** A host as a URL carries it: an IPv6 literal in brackets. */
private fun urlHost(host: String): String = if (':' in host && !host.startsWith("[")) "[$host]" else host

private fun describe(info: WebTransportCloseInfo): String = "code ${info.code} ${info.reason}".trim()

private fun render(e: ChatEvent): String =
    when (e) {
        is ChatEvent.Message -> "<${e.from}> ${e.text}"
        is ChatEvent.Joined -> "* ${e.name} joined"
        is ChatEvent.Left -> "* ${e.name} left"
        is ChatEvent.Typing -> "* ${e.name} is typing..."
        ChatEvent.ServerDraining -> "* the server is shutting down"
    }

private fun usage(): Nothing {
    System.err.println("usage: server [port] [host] [chain.pem key.pem] | client <host> <port> <name> [ca.pem]")
    exitProcess(2)
}
