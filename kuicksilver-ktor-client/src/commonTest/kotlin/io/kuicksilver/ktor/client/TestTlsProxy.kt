// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(io.kuicksilver.annotations.InternalKuicksilverApi::class)

package io.kuicksilver.ktor.client

import io.ktor.network.selector.SelectorManager
import io.ktor.network.sockets.InetSocketAddress
import io.ktor.network.sockets.Socket
import io.ktor.network.sockets.openReadChannel
import io.ktor.network.sockets.openWriteChannel
import io.ktor.utils.io.ByteReadChannel
import io.ktor.utils.io.ByteWriteChannel
import io.ktor.utils.io.LineEnding
import io.ktor.utils.io.copyAndClose
import io.ktor.utils.io.readAvailable
import io.ktor.utils.io.readLine
import io.ktor.utils.io.writeFully
import io.ktor.utils.io.writeStringUtf8
import io.kuicksilver.ktor.network.bindTcp
import io.kuicksilver.ktor.network.connectTcp
import io.kuicksilver.ktor.network.tlsServer
import io.kuicksilver.tls.ClientHelloInfo
import io.kuicksilver.tls.ServerTlsOverride
import io.kuicksilver.tls.TlsIdentity
import io.kuicksilver.tls.TlsRole
import io.kuicksilver.tls.tlsConfig
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.IO
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock

internal const val CONNECT_OK: String = "HTTP/1.1 200 Connection established\r\n\r\n"

/** What a [tlsProxy] saw, over all its connections. */
internal class ProxySeen {
    private val lock = Mutex()
    private var acceptedCount = 0
    private val helloList = ArrayList<ClientHelloInfo>()
    private val headList = ArrayList<List<String>>()
    private val failureList = ArrayList<Throwable>()

    suspend fun accepted(): Int = lock.withLock { acceptedCount }

    /** The ClientHellos of the TLS handshakes with the proxy (SNI and ALPN offered). */
    suspend fun hellos(): List<ClientHelloInfo> = lock.withLock { helloList.toList() }

    /** Every request head the proxy read inside TLS (a CONNECT or an absolute-form request), in order. */
    suspend fun heads(): List<List<String>> = lock.withLock { headList.toList() }

    /** Handshakes with the proxy that failed on its side. */
    suspend fun failures(): List<Throwable> = lock.withLock { failureList.toList() }

    suspend fun accept() = lock.withLock { acceptedCount++ }

    suspend fun hello(info: ClientHelloInfo) = lock.withLock { helloList += info }

    suspend fun head(lines: List<String>) = lock.withLock { headList += lines }

    suspend fun failed(e: Throwable) = lock.withLock { failureList += e }
}

/**
 * An HTTPS proxy on 127.0.0.1 for the tests, on the project's own TLS server (`Socket.tlsServer`): it presents [cert]
 * with [key], offers [alpn], and inside TLS answers a CONNECT with [connectResponse] (a 2xx then relays bytes to
 * 127.0.0.1:[originPort] whatever the CONNECT names) and any other request (absolute form) with [absolute]. A
 * connection stays open for the next request head unless a tunnel took it. [block] gets the proxy's port.
 */
internal suspend fun tlsProxy(
    originPort: Int = 1,
    cert: ByteArray = TestCerts.proxy,
    key: ByteArray = TestCerts.proxyKey,
    alpn: List<String> = listOf("http/1.1"),
    connectResponse: String = CONNECT_OK,
    absolute: suspend (head: List<String>, out: ByteWriteChannel) -> Unit = { _, out ->
        out.writeStringUtf8("HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
    },
    block: suspend (port: Int, seen: ProxySeen) -> Unit,
) {
    val selector = SelectorManager(Dispatchers.IO)
    val listener = bindTcp(selector, "127.0.0.1", 0)
    val seen = ProxySeen()
    val config =
        tlsConfig(TlsRole.Server) {
            this.alpn = alpn
            identity = TlsIdentity.fromDer(listOf(cert), key.copyOf())
            sniSelector = { info ->
                seen.hello(info)
                ServerTlsOverride(TlsIdentity.fromDer(listOf(cert), key.copyOf()))
            }
        }
    try {
        coroutineScope {
            val acceptor =
                launch {
                    while (true) {
                        val raw = listener.accept()
                        seen.accept()
                        launch { serveProxyConnection(raw, config, seen, selector, originPort, connectResponse, absolute) }
                    }
                }
            block((listener.localAddress as InetSocketAddress).port, seen)
            acceptor.cancel()
        }
    } finally {
        listener.close()
        selector.close()
    }
}

private suspend fun serveProxyConnection(
    raw: Socket,
    config: io.kuicksilver.tls.TlsConfig,
    seen: ProxySeen,
    selector: SelectorManager,
    originPort: Int,
    connectResponse: String,
    absolute: suspend (List<String>, ByteWriteChannel) -> Unit,
) {
    val tls =
        try {
            raw.tlsServer(config)
        } catch (e: kotlinx.coroutines.CancellationException) {
            throw e
        } catch (e: Throwable) {
            seen.failed(e) // tlsServer closed the raw socket
            return
        }
    try {
        val input = tls.openReadChannel()
        val output = tls.openWriteChannel(autoFlush = true)
        while (true) {
            val head = ArrayList<String>()
            while (true) {
                val line = runCatching { input.readLine(LineEnding.Lenient) }.getOrNull() ?: return
                if (line.isEmpty()) break
                head += line
            }
            seen.head(head)
            if (!head.first().startsWith("CONNECT ")) {
                absolute(head, output)
                continue
            }
            output.writeStringUtf8(connectResponse)
            if (!connectResponse.startsWith("HTTP/1.1 2")) continue
            connectTcp(selector, InetSocketAddress("127.0.0.1", originPort)).use { o ->
                val oIn = o.openReadChannel()
                val oOut = o.openWriteChannel(autoFlush = true)
                coroutineScope {
                    launch { runCatching { input.copyAndClose(oOut) } }
                    runCatching { oIn.copyAndClose(output) }
                }
            }
            return
        }
    } finally {
        tls.close()
    }
}

/**
 * A TCP relay on 127.0.0.1 in front of 127.0.0.1:[targetPort] that records every byte the client sends: what crosses
 * the wire before and outside TLS. [block] gets its port and the bytes recorded so far.
 */
internal suspend fun wireTap(
    targetPort: Int,
    block: suspend (port: Int, sent: suspend () -> ByteArray) -> Unit,
) {
    val selector = SelectorManager(Dispatchers.IO)
    val listener = bindTcp(selector, "127.0.0.1", 0)
    val lock = Mutex()
    val recorded = ArrayList<Byte>()
    try {
        coroutineScope {
            val acceptor =
                launch {
                    while (true) {
                        val client = listener.accept()
                        launch {
                            client.use { c ->
                                connectTcp(selector, InetSocketAddress("127.0.0.1", targetPort)).use { t ->
                                    val cIn = c.openReadChannel()
                                    val cOut = c.openWriteChannel(autoFlush = true)
                                    val tIn = t.openReadChannel()
                                    val tOut = t.openWriteChannel(autoFlush = true)
                                    coroutineScope {
                                        launch { runCatching { tIn.copyAndClose(cOut) } }
                                        runCatching { relayRecording(cIn, tOut) { chunk -> lock.withLock { recorded += chunk.asList() } } }
                                    }
                                }
                            }
                        }
                    }
                }
            block((listener.localAddress as InetSocketAddress).port) { lock.withLock { recorded.toByteArray() } }
            acceptor.cancel()
        }
    } finally {
        listener.close()
        selector.close()
    }
}

private suspend fun relayRecording(
    from: ByteReadChannel,
    to: ByteWriteChannel,
    record: suspend (ByteArray) -> Unit,
) {
    val buf = ByteArray(8192)
    try {
        while (true) {
            val n = from.readAvailable(buf, 0, buf.size)
            if (n < 0) break
            if (n == 0) continue
            val chunk = buf.copyOf(n)
            record(chunk) // before it goes on: whatever the proxy answers to was recorded first
            to.writeFully(chunk)
            to.flush()
        }
    } finally {
        to.flushAndClose()
    }
}

/** Whether [needle] occurs in [hay], byte for byte. */
internal fun ByteArray.containsBytes(needle: ByteArray): Boolean {
    if (needle.isEmpty()) return true
    outer@ for (i in 0..size - needle.size) {
        for (j in needle.indices) if (this[i + j] != needle[j]) continue@outer
        return true
    }
    return false
}
