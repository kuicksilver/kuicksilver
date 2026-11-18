// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(io.kuicksilver.annotations.InternalKuicksilverApi::class)

package io.kuicksilver.ktor.network

import io.ktor.network.selector.SelectorManager
import io.ktor.network.sockets.InetSocketAddress
import io.ktor.network.sockets.openReadChannel
import io.ktor.network.sockets.openWriteChannel
import io.ktor.utils.io.readByte
import io.ktor.utils.io.writeFully
import io.kuicksilver.native.KslLoader
import io.kuicksilver.tls.TlsConnection
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.IO
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.time.Duration.Companion.seconds

/**
 * `Socket.tlsServer(config, input)`: a server that read a prefix (a PROXY protocol header) from the socket's read channel
 * before TLS hands the same channel to the TLS session, which reads on from where the prefix ended. The ClientHello sent in
 * the prefix's own segment must not be lost, nor read twice.
 */
class TlsServerAfterPrefixTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    @Test fun clientHelloInThePrefixSegmentIsKept() =
        runBlocking {
            withTimeout(30.seconds) {
                val selector = SelectorManager(Dispatchers.IO)
                val listener = bindTcp(selector, "127.0.0.1", 0)
                try {
                    val port = (listener.localAddress as InetSocketAddress).port
                    val prefix = "PREFIX".encodeToByteArray()
                    coroutineScope {
                        val served =
                            async {
                                val raw = listener.accept()
                                val input = raw.openDeliveringReadChannel()
                                val got = ByteArray(prefix.size) { input.readByte() }
                                val tls = raw.tlsServer(serverConfig(), input)
                                val r = tls.openReadChannel()
                                val w = tls.openWriteChannel(autoFlush = true)
                                val line = r.readExactly(4)
                                w.writeFully("pong".encodeToByteArray())
                                w.flushAndClose()
                                tls.close()
                                got to line
                            }
                        val tcp = connectTcp(selector, InetSocketAddress("127.0.0.1", port))
                        val r = tcp.openReadChannel()
                        val w = tcp.openWriteChannel(autoFlush = false)
                        w.writeFully(prefix) // not flushed: it leaves with the ClientHello
                        val reply =
                            coroutineScope {
                                val t = TlsConnection.client(r, w, clientConfig(), coroutineContext)
                                t.output.writeFully("ping".encodeToByteArray())
                                t.output.flush()
                                val got = t.input.readExactly(4)
                                t.close()
                                got
                            }
                        val (seenPrefix, seenLine) = served.await()
                        assertContentEquals(prefix, seenPrefix)
                        assertEquals("ping", seenLine.decodeToString())
                        assertEquals("pong", reply.decodeToString())
                        tcp.close()
                    }
                } finally {
                    listener.close()
                    selector.close()
                }
            }
        }
}
