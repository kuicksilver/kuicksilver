// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)

package io.kuicksilver.ktor.client

import io.ktor.client.request.get
import io.ktor.client.request.header
import io.ktor.client.request.post
import io.ktor.client.request.prepareGet
import io.ktor.client.request.setBody
import io.ktor.client.statement.bodyAsBytes
import io.ktor.client.statement.bodyAsChannel
import io.ktor.client.statement.bodyAsText
import io.ktor.http.HttpProtocolVersion
import io.ktor.utils.io.readAvailable
import io.kuicksilver.http2.Http2ErrorCode
import io.kuicksilver.http2.runtime.Http2Exception
import io.kuicksilver.native.KslLoader
import io.netty.bootstrap.ServerBootstrap
import io.netty.buffer.Unpooled
import io.netty.channel.Channel
import io.netty.channel.ChannelHandlerContext
import io.netty.channel.ChannelInboundHandlerAdapter
import io.netty.channel.ChannelInitializer
import io.netty.channel.nio.NioEventLoopGroup
import io.netty.channel.socket.SocketChannel
import io.netty.channel.socket.nio.NioServerSocketChannel
import io.netty.handler.codec.http2.DefaultHttp2DataFrame
import io.netty.handler.codec.http2.DefaultHttp2Headers
import io.netty.handler.codec.http2.DefaultHttp2HeadersFrame
import io.netty.handler.codec.http2.Http2DataFrame
import io.netty.handler.codec.http2.Http2FrameCodecBuilder
import io.netty.handler.codec.http2.Http2GoAwayFrame
import io.netty.handler.codec.http2.Http2HeadersFrame
import io.netty.handler.codec.http2.Http2MultiplexHandler
import io.netty.handler.codec.http2.Http2ResetFrame
import io.netty.handler.codec.http2.Http2SecurityUtil
import io.netty.handler.ssl.ApplicationProtocolConfig
import io.netty.handler.ssl.ApplicationProtocolNames
import io.netty.handler.ssl.ApplicationProtocolNegotiationHandler
import io.netty.handler.ssl.SslCloseCompletionEvent
import io.netty.handler.ssl.SslContextBuilder
import io.netty.handler.ssl.SslHandler
import io.netty.handler.ssl.SslProvider
import io.netty.handler.ssl.SupportedCipherSuiteFilter
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.withTimeout
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.net.InetSocketAddress
import java.security.KeyFactory
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.security.spec.PKCS8EncodedKeySpec
import java.util.zip.GZIPInputStream
import java.util.zip.GZIPOutputStream
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.seconds

/**
 * The client engine against an HTTP/2 server that is not ours: Netty's HTTP/2 codec (`Http2FrameCodec` and
 * `Http2MultiplexHandler`) over JDK TLS with ALPN `h2`. GET, a 10 MiB POST, 100 requests at once, a cancelled download, a
 * 32 KiB response field and a gzip body the engine must pass through untouched.
 */
class H2InteropTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    private class Netty(
        val port: Int,
        private val group: NioEventLoopGroup,
        private val channel: Channel,
        val resets: CompletableDeferred<Long>,
        /** The error codes of the GOAWAY frames the client sent, in order. */
        val goAways: kotlinx.coroutines.channels.Channel<Long>,
        /** Completed when a connection received the client's close_notify (Netty's SslCloseCompletionEvent). */
        val closeNotify: CompletableDeferred<Unit>,
        /** The first failure of a connection's TLS (the JDK's, reaching the end of the pipeline). */
        val tlsFailure: CompletableDeferred<Throwable>,
    ) : AutoCloseable {
        override fun close() {
            channel.close().syncUninterruptibly()
            group.shutdownGracefully(0, 1, java.util.concurrent.TimeUnit.SECONDS).syncUninterruptibly()
        }
    }

    /** One stream: collects the request, answers by path. */
    private class Exchange(
        private val resets: CompletableDeferred<Long>,
    ) : ChannelInboundHandlerAdapter() {
        private var path = ""
        private var received = 0L

        override fun channelRead(
            ctx: ChannelHandlerContext,
            msg: Any,
        ) {
            when (msg) {
                is Http2HeadersFrame -> {
                    path = msg.headers().path().toString()
                    if (msg.isEndStream) respond(ctx)
                }

                is Http2DataFrame -> {
                    received += msg.content().readableBytes()
                    val end = msg.isEndStream
                    msg.release()
                    if (end) respond(ctx)
                }

                is Http2ResetFrame -> {
                    resets.complete(msg.errorCode())
                }

                else -> {
                    io.netty.util.ReferenceCountUtil
                        .release(msg)
                }
            }
        }

        override fun userEventTriggered(
            ctx: ChannelHandlerContext,
            evt: Any,
        ) {
            if (evt is Http2ResetFrame) resets.complete(evt.errorCode())
            super.userEventTriggered(ctx, evt)
        }

        private fun respond(ctx: ChannelHandlerContext) {
            val headers = DefaultHttp2Headers().status("200")
            val body: ByteArray =
                when (path) {
                    "/size" -> {
                        received.toString().encodeToByteArray()
                    }

                    "/big-field" -> {
                        headers.add("x-big", "b".repeat(32 * 1024))
                        "big".encodeToByteArray()
                    }

                    "/gzip" -> {
                        headers.add("content-encoding", "gzip")
                        gzip("compressed text".encodeToByteArray())
                    }

                    "/renegotiate" -> {
                        // TLS 1.2: a HelloRequest on the established connection (the JDK's engine started again), no answer
                        ctx
                            .channel()
                            .parent()
                            .pipeline()
                            .get(SslHandler::class.java)
                            .renegotiate()
                        return
                    }

                    "/endless" -> {
                        ctx.write(DefaultHttp2HeadersFrame(headers))
                        // more than the client's windows: the client cancels before the end
                        repeat(64) { ctx.write(DefaultHttp2DataFrame(Unpooled.wrappedBuffer(ByteArray(16_384)), false)) }
                        ctx.flush()
                        return
                    }

                    else -> {
                        "netty$path".encodeToByteArray()
                    }
                }
            ctx.write(DefaultHttp2HeadersFrame(headers))
            ctx.writeAndFlush(DefaultHttp2DataFrame(Unpooled.wrappedBuffer(body), true))
        }
    }

    private fun netty(tlsVersion: String = "TLSv1.3"): Netty {
        val cf = CertificateFactory.getInstance("X.509")
        val chain = listOf(TestCerts.server).map { cf.generateCertificate(ByteArrayInputStream(it)) as X509Certificate }
        val key = KeyFactory.getInstance("EC").generatePrivate(PKCS8EncodedKeySpec(TestCerts.serverKey))
        val ssl =
            SslContextBuilder
                .forServer(key, *chain.toTypedArray())
                .sslProvider(SslProvider.JDK)
                .protocols(tlsVersion)
                .ciphers(Http2SecurityUtil.CIPHERS, SupportedCipherSuiteFilter.INSTANCE)
                .applicationProtocolConfig(
                    ApplicationProtocolConfig(
                        ApplicationProtocolConfig.Protocol.ALPN,
                        ApplicationProtocolConfig.SelectorFailureBehavior.NO_ADVERTISE,
                        ApplicationProtocolConfig.SelectedListenerFailureBehavior.ACCEPT,
                        ApplicationProtocolNames.HTTP_2,
                    ),
                ).build()
        val resets = CompletableDeferred<Long>()
        val goAways = kotlinx.coroutines.channels.Channel<Long>(kotlinx.coroutines.channels.Channel.UNLIMITED)
        val closeNotify = CompletableDeferred<Unit>()
        val tlsFailure = CompletableDeferred<Throwable>()
        val group = NioEventLoopGroup(2)
        val channel =
            ServerBootstrap()
                .group(group)
                .channel(NioServerSocketChannel::class.java)
                .childHandler(
                    object : ChannelInitializer<SocketChannel>() {
                        override fun initChannel(ch: SocketChannel) {
                            ch.pipeline().addLast(ssl.newHandler(ch.alloc()))
                            ch.pipeline().addLast(
                                object : ChannelInboundHandlerAdapter() {
                                    override fun userEventTriggered(
                                        ctx: ChannelHandlerContext,
                                        evt: Any,
                                    ) {
                                        if (evt is SslCloseCompletionEvent && evt.isSuccess) closeNotify.complete(Unit)
                                        super.userEventTriggered(ctx, evt)
                                    }

                                    @Deprecated("Deprecated in Java")
                                    @Suppress("OVERRIDE_DEPRECATION")
                                    override fun exceptionCaught(
                                        ctx: ChannelHandlerContext,
                                        cause: Throwable,
                                    ) {
                                        tlsFailure.complete(cause)
                                        ctx.close()
                                    }
                                },
                            )
                            ch.pipeline().addLast(
                                object : ApplicationProtocolNegotiationHandler(ApplicationProtocolNames.HTTP_1_1) {
                                    override fun configurePipeline(
                                        ctx: ChannelHandlerContext,
                                        protocol: String,
                                    ) {
                                        check(protocol == ApplicationProtocolNames.HTTP_2) { "the client did not offer h2: $protocol" }
                                        ctx.pipeline().addLast(Http2FrameCodecBuilder.forServer().build())
                                        ctx.pipeline().addLast(
                                            Http2MultiplexHandler(
                                                object : ChannelInitializer<Channel>() {
                                                    override fun initChannel(ch: Channel) {
                                                        ch.pipeline().addLast(Exchange(resets))
                                                    }
                                                },
                                            ),
                                        )
                                        ctx.pipeline().addLast(
                                            object : ChannelInboundHandlerAdapter() {
                                                override fun channelRead(
                                                    ctx: ChannelHandlerContext,
                                                    msg: Any,
                                                ) {
                                                    if (msg is Http2GoAwayFrame) goAways.trySend(msg.errorCode())
                                                    io.netty.util.ReferenceCountUtil
                                                        .release(msg)
                                                }
                                            },
                                        )
                                    }
                                },
                            )
                        }
                    },
                ).bind(InetSocketAddress("127.0.0.1", 0))
                .syncUninterruptibly()
                .channel()
        return Netty((channel.localAddress() as InetSocketAddress).port, group, channel, resets, goAways, closeNotify, tlsFailure)
    }

    @Test fun getAndPostAndParallel() =
        clientTest {
            netty().use { n ->
                testClient().use { c ->
                    val r = c.get("https://127.0.0.1:${n.port}/hello")
                    assertEquals(HttpProtocolVersion.HTTP_2_0, r.version)
                    assertEquals("netty/hello", r.bodyAsText())
                    val size = 10 shl 20
                    assertEquals(size.toString(), c.post("https://127.0.0.1:${n.port}/size") { setBody(ByteArray(size)) }.bodyAsText())
                    val all =
                        coroutineScope {
                            (1..100)
                                .map { i ->
                                    async { c.get("https://127.0.0.1:${n.port}/p$i").bodyAsText() }
                                }.awaitAll()
                        }
                    assertEquals((1..100).map { "netty/p$it" }, all)
                    assertEquals(1, (c.engine as KuicksilverEngine).h1.h2.connectionCount)
                }
            }
        }

    @Test fun largeFieldAndGzipPassThrough() =
        clientTest {
            netty().use { n ->
                testClient().use { c ->
                    val big = c.get("https://127.0.0.1:${n.port}/big-field")
                    assertEquals(32 * 1024, big.headers["x-big"]!!.length)
                    val gz = c.get("https://127.0.0.1:${n.port}/gzip") { header("accept-encoding", "gzip") }
                    assertEquals("gzip", gz.headers["content-encoding"])
                    assertContentEquals(
                        "compressed text".encodeToByteArray(),
                        GZIPInputStream(ByteArrayInputStream(gz.bodyAsBytes())).readBytes(),
                    )
                }
            }
        }

    @Test fun cancelResetsTheStream() =
        clientTest {
            netty().use { n ->
                testClient().use { c ->
                    c.prepareGet("https://127.0.0.1:${n.port}/endless").execute { resp ->
                        val buf = ByteArray(1024)
                        resp.bodyAsChannel().readAvailable(buf, 0, buf.size)
                    }
                    assertEquals(0x8L, withTimeout(10.seconds) { n.resets.await() }) // CANCEL
                }
            }
        }

    /**
     * HTTP/2 over TLS 1.2 (RFC 9113 section 9.2): the default client allows TLS 1.2 (0.3.0), offers `h2` and speaks it with a
     * server that has only TLS 1.2, under the ECDHE + AEAD suites of its profile (none of them prohibited by section 9.2.2);
     * the call's diagnostics say TLS 1.2.
     */
    @Test fun tls12ServerGetsH2() =
        clientTest {
            netty("TLSv1.2").use { n ->
                testClient().use { c ->
                    val r = c.get("https://127.0.0.1:${n.port}/hello")
                    assertEquals(HttpProtocolVersion.HTTP_2_0, r.version)
                    val d = kotlin.test.assertIs<TcpConnectionSnapshot>(kotlin.test.assertNotNull(r.kuicksilverDiagnostics).connection)
                    assertEquals(io.kuicksilver.tls.TlsVersion.Tls12, d.tlsVersion)
                    assertEquals("netty/hello", r.bodyAsText())
                    assertEquals("netty/again", c.get("https://127.0.0.1:${n.port}/again").bodyAsText())
                    assertEquals(1, (c.engine as KuicksilverEngine).h1.h2.connectionCount)
                }
            }
        }

    /**
     * A server with TLS 1.2 only answers the ClientHello of a client with `versions = Tls13` (the opt-in; the default allows
     * TLS 1.2 since 0.3.0, [tls12ServerGetsH2]) with a `protocol_version`
     * alert: `protocolSelected` never comes, `connectFailed` reports the TLS failure with the server's address, and the
     * exception's diagnostics say TCP, with the connection whose handshake failed.
     */
    @Test fun negative_tls12OnlyServerAlertIsReportedWithItsAddress() =
        clientTest {
            netty("TLSv1.2").use { n ->
                val failures = java.util.concurrent.CopyOnWriteArrayList<ConnectFailure>()
                val selected = java.util.concurrent.CopyOnWriteArrayList<io.ktor.http.HttpProtocolVersion>()
                val listener =
                    object : KuicksilverEventListener() {
                        override fun connectFailed(
                            request: io.ktor.client.request.HttpRequestData,
                            failure: ConnectFailure,
                        ) {
                            failures += failure
                        }

                        override fun protocolSelected(
                            request: io.ktor.client.request.HttpRequestData,
                            protocol: io.ktor.http.HttpProtocolVersion,
                            reason: ProtocolReason,
                        ) {
                            selected += protocol
                        }
                    }
                testClient(engine = {
                    tls { versions = io.kuicksilver.tls.TlsVersions.Tls13 }
                    observability { eventListener = listener }
                }).use { c ->
                    val e = kotlin.test.assertFailsWith<Throwable> { c.get("https://127.0.0.1:${n.port}/hello") }
                    val alert = generateSequence(e) { it.cause }.filterIsInstance<io.kuicksilver.tls.TlsException.AlertReceived>().first()
                    assertEquals("protocol_version", alert.description)
                    assertTrue(selected.isEmpty(), "$selected")
                    val f = failures.single()
                    assertEquals(ConnectStage.TlsHandshake, f.stage)
                    assertEquals(Transport.Tcp, f.transport)
                    assertEquals(n.port, f.address?.port)
                    assertTrue("TlsHandshake to " in f.toString(), "$f")
                    val d = kotlin.test.assertNotNull(e.kuicksilverDiagnostics)
                    assertEquals(Transport.Tcp, d.transport)
                    val t = kotlin.test.assertIs<TcpConnectionSnapshot>(d.connection)
                    kotlin.test.assertNull(t.protocol)
                    assertEquals(n.port, t.remoteAddress?.port)
                    assertEquals(listOf(f), d.connectFailures)
                    // the carrier is one line in a printed stack trace: no stack of its own, no address
                    val carrier = e.suppressedExceptions.filterIsInstance<FailureDiagnostics>().single()
                    assertTrue(carrier.stackTrace.isEmpty())
                    val printed = e.stackTraceToString().lines().filter { "FailureDiagnostics" in it }
                    assertEquals(
                        listOf(
                            "\tSuppressed: io.kuicksilver.ktor.client.FailureDiagnostics: kuicksilver: failed over TCP; setups failed: TlsHandshake",
                        ),
                        printed,
                    )
                }
            }
        }

    /**
     * RFC 9113 section 9.2.1: "An endpoint MUST treat a TLS renegotiation as a connection error (Section 5.4.1) of type
     * PROTOCOL_ERROR." The server asks for renegotiation (a HelloRequest) while the request is in flight: the call fails with
     * PROTOCOL_ERROR raised by this client, not with a TLS failure or a lost connection.
     */
    @Test fun negative_tls12RenegotiationIsAProtocolError() =
        clientTest {
            netty("TLSv1.2").use { n ->
                testClient().use { c ->
                    val e = runCatching { withTimeout(10.seconds) { c.get("https://127.0.0.1:${n.port}/renegotiate") } }.exceptionOrNull()
                    val closed = generateSequence(e) { it.cause }.filterIsInstance<Http2Exception.ConnectionClosed>().firstOrNull()
                    assertEquals(Http2ErrorCode.PROTOCOL_ERROR, closed?.code, "the call failed with $e")
                    assertEquals(false, closed?.byPeer)
                    // the renegotiation was refused (RFC 9113 section 9.2.1: disabled): the JDK fails on our no_renegotiation
                    // warning, as OpenSSL does (a peer that asked "presumably had a good reason"), so it never reads the
                    // GOAWAY that follows it; ClientOrderlyCloseTest shows the GOAWAY of a connection error reaching a server
                    val refusal = withTimeout(10.seconds) { n.tlsFailure.await() }
                    assertTrue(
                        "no_renegotiation" in generateSequence(refusal) { it.cause }.joinToString { it.message.orEmpty() },
                        "$refusal",
                    )
                }
            }
        }

    /** An engine that closes its idle HTTP/2 connection sends GOAWAY (NO_ERROR) and then close_notify (RFC 9113 section 6.8). */
    @Test fun closingTheEngineSendsGoAwayAndCloseNotify() =
        clientTest {
            netty().use { n ->
                testClient().use { c -> assertEquals("netty/x", c.get("https://127.0.0.1:${n.port}/x").bodyAsText()) }
                assertEquals(Http2ErrorCode.NO_ERROR.code, withTimeout(10.seconds) { n.goAways.receive() })
                withTimeout(10.seconds) { n.closeNotify.await() }
            }
        }

    private companion object {
        fun gzip(b: ByteArray): ByteArray = ByteArrayOutputStream().also { o -> GZIPOutputStream(o).use { it.write(b) } }.toByteArray()
    }
}
