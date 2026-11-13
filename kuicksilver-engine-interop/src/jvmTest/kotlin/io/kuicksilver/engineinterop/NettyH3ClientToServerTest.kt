// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.engineinterop

import io.netty.bootstrap.Bootstrap
import io.netty.buffer.ByteBufUtil
import io.netty.buffer.Unpooled
import io.netty.channel.Channel
import io.netty.channel.ChannelHandlerContext
import io.netty.channel.MultiThreadIoEventLoopGroup
import io.netty.channel.nio.NioIoHandler
import io.netty.channel.socket.nio.NioDatagramChannel
import io.netty.handler.codec.http3.DefaultHttp3DataFrame
import io.netty.handler.codec.http3.DefaultHttp3HeadersFrame
import io.netty.handler.codec.http3.Http3
import io.netty.handler.codec.http3.Http3ClientConnectionHandler
import io.netty.handler.codec.http3.Http3DataFrame
import io.netty.handler.codec.http3.Http3HeadersFrame
import io.netty.handler.codec.http3.Http3RequestStreamInboundHandler
import io.netty.handler.codec.quic.QuicChannel
import io.netty.handler.codec.quic.QuicSslContextBuilder
import io.netty.handler.codec.quic.QuicStreamChannel
import io.netty.util.AsciiString
import io.netty.util.ReferenceCountUtil
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.withTimeout
import org.junit.jupiter.api.AfterAll
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.TestInstance
import java.io.ByteArrayOutputStream
import java.net.InetSocketAddress
import java.security.MessageDigest
import java.util.concurrent.TimeUnit
import kotlin.random.Random
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.time.Duration.Companion.seconds

/**
 * Netty 4.2's HTTP/3 client codec (quiche through netty-codec-native-quic) against our server's HTTP/3 listener: the one
 * non-Kuicksilver HTTP/3 client on the JVM here (OkHttp has none, the JDK's arrives in JDK 26). One QUIC connection,
 * one request stream per exchange (RFC 9114 section 4.1).
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
internal class NettyH3ClientToServerTest {
    private lateinit var server: RunningServer
    private val group = MultiThreadIoEventLoopGroup(1, NioIoHandler.newFactory())
    private lateinit var udp: Channel
    private lateinit var quic: QuicChannel

    @BeforeAll fun start() {
        server = startServer(ServerEngine.Kuicksilver, tls = true)
        val ssl =
            QuicSslContextBuilder
                .forClient()
                .trustManager(Pki.trustManager())
                .applicationProtocols(*Http3.supportedApplicationProtocols())
                .build()
        val codec =
            Http3
                .newQuicClientCodecBuilder()
                .sslContext(ssl)
                // the peer host for the trust manager's host name check (HTTPS endpoint identification): the URL's IP
                .sslEngineProvider { ch -> ssl.newEngine(ch.alloc(), "127.0.0.1", server.port) }
                .maxIdleTimeout(10_000, TimeUnit.MILLISECONDS)
                .initialMaxData(16L shl 20)
                .initialMaxStreamDataBidirectionalLocal(4L shl 20)
                .build()
        udp =
            Bootstrap()
                .group(group)
                .channel(NioDatagramChannel::class.java)
                .handler(codec)
                .bind(0)
                .sync()
                .channel()
        quic =
            QuicChannel
                .newBootstrap(udp)
                .handler(Http3ClientConnectionHandler())
                .remoteAddress(InetSocketAddress("127.0.0.1", server.port))
                .connect()
                .get(10, TimeUnit.SECONDS)
    }

    @AfterAll fun stop() {
        quic.close().sync()
        udp.close().sync()
        group.shutdownGracefully(0, 1, TimeUnit.SECONDS).sync()
        server.close()
    }

    private class Answer(
        val status: String,
        val fields: Map<String, String>,
        val body: ByteArray,
        /** What Netty's stream pipeline reported (its own validation of the response), if anything. */
        val failure: Throwable?,
    )

    /** One request on a new request stream: the head, the body if any, then the end of the stream (FIN). */
    private suspend fun exchange(
        method: String,
        path: String,
        body: ByteArray? = null,
    ): Answer {
        val done = CompletableDeferred<Answer>()
        val out = ByteArrayOutputStream()
        var status = ""
        var failure: Throwable? = null
        val fields = HashMap<String, String>()
        val stream =
            Http3
                .newRequestStream(
                    quic,
                    object : Http3RequestStreamInboundHandler() {
                        override fun channelRead(
                            ctx: ChannelHandlerContext,
                            frame: Http3HeadersFrame,
                        ) {
                            val s = frame.headers().status()?.toString()
                            // an interim (1xx) head is skipped; the final one sets the status
                            if (s != null && !s.startsWith("1")) {
                                status = s
                                for (e in frame.headers()) fields[e.key.toString()] = e.value.toString()
                            }
                            ReferenceCountUtil.release(frame)
                        }

                        override fun channelRead(
                            ctx: ChannelHandlerContext,
                            frame: Http3DataFrame,
                        ) {
                            out.write(ByteBufUtil.getBytes(frame.content()))
                            ReferenceCountUtil.release(frame)
                        }

                        override fun channelInputClosed(ctx: ChannelHandlerContext) {
                            done.complete(Answer(status, fields, out.toByteArray(), failure))
                            ctx.close()
                        }

                        @Deprecated("Deprecated in Java")
                        @Suppress("OVERRIDE_DEPRECATION")
                        override fun exceptionCaught(
                            ctx: ChannelHandlerContext,
                            cause: Throwable,
                        ) {
                            failure = failure ?: cause
                        }
                    },
                ).sync()
                .now
        val head = DefaultHttp3HeadersFrame()
        head
            .headers()
            // an AsciiString: Netty's HEAD check (Http3RequestStreamValidationHandler) compares with AsciiString.equals,
            // which is false for a String, and would then hold a HEAD response to its Content-Length
            .method(AsciiString.of(method))
            .path(path)
            .authority("127.0.0.1:${server.port}")
            .scheme("https")
        if (body != null) head.headers().add("content-length", body.size.toString())
        val last =
            if (body == null) {
                stream.writeAndFlush(head)
            } else {
                stream.write(head)
                stream.writeAndFlush(DefaultHttp3DataFrame(Unpooled.wrappedBuffer(body)))
            }
        last.addListener(QuicStreamChannel.SHUTDOWN_OUTPUT)
        return withTimeout(20.seconds) { done.await() }
    }

    @Test fun get() =
        interopTest {
            val a = exchange("GET", "/hello")
            assertEquals("200", a.status)
            assertEquals("hello", a.body.decodeToString())
            assertEquals("HTTP/3", exchange("GET", "/version").body.decodeToString().take(6))
        }

    /** A 1 MiB request body and its echo, across QUIC flow control in both directions. */
    @Test fun post1MiB() =
        interopTest {
            val body = Random(5).nextBytes(1 shl 20)
            val a = exchange("POST", "/echo", body)
            assertEquals("200", a.status)
            assertEquals((1 shl 20).toString(), a.fields["x-received-length"])
            val sha = MessageDigest.getInstance("SHA-256")
            assertContentEquals(sha.digest(body), MessageDigest.getInstance("SHA-256").digest(a.body))
        }

    /**
     * RFC 9110 section 15.3.5: a 204 has no content. A HEAD response carries the GET's Content-Length with no DATA (RFC
     * 9110 section 9.3.2), which RFC 9114 section 4.1.2 allows: "A response that is defined as never having content, even
     * when a Content-Length is present, can have a non-zero Content-Length header field even though no content is
     * included in DATA frames." Netty's validation accepts both.
     */
    @Test fun headAnd204() =
        interopTest {
            val noContent = exchange("GET", "/status/204")
            assertEquals("204", noContent.status)
            assertEquals(0, noContent.body.size)
            assertEquals(null, noContent.failure)
            val head = exchange("HEAD", "/bytes/1000")
            assertEquals("200", head.status)
            assertEquals("1000", head.fields["content-length"])
            assertEquals(0, head.body.size)
            assertEquals(null, head.failure)
        }

    /** 100 response fields through QPACK (RFC 9204), and the decoded UTF-8 target. */
    @Test fun manyFieldsAndUtf8Target() =
        interopTest {
            val many = exchange("GET", "/many-headers?n=100&size=40")
            assertEquals(100, many.fields.keys.count { it.startsWith("x-r-") })
            assertEquals(
                "привет|✓ ok",
                exchange("GET", "/utf8/%D0%BF%D1%80%D0%B8%D0%B2%D0%B5%D1%82?q=%E2%9C%93%20ok").body.decodeToString(),
            )
        }

    /** Ten request streams at once on the one connection. */
    @Test fun concurrentStreams() =
        interopTest {
            val all =
                coroutineScope {
                    (0 until 10).map { i -> async { exchange("GET", "/bytes/${2000 + i}").body.size } }.map { it.await() }
                }
            assertEquals((0 until 10).map { 2000 + it }, all)
        }
}
