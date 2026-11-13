// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.engineinterop

import io.netty.bootstrap.ServerBootstrap
import io.netty.buffer.Unpooled
import io.netty.channel.Channel
import io.netty.channel.ChannelHandlerContext
import io.netty.channel.ChannelInboundHandlerAdapter
import io.netty.channel.ChannelInitializer
import io.netty.channel.MultiThreadIoEventLoopGroup
import io.netty.channel.nio.NioIoHandler
import io.netty.channel.socket.SocketChannel
import io.netty.channel.socket.nio.NioServerSocketChannel
import io.netty.handler.codec.http.DefaultFullHttpResponse
import io.netty.handler.codec.http.DefaultHttpContent
import io.netty.handler.codec.http.DefaultHttpResponse
import io.netty.handler.codec.http.DefaultLastHttpContent
import io.netty.handler.codec.http.HttpHeaderNames
import io.netty.handler.codec.http.HttpHeaderValues
import io.netty.handler.codec.http.HttpObjectAggregator
import io.netty.handler.codec.http.HttpRequest
import io.netty.handler.codec.http.HttpResponseStatus
import io.netty.handler.codec.http.HttpServerCodec
import io.netty.handler.codec.http.HttpVersion
import io.netty.handler.codec.http.LastHttpContent
import io.netty.handler.codec.http2.DefaultHttp2DataFrame
import io.netty.handler.codec.http2.DefaultHttp2GoAwayFrame
import io.netty.handler.codec.http2.DefaultHttp2Headers
import io.netty.handler.codec.http2.DefaultHttp2HeadersFrame
import io.netty.handler.codec.http2.Http2DataFrame
import io.netty.handler.codec.http2.Http2Error
import io.netty.handler.codec.http2.Http2FrameCodecBuilder
import io.netty.handler.codec.http2.Http2HeadersFrame
import io.netty.handler.codec.http2.Http2MultiplexHandler
import io.netty.handler.ssl.ApplicationProtocolConfig
import io.netty.handler.ssl.ApplicationProtocolNames
import io.netty.handler.ssl.ApplicationProtocolNegotiationHandler
import io.netty.handler.ssl.SslContextBuilder
import io.netty.handler.ssl.SslProvider
import io.netty.util.ReferenceCountUtil
import kotlinx.coroutines.CompletableDeferred
import java.net.InetSocketAddress
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger

/**
 * A plain Netty 4.2 server (no Ktor) over JDK TLS, ALPN `h2` and `http/1.1` (or `http/1.1` only), for what Ktor's server
 * API cannot send: interim 1xx responses before the final one, trailer fields, and a GOAWAY while a stream is open.
 *
 * Paths: `/early-hints` (103 with a Link field, then 200 "hinted"), `/trailers` (200 "with trailers" and a trailer
 * section with `x-checksum`), `/goaway` (the first piece of the body, then GOAWAY NO_ERROR on HTTP/2 before the rest),
 * anything else 200 with the path as its body.
 */
internal class PlainNettyServer(
    h2: Boolean,
) : AutoCloseable {
    /** TCP connections accepted so far. */
    val connections = AtomicInteger()

    /** Completed with the GOAWAY's last stream identifier once the server sent it. */
    val goAwaySent = CompletableDeferred<Int>()

    private val group = MultiThreadIoEventLoopGroup(2, NioIoHandler.newFactory())
    private val channel: Channel
    val port: Int

    init {
        val protocols =
            if (h2) {
                arrayOf(
                    ApplicationProtocolNames.HTTP_2,
                    ApplicationProtocolNames.HTTP_1_1,
                )
            } else {
                arrayOf(ApplicationProtocolNames.HTTP_1_1)
            }
        val ssl =
            SslContextBuilder
                .forServer(Pki.serverKey, Pki.server, Pki.ca)
                .sslProvider(SslProvider.JDK)
                .protocols("TLSv1.3")
                .applicationProtocolConfig(
                    ApplicationProtocolConfig(
                        ApplicationProtocolConfig.Protocol.ALPN,
                        ApplicationProtocolConfig.SelectorFailureBehavior.NO_ADVERTISE,
                        ApplicationProtocolConfig.SelectedListenerFailureBehavior.ACCEPT,
                        *protocols,
                    ),
                ).build()
        channel =
            ServerBootstrap()
                .group(group)
                .channel(NioServerSocketChannel::class.java)
                .childHandler(
                    object : ChannelInitializer<SocketChannel>() {
                        override fun initChannel(ch: SocketChannel) {
                            connections.incrementAndGet()
                            ch.pipeline().addLast(ssl.newHandler(ch.alloc()))
                            ch.pipeline().addLast(
                                object : ApplicationProtocolNegotiationHandler(ApplicationProtocolNames.HTTP_1_1) {
                                    override fun configurePipeline(
                                        ctx: ChannelHandlerContext,
                                        protocol: String,
                                    ) {
                                        if (protocol == ApplicationProtocolNames.HTTP_2) {
                                            ctx.pipeline().addLast(Http2FrameCodecBuilder.forServer().build())
                                            ctx.pipeline().addLast(
                                                Http2MultiplexHandler(
                                                    object : ChannelInitializer<Channel>() {
                                                        override fun initChannel(ch: Channel) {
                                                            ch.pipeline().addLast(H2Exchange())
                                                        }
                                                    },
                                                ),
                                            )
                                        } else {
                                            ctx.pipeline().addLast(HttpServerCodec(), HttpObjectAggregator(1 shl 20), H1Exchange())
                                        }
                                    }
                                },
                            )
                        }
                    },
                ).bind(InetSocketAddress("127.0.0.1", 0))
                .syncUninterruptibly()
                .channel()
        port = (channel.localAddress() as InetSocketAddress).port
    }

    fun url(path: String) = "https://127.0.0.1:$port$path"

    override fun close() {
        channel.close().syncUninterruptibly()
        group.shutdownGracefully(0, 1, TimeUnit.SECONDS).syncUninterruptibly()
    }

    private inner class H1Exchange : ChannelInboundHandlerAdapter() {
        override fun channelRead(
            ctx: ChannelHandlerContext,
            msg: Any,
        ) {
            if (msg !is HttpRequest) {
                ReferenceCountUtil.release(msg)
                return
            }
            val path = msg.uri()
            ReferenceCountUtil.release(msg)
            when (path) {
                "/early-hints" -> {
                    val hints = DefaultFullHttpResponse(HttpVersion.HTTP_1_1, HttpResponseStatus(103, "Early Hints"))
                    hints.headers().add("link", "</style.css>; rel=preload; as=style")
                    ctx.write(hints)
                    val r =
                        DefaultFullHttpResponse(
                            HttpVersion.HTTP_1_1,
                            HttpResponseStatus.OK,
                            Unpooled.wrappedBuffer("hinted".encodeToByteArray()),
                        )
                    r.headers().set(HttpHeaderNames.CONTENT_LENGTH, 6)
                    ctx.writeAndFlush(r)
                }

                "/trailers" -> {
                    val head = DefaultHttpResponse(HttpVersion.HTTP_1_1, HttpResponseStatus.OK)
                    head.headers().set(HttpHeaderNames.TRANSFER_ENCODING, HttpHeaderValues.CHUNKED)
                    head.headers().set(HttpHeaderNames.TRAILER, "x-checksum")
                    ctx.write(head)
                    ctx.write(DefaultHttpContent(Unpooled.wrappedBuffer("with ".encodeToByteArray())))
                    ctx.write(DefaultHttpContent(Unpooled.wrappedBuffer("trailers".encodeToByteArray())))
                    val last: LastHttpContent = DefaultLastHttpContent()
                    last.trailingHeaders().add("x-checksum", "abc123")
                    ctx.writeAndFlush(last)
                }

                else -> {
                    val body = path.encodeToByteArray()
                    val r = DefaultFullHttpResponse(HttpVersion.HTTP_1_1, HttpResponseStatus.OK, Unpooled.wrappedBuffer(body))
                    r.headers().set(HttpHeaderNames.CONTENT_LENGTH, body.size)
                    ctx.writeAndFlush(r)
                }
            }
        }
    }

    private inner class H2Exchange : ChannelInboundHandlerAdapter() {
        override fun channelRead(
            ctx: ChannelHandlerContext,
            msg: Any,
        ) {
            when (msg) {
                is Http2HeadersFrame -> if (msg.isEndStream) respond(ctx, msg.headers().path().toString())
                is Http2DataFrame -> msg.release()
                else -> ReferenceCountUtil.release(msg)
            }
        }

        private fun respond(
            ctx: ChannelHandlerContext,
            path: String,
        ) {
            when (path) {
                "/early-hints" -> {
                    ctx.write(
                        DefaultHttp2HeadersFrame(DefaultHttp2Headers().status("103").add("link", "</style.css>; rel=preload; as=style")),
                    )
                    ctx.write(DefaultHttp2HeadersFrame(DefaultHttp2Headers().status("200")))
                    ctx.writeAndFlush(DefaultHttp2DataFrame(Unpooled.wrappedBuffer("hinted".encodeToByteArray()), true))
                }

                "/trailers" -> {
                    ctx.write(DefaultHttp2HeadersFrame(DefaultHttp2Headers().status("200")))
                    ctx.write(DefaultHttp2DataFrame(Unpooled.wrappedBuffer("with trailers".encodeToByteArray()), false))
                    ctx.writeAndFlush(DefaultHttp2HeadersFrame(DefaultHttp2Headers().add("x-checksum", "abc123"), true))
                }

                "/goaway" -> {
                    // RFC 9113 section 6.8: GOAWAY with this stream as the last one, then the rest of its response
                    ctx.write(DefaultHttp2HeadersFrame(DefaultHttp2Headers().status("200")))
                    ctx.writeAndFlush(DefaultHttp2DataFrame(Unpooled.wrappedBuffer("before goaway;".encodeToByteArray()), false))
                    val parent = ctx.channel().parent()
                    parent.writeAndFlush(DefaultHttp2GoAwayFrame(Http2Error.NO_ERROR)).addListener {
                        goAwaySent.complete(
                            (ctx.channel() as io.netty.handler.codec.http2.Http2StreamChannel)
                                .stream()
                                .id(),
                        )
                        ctx.writeAndFlush(DefaultHttp2DataFrame(Unpooled.wrappedBuffer("after goaway".encodeToByteArray()), true))
                    }
                }

                else -> {
                    ctx.write(DefaultHttp2HeadersFrame(DefaultHttp2Headers().status("200")))
                    ctx.writeAndFlush(DefaultHttp2DataFrame(Unpooled.wrappedBuffer(path.encodeToByteArray()), true))
                }
            }
        }
    }
}
