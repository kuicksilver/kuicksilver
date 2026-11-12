// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.http2.core

import io.kuicksilver.http2.Http2ErrorCode
import io.kuicksilver.http2.Http2Settings
import io.kuicksilver.http2.frame.Frame
import io.kuicksilver.http2.frame.FrameDecoder
import io.kuicksilver.http2.frame.FrameEncoder
import io.kuicksilver.http2.frame.H2
import io.kuicksilver.http2.hpack.HpackDecoder
import io.kuicksilver.http2.hpack.HpackEncoder
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.fail

internal const val MS = 1_000_000L
internal const val SECOND = 1_000_000_000L

internal val GET = listOf(":method" to "GET", ":scheme" to "https", ":authority" to "example.com", ":path" to "/")
internal val OK = listOf(":status" to "200")

/**
 * A raw peer of one [H2ConnectionCore] under test: it writes any frames into the core and reads the core's output as
 * frames, with its own HPACK state. Time is virtual: [now] in nanoseconds.
 */
internal class RawH2Peer(
    role: Role,
    settings: Http2Settings = Http2Settings(),
    var now: Long = 0,
    enableConnectProtocol: Boolean = false,
) {
    val core = H2ConnectionCore(role, settings, now, enableConnectProtocol)
    private val clientCore = role == Role.CLIENT
    private val dec = FrameDecoder(H2.MAX_MAX_FRAME_SIZE)
    private var prefaceLeft = if (clientCore) H2.PREFACE.size else 0
    val hpackOut = HpackEncoder()
    private val hpackIn = HpackDecoder(4096, 1 shl 20)
    private val buf = ByteArray(65_536)

    /** Every frame the core wrote so far, in order (decoded on [read]). */
    val written = mutableListOf<Frame>()

    /** Feeds raw bytes to the core. */
    fun send(vararg frames: ByteArray) {
        var all = ByteArray(0)
        for (f in frames) all += f
        core.receive(all, 0, all.size, now)
    }

    /** Server under test: the client preface; then our SETTINGS (empty or [settings]) and an ACK of the core's. */
    fun handshake(settings: ByteArray = FrameEncoder.settings(IntArray(0), LongArray(0))): List<Frame> {
        if (!clientCore) send(H2.PREFACE)
        send(settings, FrameEncoder.settingsAck())
        return read()
    }

    /** Polls everything the core has and decodes it; field blocks are decoded too (keeps our HPACK in step). */
    fun read(): List<Frame> {
        val out = mutableListOf<Frame>()
        while (true) {
            val n = core.poll(buf, 0, now)
            if (n == 0) break
            var p = 0
            if (prefaceLeft > 0) {
                val k = minOf(prefaceLeft, n)
                prefaceLeft -= k
                p = k
            }
            while (p < n) {
                p += dec.feed(buf, p, n - p)
                dec.next()?.let { out += it }
            }
        }
        written += out
        return out
    }

    /** Every event drained so far. */
    val allEvents = mutableListOf<H2Event>()

    fun events(): List<H2Event> = generateSequence { core.nextEvent() }.toList().also { allEvents += it }

    fun headers(
        id: Int,
        fields: List<Pair<String, String>> = GET,
        endStream: Boolean = true,
        endHeaders: Boolean = true,
        dependency: Int = -1,
    ): ByteArray = FrameEncoder.headers(id, hpackOut.encode(fields), endStream, endHeaders, dependency)

    fun data(
        id: Int,
        size: Int,
        endStream: Boolean = false,
    ): ByteArray = FrameEncoder.data(id, ByteArray(size), 0, size, endStream)

    /** Decodes a field block the core sent (for tests that look at what it wrote). */
    fun decodeBlock(fragment: ByteArray): List<Pair<String, String>> =
        mutableListOf<Pair<String, String>>().also { l -> hpackIn.decode(fragment) { n, v -> l += n to v } }

    fun goAway(): Frame.GoAway? = written.filterIsInstance<Frame.GoAway>().lastOrNull()

    fun resets(): List<Frame.RstStream> = written.filterIsInstance<Frame.RstStream>()
}

/** Asserts that the core ended the connection with a GOAWAY carrying [code], and reported it. */
internal fun RawH2Peer.assertConnectionError(code: Http2ErrorCode) {
    read()
    val g = goAway() ?: fail("no GOAWAY, expected $code; wrote ${written.map { it::class.simpleName }}")
    assertEquals(code.code, g.errorCode, g.debug.decodeToString())
    kotlin.test.assertTrue(core.isClosed)
    events()
    val closed = allEvents.filterIsInstance<H2Event.Closed>().single()
    assertEquals(code, closed.code)
}

/** Asserts that the core reset [streamId] with [code] and kept the connection. */
internal fun RawH2Peer.assertStreamError(
    streamId: Int,
    code: Http2ErrorCode,
) {
    read()
    val r =
        resets().lastOrNull { it.streamId == streamId }
            ?: fail("no RST_STREAM on $streamId, expected $code; wrote ${written.map { it::class.simpleName }}")
    assertEquals(code.code, r.errorCode)
    kotlin.test.assertFalse(core.isClosed, "the connection must stay open")
}

/** A client and a server core joined by an in-memory byte pipe; [pump] moves bytes both ways until both are quiet. */
internal class H2Pair(
    clientSettings: Http2Settings = Http2Settings(),
    serverSettings: Http2Settings = Http2Settings(),
    var now: Long = 0,
) {
    val client = H2ConnectionCore(Role.CLIENT, clientSettings, now)
    val server = H2ConnectionCore(Role.SERVER, serverSettings, now)
    private val buf = ByteArray(16_384)
    val clientEvents = mutableListOf<H2Event>()
    val serverEvents = mutableListOf<H2Event>()

    /** Bytes moved each way so far. */
    var toServer = 0L
    var toClient = 0L

    fun pump(rounds: Int = 1_000) {
        repeat(rounds) {
            var moved = false
            while (true) {
                val n = client.poll(buf, 0, now)
                if (n == 0) break
                server.receive(buf, 0, n, now)
                toServer += n
                moved = true
            }
            while (true) {
                val n = server.poll(buf, 0, now)
                if (n == 0) break
                client.receive(buf, 0, n, now)
                toClient += n
                moved = true
            }
            generateSequence { client.nextEvent() }.forEach { clientEvents += it }
            generateSequence { server.nextEvent() }.forEach { serverEvents += it }
            if (!moved) return
        }
    }

    inline fun <reified T : H2Event> clientGot(): List<T> = clientEvents.filterIsInstance<T>()

    inline fun <reified T : H2Event> serverGot(): List<T> = serverEvents.filterIsInstance<T>()
}

internal inline fun <reified T> List<*>.only(): T = assertIs<T>(filterIsInstance<T>().single())
