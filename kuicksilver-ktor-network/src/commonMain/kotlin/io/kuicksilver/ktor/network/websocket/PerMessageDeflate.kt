// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(ExperimentalAtomicApi::class)

package io.kuicksilver.ktor.network.websocket

import io.ktor.util.AttributeKey
import io.ktor.util.Attributes
import io.ktor.websocket.Frame
import io.ktor.websocket.FrameTooBigException
import io.ktor.websocket.ProtocolViolationException
import io.ktor.websocket.WebSocketExtension
import io.ktor.websocket.WebSocketExtensionFactory
import io.ktor.websocket.WebSocketExtensionHeader
import io.ktor.websocket.parseWebSocketExtensions
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.annotations.InternalKuicksilverApi
import io.kuicksilver.ktor.network.Utf8Validator
import kotlinx.io.Buffer
import kotlinx.io.readByteArray
import kotlin.concurrent.atomics.AtomicInt
import kotlin.concurrent.atomics.ExperimentalAtomicApi

/**
 * The WebSocket per-message compression extension `permessage-deflate` (RFC 7692) for Ktor's `WebSockets` plugins, on
 * every target: java.util.zip on the JVM and Android, the platform's zlib on Kotlin/Native (`libz.so.1` on Linux, the
 * system's on Apple, linked statically on Windows).
 *
 * ```kotlin
 * HttpClient(Kuicksilver) {
 *     install(WebSockets) { extensions { install(PerMessageDeflate) } }
 * }
 * // a server, on any engine
 * install(WebSockets) { extensions { install(PerMessageDeflate) { maxInflatedMessageSize = 1024 * 1024 } } }
 * ```
 *
 * It works with any Ktor engine. A compressed message that inflates to more than [Config.maxInflatedMessageSize] is
 * refused: Kuicksilver's engines decompress the frames themselves as they arrive, in pieces of 64 KiB, and close the
 * connection with 1009 (message too big, RFC 6455 section 7.4.1) when a message passes the limit; on another engine the
 * extension decompresses the reassembled message in Ktor's session, in the same pieces, and fails it with
 * [FrameTooBigException] (what goes on the wire then is the engine's and Ktor's session's choice). Malformed compressed
 * data fails the connection with 1002 (protocol error) on Kuicksilver's engines, with [ProtocolViolationException]
 * elsewhere.
 *
 * Negotiation (RFC 7692 sections 5, 7 and 7.1). As a client it offers `permessage-deflate` with
 * `client_no_context_takeover` and `server_no_context_takeover` as configured; it does not offer `client_max_window_bits`,
 * so it compresses with a 32 KiB window. A response that is not a valid acceptance of that offer (an unknown, repeated or
 * malformed parameter, `client_max_window_bits`, more than one `permessage-deflate`, or a requested
 * `server_no_context_takeover` left out) fails the handshake with [ProtocolViolationException]; any
 * `server_max_window_bits` from 8 to 15 is accepted (the inflater's 32 KiB window reads every smaller one). As a server it
 * accepts the first offer it can honour and declines invalid ones (section 7): it echoes `server_no_context_takeover`
 * and `client_no_context_takeover` (adding them when configured), answers `server_max_window_bits` with the offered value
 * when its deflater can keep to it (9 to 15 on Kotlin/Native, 15 on the JVM, whose `Deflater` has a fixed window, and
 * declines the offer otherwise), and takes `client_max_window_bits` as a hint it leaves unanswered.
 *
 * Only Text and Binary messages are compressed (control frames never are, RFC 7692 section 6), with RSV1 on the first
 * frame of a message only (section 6.1); a fragmented message is one DEFLATE stream across its frames. Compression and
 * secrets: a message compressed in a window shared with attacker-chosen data can leak a secret through its size (CRIME,
 * BREACH; section 8); keep such messages uncompressed with [Config.compressIf], or use the `*_no_context_takeover`
 * settings to stop one message from sharing a window with the next.
 *
 * Memory per connection: the deflater (≈ 256 KiB of zlib state with a 32 KiB window) and the inflater (≈ 40 KiB), each
 * made on first use, plus the 64 KiB piece the output is produced in. Kuicksilver's engines free the zlib state when the
 * session ends; on other engines it is freed when the extension is garbage collected.
 */
@ExperimentalKuicksilverApi
public class PerMessageDeflate internal constructor(
    private val config: Config,
) : WebSocketExtension<PerMessageDeflate.Config> {
    /** Settings of [PerMessageDeflate]; [install] checks them. */
    public class Config {
        /** The zlib compression level of outgoing messages, 0 (stored) to 9 (smallest). */
        public var compressionLevel: Int = 6

        /**
         * The client compresses each message on its own (`client_no_context_takeover`): as a client, offered (and then
         * kept to whatever the server answers); as a server, asked of the client in the answer.
         */
        public var clientNoContextTakeover: Boolean = false

        /**
         * The server compresses each message on its own (`server_no_context_takeover`): as a client, requested (an
         * answer without it fails the handshake); as a server, announced in every answer.
         */
        public var serverNoContextTakeover: Boolean = false

        /** The largest size, in bytes, an incoming compressed message may inflate to; at least 1. */
        public var maxInflatedMessageSize: Long = DEFAULT_MAX_INFLATED_MESSAGE_SIZE

        /**
         * Messages smaller than this many bytes are sent uncompressed; a fragmented message, whose size is not known at
         * its first frame, is compressed.
         */
        public var minSizeToCompress: Int = 0

        internal var compressCondition: (Frame) -> Boolean = { true }

        /**
         * Compresses a message only when [predicate] (and every earlier one) agrees, decided on its first frame. For
         * messages that put a secret next to data an attacker can choose: compressed in one window, their size can tell
         * the secret (CRIME, BREACH; RFC 7692 section 8); sent uncompressed, they do not share it.
         */
        public fun compressIf(predicate: (Frame) -> Boolean) {
            val earlier = compressCondition
            compressCondition = { earlier(it) && predicate(it) }
        }
    }

    /** Creates [PerMessageDeflate] for `extensions { install(PerMessageDeflate) { ... } }`; sets RSV1 only. */
    public companion object : WebSocketExtensionFactory<Config, PerMessageDeflate> {
        /** The default of [Config.maxInflatedMessageSize]: 16 MiB. */
        public const val DEFAULT_MAX_INFLATED_MESSAGE_SIZE: Long = 16L * 1024 * 1024

        /** Where Ktor keeps the extension in a session's attributes. */
        override val key: AttributeKey<PerMessageDeflate> = AttributeKey("io.kuicksilver.PerMessageDeflate")

        /** The extension uses RSV1 (RFC 7692 section 6). */
        override val rsv1: Boolean = true

        /** The extension does not use RSV2. */
        override val rsv2: Boolean = false

        /** The extension does not use RSV3. */
        override val rsv3: Boolean = false

        /** A new extension for one session with [config] applied; invalid settings throw [IllegalArgumentException]. */
        override fun install(config: Config.() -> Unit): PerMessageDeflate {
            val c = Config().apply(config)
            require(c.compressionLevel in 0..9) { "compressionLevel ${c.compressionLevel} is not in 0..9" }
            require(c.maxInflatedMessageSize >= 1) { "maxInflatedMessageSize ${c.maxInflatedMessageSize} is less than 1" }
            require(c.minSizeToCompress >= 0) { "minSizeToCompress ${c.minSizeToCompress} is negative" }
            return PerMessageDeflate(c)
        }
    }

    /** The factory that makes this extension: its companion. */
    override val factory: WebSocketExtensionFactory<Config, out WebSocketExtension<Config>> get() = PerMessageDeflate

    /** The client's offer (RFC 7692 section 7.1). */
    override val protocols: List<WebSocketExtensionHeader> =
        listOf(
            WebSocketExtensionHeader(
                PERMESSAGE_DEFLATE,
                listOfNotNull(
                    CLIENT_NO_CONTEXT_TAKEOVER.takeIf { config.clientNoContextTakeover },
                    SERVER_NO_CONTEXT_TAKEOVER.takeIf { config.serverNoContextTakeover },
                ),
            ),
        )

    // what both sides agreed, from this endpoint's view; set by the negotiation
    private var agreement: DeflateAgreement? = null

    private var deflater: MessageDeflater? = null
    private var inflater: MessageInflater? = null

    // outgoing message state: inside a fragmented message, and whether it is compressed
    private var sendingFragments = false
    private var compressingMessage = false
    private var checkingText = false
    private val sentText = Utf8Validator()

    // an incoming message failed to decompress: the session is failing, no later one is decompressed
    private var inflateFailed = false

    // users of the codecs (USE each) and the DISPOSED / FREED bits: the codecs are freed once, after the last user
    private val state = AtomicInt(0)

    /** True when the server accepted permessage-deflate, false when it did not; an invalid answer throws [ProtocolViolationException] (RFC 7692 section 7.1). */
    override fun clientNegotiation(negotiatedProtocols: List<WebSocketExtensionHeader>): Boolean {
        val a = clientAgreement(negotiatedProtocols) ?: return false
        agreement = a
        return true
    }

    /** Answers the first valid permessage-deflate offer this extension can keep to (RFC 7692 section 7); an empty list declines them all. */
    override fun serverNegotiation(requestedProtocols: List<WebSocketExtensionHeader>): List<WebSocketExtensionHeader> {
        for (offer in requestedProtocols) {
            if (!offer.name.trim().equals(PERMESSAGE_DEFLATE, ignoreCase = true)) continue
            val p = parseParameters(offer, response = false) ?: continue // an invalid offer is declined (section 7)
            val window = p.serverMaxWindowBits ?: MAX_WINDOW_BITS
            if (window < DEFLATE_MIN_WINDOW_BITS) continue // a window this deflater cannot keep to (section 7.1.2.1)
            val serverNoContextTakeover = p.serverNoContextTakeover || config.serverNoContextTakeover
            val clientNoContextTakeover = p.clientNoContextTakeover || config.clientNoContextTakeover
            agreement =
                DeflateAgreement(
                    outboundNoContextTakeover = serverNoContextTakeover,
                    outboundWindowBits = window,
                    inboundNoContextTakeover = clientNoContextTakeover,
                )
            val answer =
                listOfNotNull(
                    SERVER_NO_CONTEXT_TAKEOVER.takeIf { serverNoContextTakeover },
                    CLIENT_NO_CONTEXT_TAKEOVER.takeIf { clientNoContextTakeover },
                    p.serverMaxWindowBits?.let { "$SERVER_MAX_WINDOW_BITS=$it" },
                )
            return listOf(WebSocketExtensionHeader(PERMESSAGE_DEFLATE, answer))
        }
        return emptyList()
    }

    /**
     * Compresses a Text or Binary frame (RSV1 on the first frame of a message, RFC 7692 section 6.1); other frames are
     * returned unchanged. Called by Ktor's session for each outgoing frame, in order. A text message it compresses must be
     * UTF-8 as a whole (RFC 6455 section 5.6, MUST; once compressed, nothing after the extension can check it): at the
     * first frame that shows it is not, the frame fails with [ProtocolViolationException], which ends Ktor's session
     * without sending it.
     */
    override fun processOutgoingFrame(frame: Frame): Frame {
        if (frame !is Frame.Text && frame !is Frame.Binary) return frame
        val a = agreement ?: return frame
        val first = !sendingFragments
        if (first) {
            compressingMessage = (!frame.fin || frame.data.size >= config.minSizeToCompress) && config.compressCondition(frame)
            checkingText = compressingMessage && frame is Frame.Text
            sentText.reset()
        }
        sendingFragments = !frame.fin
        if (!compressingMessage) return frame
        if (checkingText && (!sentText.feed(frame.data, 0, frame.data.size) || (frame.fin && !sentText.complete))) {
            throw ProtocolViolationException("a text message that is not UTF-8 (RFC 6455 section 5.6) was not sent")
        }
        val data =
            withCodecs {
                val d =
                    deflater ?: MessageDeflater(config.compressionLevel, a.outboundWindowBits, a.outboundNoContextTakeover).also {
                        deflater = it
                    }
                d.compress(frame.data, frame.fin)
            }
        return Frame.byType(frame.fin, frame.frameType, data, first, frame.rsv2, frame.rsv3)
    }

    /**
     * Decompresses a message whose first frame had RSV1 (Ktor's session hands extensions reassembled messages); other
     * frames are returned unchanged. A message over [Config.maxInflatedMessageSize] fails with [FrameTooBigException],
     * malformed data with [ProtocolViolationException].
     */
    override fun processIncomingFrame(frame: Frame): Frame {
        if (!frame.rsv1 || (frame !is Frame.Text && frame !is Frame.Binary)) return frame
        val a = agreement ?: return frame
        if (inflateFailed) throw ProtocolViolationException("A compressed message after one that failed to decompress")
        val data =
            withCodecs {
                val i = inflater ?: MessageInflater(a.inboundNoContextTakeover, config.maxInflatedMessageSize).also { inflater = it }
                try {
                    inflateMessage(i, frame.data)
                } catch (e: MessageTooBigException) {
                    throw FrameTooBigException(e.size, e)
                } catch (_: DeflateDataException) {
                    // Ktor may send this message as a Close reason: zlib's own text stays out of it
                    throw ProtocolViolationException("Invalid compressed data")
                }
            }
        return Frame.byType(true, frame.frameType, data, false, frame.rsv2, frame.rsv3)
    }

    private fun inflateMessage(
        inflater: MessageInflater,
        data: ByteArray,
    ): ByteArray {
        val out = Buffer()
        val chunk = ByteArray(INFLATE_CHUNK)
        try {
            inflater.input(data, 0, data.size)
            drain(inflater, chunk, out)
            inflater.endOfMessage()
            drain(inflater, chunk, out)
            inflater.messageDone()
        } catch (e: Throwable) {
            // the window holds part of a message that failed: no later message is decompressed against it
            inflateFailed = true
            throw e
        }
        return out.readByteArray()
    }

    private fun drain(
        inflater: MessageInflater,
        chunk: ByteArray,
        out: Buffer,
    ) {
        while (true) {
            val n = inflater.read(chunk, 0, chunk.size)
            if (n == 0) return
            out.write(chunk, 0, n)
        }
    }

    /**
     * The client's view of the server's answer [response] to [protocols]: null when it did not accept `permessage-deflate`;
     * an answer that is not a valid acceptance fails with [ProtocolViolationException] (RFC 7692 section 7: the client
     * fails the WebSocket connection).
     */
    private fun clientAgreement(response: List<WebSocketExtensionHeader>): DeflateAgreement? {
        val accepted = response.filter { it.name.trim().equals(PERMESSAGE_DEFLATE, ignoreCase = true) }
        if (accepted.isEmpty()) return null

        fun fail(why: String): Nothing = throw ProtocolViolationException("Invalid permessage-deflate response: $why")
        if (accepted.size > 1) fail("the extension was accepted ${accepted.size} times")
        val p = parseParameters(accepted.single(), response = true) ?: fail("an unknown, repeated or malformed parameter")
        if (p.clientMaxWindowBits != null) fail("$CLIENT_MAX_WINDOW_BITS, which the client did not offer (RFC 7692 section 7.1.2.2)")
        if (config.serverNoContextTakeover && !p.serverNoContextTakeover) {
            fail("$SERVER_NO_CONTEXT_TAKEOVER was requested and is missing (RFC 7692 section 7.1.1.1)")
        }
        return DeflateAgreement(
            outboundNoContextTakeover = p.clientNoContextTakeover || config.clientNoContextTakeover,
            outboundWindowBits = MAX_WINDOW_BITS,
            inboundNoContextTakeover = p.serverNoContextTakeover,
        )
    }

    /**
     * Kuicksilver's client engines: what the server's answer (the `Sec-WebSocket-Extensions` values [responseValues])
     * means for the frames that arrive, before Ktor's plugin negotiates with this extension; null when the server did not
     * accept `permessage-deflate`. An invalid answer fails with [ProtocolViolationException], as the plugin's negotiation
     * would.
     */
    @InternalKuicksilverApi
    public fun clientInflate(responseValues: List<String>): WebSocketInflate? =
        clientAgreement(responseValues.flatMap { parseWebSocketExtensions(it) })?.let {
            WebSocketInflate(it.inboundNoContextTakeover, config.maxInflatedMessageSize)
        }

    /** Kuicksilver's server engines: the inflation the answer of [serverNegotiation] agreed; null when none was. */
    @InternalKuicksilverApi
    public fun serverInflate(): WebSocketInflate? =
        agreement?.let { WebSocketInflate(it.inboundNoContextTakeover, config.maxInflatedMessageSize) }

    /**
     * Frees the zlib state once the session has ended (Kuicksilver's engines call it then); a frame processed after that
     * fails with [IllegalStateException]. Idempotent; it waits for no call in progress, the last one frees.
     */
    @InternalKuicksilverApi
    public fun dispose() {
        while (true) {
            val s = state.load()
            if (s and DISPOSED != 0) return
            if (state.compareAndSet(s, s or DISPOSED)) {
                if (s == 0) free()
                return
            }
        }
    }

    private inline fun <T> withCodecs(block: () -> T): T {
        while (true) {
            val s = state.load()
            check(s and DISPOSED == 0) { "the WebSocket session of this permessage-deflate extension has ended" }
            if (state.compareAndSet(s, s + USE)) break
        }
        try {
            return block()
        } finally {
            if (state.addAndFetch(-USE) == DISPOSED) free()
        }
    }

    private fun free() {
        if (!state.compareAndSet(DISPOSED, DISPOSED or FREED)) return
        deflater?.close()
        deflater = null
        inflater?.close()
        inflater = null
    }

    /** For logs: the client's offer. */
    override fun toString(): String = "PerMessageDeflate(${protocols.single()})"
}

/**
 * What a permessage-deflate negotiation means for the frames that arrive (Kuicksilver's engines decompress them as they
 * come): each message from an empty window when [noContextTakeover], and no message larger than [maxMessageSize] bytes
 * once inflated.
 */
@InternalKuicksilverApi
public class WebSocketInflate(
    public val noContextTakeover: Boolean,
    public val maxMessageSize: Long,
)

/**
 * What the `permessage-deflate` element of a handshake's answer ([responseValues], the `Sec-WebSocket-Extensions` values
 * of the 101 or of the RFC 9220 2xx) means for the frames that arrive, whichever implementation negotiated it (this
 * library's [PerMessageDeflate] or Ktor's own `WebSocketDeflateExtension`), so that Kuicksilver's engines decompress
 * every permessage-deflate message themselves (RFC 7692 section 6: "the payload data portion after decompression is
 * subject to the constraints for the original data type again"). The peer's `*_no_context_takeover` ([client]: the
 * server's) decides whether its messages share a window; any window size is read with a 32 KiB one. Null when the
 * answer has no `permessage-deflate`; one that is repeated or has a malformed or unknown parameter fails with
 * [ProtocolViolationException] (RFC 7692 section 7: such an answer fails the connection).
 */
@InternalKuicksilverApi
public fun negotiatedWebSocketInflate(
    responseValues: List<String>,
    client: Boolean,
    maxMessageSize: Long,
): WebSocketInflate? {
    val accepted =
        responseValues
            .flatMap { parseWebSocketExtensions(it) }
            .filter { it.name.trim().equals(PERMESSAGE_DEFLATE, ignoreCase = true) }
    if (accepted.isEmpty()) return null
    if (accepted.size >
        1
    ) {
        throw ProtocolViolationException("Invalid permessage-deflate response: the extension was accepted ${accepted.size} times")
    }
    val p =
        parseParameters(accepted.single(), response = true)
            ?: throw ProtocolViolationException("Invalid permessage-deflate response: an unknown, repeated or malformed parameter")
    return WebSocketInflate(if (client) p.serverNoContextTakeover else p.clientNoContextTakeover, maxMessageSize)
}

/**
 * The WebSocket extensions in [Attributes]: the ones Ktor's client plugin installed for a request, or the ones Ktor's server
 * plugin negotiated for a call. Ktor keeps them under an attribute of its own; this looks for them by type, not by Ktor's
 * key.
 */
@InternalKuicksilverApi
public fun Attributes.webSocketExtensions(): List<WebSocketExtension<*>> {
    val found = ArrayList<WebSocketExtension<*>>()
    for (key in allKeys) {
        @Suppress("UNCHECKED_CAST")
        val value = getOrNull(key as AttributeKey<Any>)
        if (value is List<*>) for (e in value) if (e is WebSocketExtension<*> && found.none { it === e }) found += e
    }
    return found
}

/** The [PerMessageDeflate] among the WebSocket extensions in [Attributes] ([webSocketExtensions]), or null. */
@InternalKuicksilverApi
public fun Attributes.perMessageDeflate(): PerMessageDeflate? = webSocketExtensions().firstNotNullOfOrNull { it as? PerMessageDeflate }

/**
 * Why [extensions], all in use on one WebSocket, cannot be used together, or null: two of them claim the same RSV bit
 * (their factories' `rsv1`, `rsv2`, `rsv3`). RFC 7692 section 5: a server MUST NOT accept a PMCE together with another
 * extension that uses RSV1, and a client that gets such an answer MUST fail the connection.
 */
@InternalKuicksilverApi
public fun webSocketRsvConflict(extensions: List<WebSocketExtension<*>>): String? {
    val bits =
        listOf<Pair<String, (WebSocketExtensionFactory<*, *>) -> Boolean>>(
            "RSV1" to { it.rsv1 },
            "RSV2" to { it.rsv2 },
            "RSV3" to { it.rsv3 },
        )
    for ((bit, uses) in bits) {
        val users = extensions.filter { uses(it.factory) }
        if (users.size > 1) {
            val names = users.joinToString { e -> e.protocols.joinToString("/") { it.name }.ifEmpty { e.factory.key.name } }
            return "$names all use $bit"
        }
    }
    return null
}

/** The agreed parameters from one endpoint's view: its own compressor (outbound) and its peer's (inbound). */
private class DeflateAgreement(
    val outboundNoContextTakeover: Boolean,
    val outboundWindowBits: Int,
    val inboundNoContextTakeover: Boolean,
)

/** The parameters of one `permessage-deflate` element; a window parameter without value is 0. */
private class DeflateParameters(
    val serverNoContextTakeover: Boolean,
    val clientNoContextTakeover: Boolean,
    val serverMaxWindowBits: Int?,
    val clientMaxWindowBits: Int?,
)

/**
 * The parameters of [element] (an offer, or a [response]), or null when one is unknown, repeated or has an invalid value
 * (RFC 7692 sections 5.1 and 7.1): the `*_no_context_takeover` ones take no value; `server_max_window_bits` takes one,
 * `client_max_window_bits` may go without in an offer; a value (also as a quoted-string) is 8 to 15 without leading zeros.
 */
private fun parseParameters(
    element: WebSocketExtensionHeader,
    response: Boolean,
): DeflateParameters? {
    var serverNoContextTakeover = false
    var clientNoContextTakeover = false
    var serverMaxWindowBits: Int? = null
    var clientMaxWindowBits: Int? = null
    val seen = HashSet<String>()
    for (parameter in element.parameters) {
        if (parameter.isBlank()) continue
        val eq = parameter.indexOf('=')
        val name = (if (eq < 0) parameter else parameter.substring(0, eq)).trim().lowercase()
        val value = if (eq < 0) null else unquote(parameter.substring(eq + 1).trim()) ?: return null
        if (!seen.add(name)) return null
        when (name) {
            SERVER_NO_CONTEXT_TAKEOVER -> {
                if (value != null) return null
                serverNoContextTakeover = true
            }

            CLIENT_NO_CONTEXT_TAKEOVER -> {
                if (value != null) return null
                clientNoContextTakeover = true
            }

            SERVER_MAX_WINDOW_BITS -> {
                serverMaxWindowBits = windowBits(value ?: return null) ?: return null
            }

            CLIENT_MAX_WINDOW_BITS -> {
                clientMaxWindowBits =
                    when {
                        value != null -> windowBits(value) ?: return null
                        response -> return null
                        else -> 0
                    }
            }

            else -> {
                return null
            }
        }
    }
    return DeflateParameters(serverNoContextTakeover, clientNoContextTakeover, serverMaxWindowBits, clientMaxWindowBits)
}

/** RFC 7692 section 7.1.2.1: `%x38-39 / "1" %x30-35`, the decimal 8 to 15 with no leading zero. */
private fun windowBits(value: String): Int? =
    when {
        value.length == 1 && value[0] in '8'..'9' -> value[0] - '0'
        value.length == 2 && value[0] == '1' && value[1] in '0'..'5' -> 10 + (value[1] - '0')
        else -> null
    }

/** A token as is, a quoted-string unescaped (RFC 7230 section 3.2.6, as RFC 6455 section 9.1 uses it); null if malformed. */
private fun unquote(value: String): String? {
    if (!value.startsWith('"')) return value.takeIf { it.isNotEmpty() && '"' !in it }
    if (value.length < 2 || !value.endsWith('"')) return null
    val b = StringBuilder()
    var i = 1
    while (i < value.length - 1) {
        var c = value[i]
        if (c == '\\') {
            i++
            if (i == value.length - 1) return null
            c = value[i]
        } else if (c == '"') {
            return null
        }
        b.append(c)
        i++
    }
    return b.toString()
}

private const val PERMESSAGE_DEFLATE = "permessage-deflate"
private const val SERVER_NO_CONTEXT_TAKEOVER = "server_no_context_takeover"
private const val CLIENT_NO_CONTEXT_TAKEOVER = "client_no_context_takeover"
private const val SERVER_MAX_WINDOW_BITS = "server_max_window_bits"
private const val CLIENT_MAX_WINDOW_BITS = "client_max_window_bits"
private const val MAX_WINDOW_BITS = 15

private const val DISPOSED = 1
private const val FREED = 2
private const val USE = 4
