// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(InternalKuicksilverApi::class, DelicateKuicksilverApi::class)

package io.kuicksilver.tls

import io.ktor.utils.io.ByteChannel
import io.ktor.utils.io.ByteReadChannel
import io.ktor.utils.io.ByteWriteChannel
import io.ktor.utils.io.cancel
import io.ktor.utils.io.readAvailable
import io.ktor.utils.io.writeFully
import io.kuicksilver.annotations.DelicateKuicksilverApi
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.annotations.InternalKuicksilverApi
import io.kuicksilver.native.Ksl
import io.kuicksilver.native.KslConst
import io.kuicksilver.native.KslException
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withTimeoutOrNull
import kotlin.coroutines.CoroutineContext
import kotlin.coroutines.EmptyCoroutineContext
import kotlin.time.Duration.Companion.seconds

/**
 * TLS over any byte transport (docs/guide/tls.md, TLS over any channel): ciphertext moves through [transportIn]/[transportOut], plaintext through
 * [input]/[output]. Two pump coroutines and one mutex guard the single `ksl_ssl`. The transport is the caller's: sockets,
 * a QUIC stream, anything that offers channels.
 */
public class TlsConnection private constructor(
    private val ctx: KslContext,
    private val transportIn: ByteReadChannel,
    private val transportOut: ByteWriteChannel,
    context: CoroutineContext,
    private val sessionCache: SessionCache,
) : AutoCloseable {
    private val config = ctx.config
    private var ssl: Long = Ksl.sslNew(ctx.handle, KslConst.MODE_TCP)
    private val lock = Mutex()
    private val scope = CoroutineScope(context + SupervisorJob(context[Job]) + Dispatchers.Default)
    private val inputChannel = ByteChannel(autoFlush = true)
    private val outputChannel = ByteChannel(autoFlush = true)
    private val verification = Verification(config)
    private var presented: List<Certificate> = emptyList()
    private var reference: HostName? = null
    private var overrideCtx: KslContext? = null
    private var cacheKey: String? = null
    private var reused = false
    private var closed = false
    private var readerJob: Job? = null
    private var writerJob: Job? = null

    /** Plaintext from the peer. Closed cleanly after `close_notify`; closed with a [TlsException] on any other end. */
    public val input: ByteReadChannel get() = inputChannel

    /** Plaintext to the peer. Closing it sends `close_notify`. */
    public val output: ByteWriteChannel get() = outputChannel

    /**
     * The chain the peer presented, leaf first, already verified by [TlsConfig.trust]; after a resumption, the chain cached
     * from the original handshake. Empty when the peer sent none (a client without a certificate under [ClientAuth.Optional]).
     */
    public val peerCertificates: List<Certificate> get() = presented

    /** The application protocol both sides agreed on (RFC 7301), or null when ALPN was not negotiated. */
    public var negotiatedAlpn: String? = null
        private set

    /** The TLS version in use; [TlsVersion.Tls12] only when [TlsConfig.versions] allowed it. */
    public var protocolVersion: TlsVersion = TlsVersion.Tls13
        private set

    private fun s(): Long {
        if (closed || ssl == 0L) throw IllegalStateException("connection closed")
        return ssl
    }

    init {
        if (config.role == TlsRole.Client) {
            val name =
                when (val t = config.trust) {
                    is TrustConfig.ExpectedName -> {
                        t.name
                    }

                    is TrustConfig.Pinned -> {
                        (t.base as? TrustConfig.ExpectedName)?.name
                            ?: config.serverName
                    }

                    else -> {
                        config.serverName
                    }
                }
                    ?: throw TlsException.Config("a client needs serverName (or ExpectedName) as the reference identifier")
            val host = HostName.normalize(name)
            reference = host
            sniOf(config)?.let { Ksl.sslSet(ssl, KslConst.SET_SNI, it.encodeToByteArray()) }
            Ksl.sslSet(ssl, KslConst.SET_VERIFY_NAME, host.value.encodeToByteArray())
            cacheKey = SessionCache.key(config.serverName, host.value, config.trust, config.identity)
        }
    }

    // ---- handshake ----
    private var cached: SessionCache.Entry? = null // the entry consumed for this connection (single-use ticket)

    private suspend fun handshake() {
        cacheKey?.let { key ->
            sessionCache.take(key)?.let { e ->
                cached = e
                try {
                    lock.withLock { Ksl.sslSetSession(s(), e.session) }
                } catch (_: KslException.Internal) {
                    cached =
                        null
                    e.close()
                }
            }
        }
        // withTimeoutOrNull: our own deadline becomes a TlsException, an outer cancellation stays a CancellationException
        withTimeoutOrNull(config.handshakeTimeout) { handshakeLoop() }
            ?: throw TlsException.Protocol(null, "TLS handshake timed out after ${config.handshakeTimeout}", null)
        afterHandshake()
        readerJob = scope.launch { readerPump() }
        writerJob = scope.launch { writerPump() }
        scope.launch { drainerPump() }
    }

    private suspend fun handshakeLoop() {
        val buf = ByteArray(16 * 1024)
        while (true) {
            val rc =
                try {
                    lock.withLock { Ksl.drive(s()).also { deliverKeylog() } }
                } catch (e: KslException.Internal) {
                    presented =
                        chain()
                    drainToTransport()
                    failWith(e)
                } // the alert leaves before we give up
            drainToTransport()
            when (rc) {
                KslConst.OK -> {
                    return
                }

                KslConst.WANT_READ -> {
                    val n = transportIn.readAvailable(buf, 0, buf.size)
                    if (n <
                        0
                    ) {
                        throw TlsException.Protocol(null, "transport closed during the TLS handshake", null)
                    }
                    feed(buf, n)
                }

                KslConst.WANT_VERIFY -> {
                    presented = chain()
                    val r = verification.verify(presented, reference!!)
                    lock.withLock { resume(r) }
                }

                KslConst.WANT_SNI -> {
                    selectIdentity()
                }

                else -> {
                    throw TlsException.Protocol(null, "unexpected ksl state $rc", null)
                }
            }
        }
    }

    private fun failWith(e: KslException.Internal): Nothing {
        rejection?.let { throw TlsException.Verify(it, presented) }
        val (ex, _) = e.toTlsFailure(presented)
        throw ex
    }

    private fun resume(r: VerifyResult) {
        when (r) {
            is VerifyResult.Accepted -> {
                Ksl.sslVerifyResume(s(), true, 0)
            }

            is VerifyResult.Rejected -> {
                Ksl.sslVerifyResume(s(), false, if (config.genericAlerts) 40 else r.reason.alertCode)
                rejection =
                    r.reason
            }
        }
    }

    private var rejection: VerifyReason? = null

    private suspend fun selectIdentity() {
        val selector = config.sniSelector ?: throw TlsException.Config("ksl paused for SNI without a selector")
        val ch = Ksl.sslClientHello(s())
        val info = ClientHelloInfo(ch.serverName, parseAlpn(ch.alpnWire), parseU16List(ch.signatureAlgorithmsWire))
        val override = selector(info)
        when {
            override != null -> {
                val o = KslContext.create(config.withOverride(override), quic = false)
                overrideCtx = o
                lock.withLock { Ksl.sslSniResume(s(), o.handle, 0) }
            }

            info.serverName != null -> {
                lock.withLock { Ksl.sslSniResume(s(), 0L, 112) }
            }

            // unrecognized_name
            else -> {
                lock.withLock { Ksl.sslSniResume(s(), 0L, 0) }
            } // default identity
        }
    }

    private suspend fun afterHandshake() {
        negotiatedAlpn = Ksl.sslGet(s(), KslConst.GET_ALPN).takeIf { it.isNotEmpty() }?.decodeToString()
        protocolVersion = if (Ksl.sslGet(s(), KslConst.GET_VERSION)[1].toInt() == 0x03) TlsVersion.Tls12 else TlsVersion.Tls13
        reused = Ksl.sslGet(s(), KslConst.GET_SESSION_REUSED)[0].toInt() == 1
        presented = chain()
        val effective = overrideCtx?.config ?: config
        if (effective.role == TlsRole.Client) {
            if (reused) {
                // no Certificate on a resumed handshake: trust is re-established from the cached chain (ADR-0011: resumption never bypasses verification)
                val cached = cached ?: throw TlsException.Protocol(null, "resumed session without a cached chain", null)
                presented = cached.chain
                val r =
                    if (ctx.verifyMode ==
                        KslConst.VERIFY_OPENSSL
                    ) {
                        verification.pinCheck(cached.validated)
                    } else {
                        verification.verify(cached.chain, reference!!)
                    }
                if (r is VerifyResult.Rejected) abort(TlsException.Verify(r.reason, presented))
            } else if (ctx.verifyMode == KslConst.VERIFY_OPENSSL) {
                val r = verification.pinCheck(validated())
                if (r is VerifyResult.Rejected) abort(TlsException.Verify(r.reason, presented))
            }
        } else {
            val pinnedClients = effective.clientAuth != ClientAuth.None && effective.trust is TrustConfig.Pinned
            // a resumed session carries only the client's leaf, so a CA pin cannot be re-checked; it resumed under this trust configuration's
            // session context, and with pinned clients ksl encrypts a ticket only on the explicit request below and resumes only tickets
            // stamped that way (ksl_ctx.c ticket callbacks): the verdict travels with it
            if (pinnedClients &&
                !reused
            ) {
                val r = Verification(effective).pinCheck(validated())
                if (r is VerifyResult.Rejected) abort(TlsException.Verify(r.reason, presented))
            }
            // explicit ticket: after the pin verdict (never before), and after a resumption (OpenSSL issues none by itself; client tickets are single-use)
            if (pinnedClients || reused) {
                lock.withLock { Ksl.sslNewSessionTicket(s()) }
                drainToTransport()
            }
        }
    }

    private suspend fun abort(e: TlsException): Nothing {
        lock.withLock { runCatching { Ksl.tcpShutdown(s()) } }
        drainToTransport()
        close()
        throw e
    }

    // ---- pumps ----
    private suspend fun feed(
        buf: ByteArray,
        n: Int,
    ) {
        var off = 0
        while (off <
            n
        ) {
            val used = lock.withLock { Ksl.tcpFeed(s(), buf, off, n - off) }
            if (used <=
                0
            ) {
                throw TlsException.Protocol(null, "ksl refused ciphertext", null)
            }
            off += used
        }
    }

    /**
     * Ciphertext goes out under [drainLock]: the writer pump and the [drainerPump] both drain, and two drains interleaving
     * between `tcpDrain` and the write would reorder records on the wire (the peer fails with bad_record_mac) or write the
     * transport concurrently. Order: [drainLock], then [lock]. The reader pump never drains itself: a drain also takes the
     * application data the writer pump encrypted and waits for room on the transport, and a reader pump waiting there stops
     * reading, so two peers writing at once over full transports would each wait for the other to read. It asks the
     * [drainerPump] instead ([drainRequests]).
     */
    private suspend fun drainToTransport() {
        drainLock.withLock {
            while (true) {
                val n = lock.withLock { if (ssl == 0L) 0 else Ksl.tcpDrain(ssl, drainBuffer, 0, drainBuffer.size) }
                if (n <= 0) break
                transportOut.writeFully(drainBuffer, 0, n)
            }
            transportOut.flush()
        }
    }

    private val drainLock = Mutex()
    private val drainBuffer = ByteArray(16 * 1024)

    /** Signalled by the reader pump when what it fed may have produced ciphertext (handshake messages, alerts, key updates). */
    private val drainRequests = Channel<Unit>(Channel.CONFLATED)

    /** Drains for the reader pump, so that the reader pump never waits on the transport. */
    private suspend fun drainerPump() {
        try {
            while (drainRequests.receiveCatching().isSuccess) drainToTransport()
        } catch (e: CancellationException) {
            throw e
        } catch (e: Throwable) {
            val failure = e as? TlsException ?: TlsException.Protocol(null, e.message ?: "transport failure", e)
            inputChannel.cancel(failure)
            outputChannel.cancel(failure)
        }
    }

    private suspend fun readerPump() {
        val cipher = ByteArray(16 * 1024)
        val plain = ByteArray(16 * 1024)
        try {
            while (true) {
                // drain plaintext already decryptable
                while (true) {
                    val r =
                        try {
                            lock.withLock { Ksl.tcpRead(s(), plain, 0, plain.size) }
                        } catch (
                            e: KslException.Internal,
                        ) {
                            throw e.toTlsFailure(presented).first
                        }
                    when {
                        r > 0 -> {
                            // a ticket that preceded these bytes is cached before the application sees them: a
                            // client that reads one response and closes would otherwise cancel this pump first
                            rememberSession()
                            inputChannel.writeFully(plain, 0, r)
                        }

                        r == -KslConst.EOF -> {
                            drainRequests.trySend(Unit)
                            inputChannel.flushAndClose()
                            return
                        }

                        else -> {
                            break
                        } // WANT_READ
                    }
                }
                drainRequests.trySend(Unit)
                rememberSession()
                val n = transportIn.readAvailable(cipher, 0, cipher.size)
                if (n < 0) throw TlsException.Protocol(null, "transport closed without close_notify (truncation)", null)
                feed(cipher, n)
            }
        } catch (
            e: CancellationException,
        ) {
            inputChannel.cancel(e)
            throw e
        } catch (
            e: Throwable,
        ) {
            inputChannel.cancel(e as? TlsException ?: TlsException.Protocol(null, e.message ?: "transport failure", e))
        }
    }

    private suspend fun writerPump() {
        val buf = ByteArray(16 * 1024)
        try {
            while (true) {
                val n = outputChannel.readAvailable(buf, 0, buf.size)
                if (n < 0) {
                    shutdownSend()
                    return
                }
                var off = 0
                while (off < n) {
                    val w =
                        try {
                            lock.withLock { Ksl.tcpWrite(s(), buf, off, n - off) }
                        } catch (
                            e: KslException.Internal,
                        ) {
                            throw e.toTlsFailure(presented).first
                        }
                    if (w > 0) off += w
                    drainToTransport()
                }
            }
        } catch (
            e: CancellationException,
        ) {
            throw e
        } catch (
            e: Throwable,
        ) {
            val failure = e as? TlsException ?: TlsException.Protocol(null, e.message ?: "transport failure", e)
            inputChannel.cancel(failure)
            // the application's writer too: with nobody draining the output channel any more, a writer of a long body would
            // wait on a full buffer forever, holding its connection (a peer gone mid-response; found by the soak)
            outputChannel.cancel(failure)
        }
    }

    private var ticketStored = false

    /** After a NewSessionTicket the serialized session changes; store it once per connection (single-use on the client). */
    private suspend fun rememberSession() {
        val key = cacheKey ?: return
        if (ticketStored) return
        val entry =
            try {
                lock.withLock {
                    if (ssl == 0L) return
                    val session = Ksl.sslGet1Session(ssl) // a native handle: the ticket and its secret never reach the heap
                    if (session == 0L) return
                    if (session == cached?.session) {
                        Ksl.sessionFree(session)
                        return
                    } // the consumed ticket itself: single-use
                    try {
                        val validated =
                            if (ctx.verifyMode == KslConst.VERIFY_OPENSSL &&
                                !reused
                            ) {
                                validated()
                            } else {
                                (cached?.validated ?: presented)
                            }
                        SessionCache.Entry(session, presented, validated)
                    } catch (t: Throwable) {
                        Ksl.sessionFree(session)
                        throw t
                    }
                }
            } catch (_: KslException.Internal) {
                return
            }
        sessionCache.put(key, entry)
        ticketStored = true
    }

    private suspend fun shutdownSend() {
        lock.withLock { runCatching { Ksl.tcpShutdown(s()) } }
        drainToTransport()
    }

    // ---- public operations ----

    /** RFC 5705 / RFC 8446 section 7.5 exporter; only after the handshake. Throws [IllegalStateException] when the exporter is unavailable, [TlsException.Protocol] for other TLS errors. */
    public suspend fun exportKeyingMaterial(
        label: String,
        context: ByteArray?,
        length: Int,
    ): ByteArray = lock.withLock { mapped { Ksl.sslExportKeyingMaterial(s(), label, context, length) } }

    /** RFC 9266 `tls-exporter` channel binding (32 bytes); TLS 1.2 without EMS throws. */
    public suspend fun channelBinding(): ByteArray =
        lock.withLock {
            try {
                Ksl.sslGet(s(), KslConst.GET_CHANNEL_BINDING)
            } catch (e: KslException.Internal) {
                throw TlsException.Protocol(
                    e.packed,
                    e.message ?: "channel binding unavailable",
                    e,
                )
            }
        }

    /** RFC 8446 section 4.6.3 key update; takes effect with the next write. */
    public suspend fun keyUpdate(requestPeer: Boolean = false) {
        lock.withLock { Ksl.sslKeyUpdate(s(), requestPeer) }
    }

    /** Sends `close_notify` and waits (bounded) for the peer's; then releases the native session. */
    public suspend fun shutdown() {
        if (closed) return
        outputChannel.flushAndClose()
        writerJob?.join() // the writer pump sends close_notify after draining the output channel
        withTimeoutOrNull(3.seconds) {
            readerJob?.join()
        } // the reader pump ends on the peer's close_notify; never read the input channel here (its consumer may be mid-read)
        close()
    }

    /** Cancels the pumps and frees the native session once they have stopped and nobody holds the lock (never while any caller is inside ksl). */
    override fun close() {
        if (closed) return
        closed = true
        val job = scope.coroutineContext[Job]!!
        inputChannel.cancel(TlsException.Protocol(null, "connection closed", null))
        outputChannel.cancel(TlsException.Protocol(null, "connection closed", null))
        job.invokeOnCompletion {
            @OptIn(kotlinx.coroutines.DelicateCoroutinesApi::class)
            kotlinx.coroutines.GlobalScope.launch(Dispatchers.Default) { lock.withLock { freeNative() } }
        }
        job.cancel()
    }

    private fun freeNative() {
        if (ssl != 0L) {
            Ksl.sslFree(ssl)
            ssl = 0L
        }
        cached?.close()
        cached = null
        overrideCtx?.close()
        ctx.close()
    }

    /** True when this connection resumed a previous session (no Certificate was exchanged). */
    public val sessionReused: Boolean get() = reused

    private fun deliverKeylog() {
        val sink = config.keylog ?: return
        sink.deliver(Ksl.sslGet(s(), KslConst.GET_KEYLOG).decodeToString())
    }

    private fun chain(): List<Certificate> = Ksl.sslPeerChain(s(), KslConst.CHAIN_PRESENTED).map(::Certificate)

    private fun validated(): List<Certificate> = Ksl.sslPeerChain(s(), KslConst.CHAIN_VALIDATED).map(::Certificate)

    /** Factories that run the handshake: [client] and [server]. */
    public companion object {
        /**
         * Runs a client handshake over [transportIn]/[transportOut] and returns once it completed and the server passed
         * [TlsConfig.trust] and the host name check. A cached session for the same name and trust is resumed automatically
         * and re-checked. The pumps run in [context] (their parent job, if any); cancelling it ends the connection.
         * Throws [TlsException]: [TlsException.Config] for a server configuration or a client without a reference identifier,
         * [TlsException.Verify], [TlsException.AlertReceived], or [TlsException.Protocol] (also after
         * [TlsConfig.handshakeTimeout]). On failure the alert is flushed and [transportOut] is closed.
         */
        public suspend fun client(
            transportIn: ByteReadChannel,
            transportOut: ByteWriteChannel,
            config: TlsConfig,
            context: CoroutineContext = EmptyCoroutineContext,
        ): TlsConnection = client(transportIn, transportOut, config, context, SessionCache.Default)

        /** [client] with the session cache of the engine that owns the connection instead of [SessionCache.Default]. */
        @InternalKuicksilverApi
        public suspend fun client(
            transportIn: ByteReadChannel,
            transportOut: ByteWriteChannel,
            config: TlsConfig,
            context: CoroutineContext,
            sessionCache: SessionCache,
        ): TlsConnection {
            if (config.role != TlsRole.Client) throw TlsException.Config("client() needs a client configuration")
            return start(transportIn, transportOut, config, context, sessionCache)
        }

        /**
         * Runs a server handshake over [transportIn]/[transportOut] and returns once it completed: the identity is chosen
         * (through [TlsConfig.sniSelector] when set) and a client certificate, when requested, passed [TlsConfig.trust]
         * and the pins. Same [context], errors and failure handling as [client].
         */
        public suspend fun server(
            transportIn: ByteReadChannel,
            transportOut: ByteWriteChannel,
            config: TlsConfig,
            context: CoroutineContext = EmptyCoroutineContext,
        ): TlsConnection {
            if (config.role != TlsRole.Server) throw TlsException.Config("server() needs a server configuration")
            return start(transportIn, transportOut, config, context, SessionCache.Default)
        }

        private suspend fun start(
            transportIn: ByteReadChannel,
            transportOut: ByteWriteChannel,
            config: TlsConfig,
            context: CoroutineContext,
            sessionCache: SessionCache,
        ): TlsConnection {
            val c = TlsConnection(KslContext.create(config, quic = false), transportIn, transportOut, context, sessionCache)
            try {
                c.handshake()
            } catch (t: Throwable) {
                c.close()
                runCatching { transportOut.flushAndClose() }
                throw t
            } // clean close: the alert already written stays readable for the peer
            return c
        }

        internal fun parseAlpn(wire: ByteArray): List<String> {
            val out = ArrayList<String>()
            var i = 0
            while (i <
                wire.size
            ) {
                val n =
                    wire[i].toInt() and 0xff
                if (i + 1 + n >
                    wire.size
                ) {
                    break
                }
                out += wire.decodeToString(i + 1, i + 1 + n)
                i += 1 + n
            }
            return out
        }

        internal fun parseU16List(wire: ByteArray): List<Int> =
            (0 until wire.size / 2).map {
                (wire[it * 2].toInt() and 0xff) shl 8 or
                    (wire[it * 2 + 1].toInt() and 0xff)
            }
    }
}

/** The TLS version a [TlsConnection] negotiated. */
public enum class TlsVersion {
    /** TLS 1.2 (RFC 5246) under the RFC 9325 profile, with Extended Master Secret; only with [TlsVersions.Tls12And13]. */
    Tls12,

    /** TLS 1.3 (RFC 8446). */
    Tls13,
}

/**
 * Client session cache: keyed by SNI, reference identifier, trust configuration and client identity; tickets are single-use;
 * entries expire after 7 days and the cache holds at most [maxEntries] sessions (the least recently stored one goes first).
 * A session is a native `ksl_session` handle: the ticket and its resumption secret stay in native memory and are cleansed
 * when the entry is used, replaced, evicted, expired or [clear]ed (threat model 3.7). Each engine owns an instance and clears
 * it when it closes; [TlsConnection.client] without an explicit cache uses [Default].
 */
@InternalKuicksilverApi
public class SessionCache(
    private val maxEntries: Int = DEFAULT_MAX_ENTRIES,
) {
    init {
        require(maxEntries > 0) { "maxEntries must be positive" }
    }

    /** Owns one reference to the native session [session] until [close]. */
    internal class Entry(
        session: Long,
        val chain: List<Certificate>,
        val validated: List<Certificate>,
        val created: Long = nowSeconds(),
    ) {
        var session: Long = session
            private set

        /** What a QUIC transport stores with the ticket (the server's transport parameters, RFC 9000 section 7.4.1). */
        var remembered: ByteArray? = null

        /** True once [close] ran: the native reference is released (tests observe eviction through it). */
        var closed: Boolean = false
            private set

        fun close() {
            closed = true
            val h = session
            if (h != 0L) {
                session = 0L
                Ksl.sessionFree(h)
            }
        }
    }

    private val entries = LinkedHashMap<String, Entry>() // insertion order: the head is the least recently stored entry
    private val mutex = Mutex()

    /** The process-wide cache, key derivation and the default bound. */
    @InternalKuicksilverApi
    public companion object {
        /** Sessions a cache keeps before the oldest is evicted; one origin per entry, so this is also the number of resumable origins. */
        public const val DEFAULT_MAX_ENTRIES: Int = 256
        private const val TTL_SECONDS = 7L * 24 * 3600

        /** The cache of connections opened without an engine (`TlsConnection.client`, `Socket.tls`). */
        public val Default: SessionCache = SessionCache()

        internal fun key(
            sni: String?,
            reference: String,
            trust: TrustConfig,
            identity: TlsIdentity?,
        ): String = "$sni|$reference|${trust.cacheKey()}|id:${identity?.chain?.firstOrNull()?.spkiSha256 ?: "none"}"
    }

    /** Removes and returns the entry: a ticket is used at most once (RFC 8446 appendix C.4). */
    internal suspend fun take(key: String): Entry? =
        mutex.withLock {
            val e =
                entries.remove(key) ?: return null
            if (nowSeconds() - e.created > TTL_SECONDS) {
                e.close()
                null
            } else {
                e
            }
        }

    /** Stores [entry] and drops every expired session, so the cache never keeps dead tickets (and their native secrets) until their key is asked for. */
    internal suspend fun put(
        key: String,
        entry: Entry,
    ) {
        mutex.withLock {
            entries.remove(key)?.close() // re-inserted at the tail: a fresh ticket for an origin is the most recent entry
            entries.put(key, entry)
            val now = nowSeconds()
            val it = entries.values.iterator()
            while (it.hasNext()) {
                val e = it.next()
                if (now - e.created > TTL_SECONDS) {
                    e.close()
                    it.remove()
                }
            }
            while (entries.size > maxEntries) {
                val oldest = entries.entries.iterator()
                val e = oldest.next()
                e.value.close()
                oldest.remove()
            }
        }
    }

    /** Drops every cached session (tests, credential rotation). */
    public suspend fun clear() {
        mutex.withLock {
            entries.values.forEach { it.close() }
            entries.clear()
        }
    }

    /** Number of cached sessions. */
    public suspend fun size(): Int = mutex.withLock { entries.size }

    internal suspend fun peek(key: String): Boolean = mutex.withLock { entries.containsKey(key) }

    /**
     * QUIC (ADR-0015): takes the ticket stored for [config] (single use) and checks its cached chain again against the
     * current trust (pins, platform or custom verdict), as a TCP resumption does; null when there is none or the chain no
     * longer passes (the ticket is then dropped).
     */
    @ExperimentalKuicksilverApi
    public suspend fun takeQuic(config: TlsConfig): QuicSessionTicket? {
        val e = take(quicKey(config)) ?: return null
        val verdict =
            try {
                val v = Verification(config)
                if (KslContext.verifyModeFor(config) == KslConst.VERIFY_OPENSSL) {
                    v.pinCheck(e.validated)
                } else {
                    v.verify(e.chain, HostName.normalize(referenceOf(config)))
                }
            } catch (t: Throwable) {
                e.close()
                throw t
            }
        if (verdict is VerifyResult.Rejected) {
            e.close()
            return null
        }
        return QuicSessionTicket(e)
    }

    /** QUIC: stores [ticket] for [config], replacing the previous one of that origin. */
    @ExperimentalKuicksilverApi
    public suspend fun putQuic(
        config: TlsConfig,
        ticket: QuicSessionTicket,
    ) {
        if (ticket.closed) return
        put(quicKey(config), ticket.entry)
    }

    private fun quicKey(config: TlsConfig): String =
        "quic|" + config.alpn.joinToString(",") + "|" +
            key(config.serverName, HostName.normalize(referenceOf(config)).value, config.trust, config.identity)
}

internal expect fun nowSeconds(): Long

internal fun TrustConfig.cacheKey(): String =
    when (this) {
        is TrustConfig.Platform -> "platform"
        is TrustConfig.AnchoredCa -> "ca:" + roots.joinToString(",") { it.spkiSha256.toString() }
        is TrustConfig.ExpectedName -> "name:$name/" + base.cacheKey()
        is TrustConfig.Pinned -> "pin:$scope:" + pins.map { it.toString() }.sorted().joinToString(",") + "/" + base.cacheKey()
        is TrustConfig.Tofu -> "tofu:${store.hashCode()}"
        is TrustConfig.Custom -> "custom:${verifier.hashCode()}"
    }
