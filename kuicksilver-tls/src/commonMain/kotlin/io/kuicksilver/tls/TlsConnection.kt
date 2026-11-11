// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(InternalKuicksilverApi::class, DelicateKuicksilverApi::class, ExperimentalAtomicApi::class)

package io.kuicksilver.tls

import io.ktor.utils.io.ByteChannel
import io.ktor.utils.io.ByteReadChannel
import io.ktor.utils.io.ByteWriteChannel
import io.ktor.utils.io.availableForRead
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
import kotlin.concurrent.Volatile
import kotlin.concurrent.atomics.AtomicBoolean
import kotlin.concurrent.atomics.ExperimentalAtomicApi
import kotlin.coroutines.CoroutineContext
import kotlin.coroutines.EmptyCoroutineContext
import kotlin.time.Duration
import kotlin.time.Duration.Companion.seconds

/**
 * TLS over any byte transport (docs/guide/tls.md, TLS over any channel): ciphertext moves through `transportIn`/`transportOut`, plaintext through
 * [input]/[output]. Two pump coroutines and one mutex guard the single `ksl_ssl`. The transport is the caller's: sockets,
 * a QUIC stream, anything that offers channels.
 */
public class TlsConnection private constructor(
    private val lease: KslContext.Lease,
    private val transportIn: ByteReadChannel,
    private val transportOut: ByteWriteChannel,
    context: CoroutineContext,
    private val sessionCache: SessionCache,
) : AutoCloseable {
    private val ctx = lease.ctx
    private val config = ctx.config
    private var ssl: Long = Ksl.sslNew(ctx.handle, KslConst.MODE_TCP)
    private val lock = Mutex()

    /** The context this connection was built from (tests). */
    internal val contextForTest: KslContext get() = ctx

    /** Runs [block] with the session's ksl handle under the session lock (the native test hooks). */
    internal suspend fun <T> withSslForTest(block: (Long) -> T): T = lock.withLock { block(s()) }

    private val scope = CoroutineScope(context + SupervisorJob(context[Job]) + Dispatchers.Default)

    /** The record framing of everything fed to ksl, the handshake included (the reader pump counts records with it). */
    private val framing = RecordFraming()

    /** Tests: asked before each of the reader pump's feeds; true makes it as if ksl refused the ciphertext. */
    @Volatile internal var refuseFeedForTest: (() -> Boolean)? = null

    /** Whether the record framing was lost (tests). */
    internal val framingLostForTest: Boolean get() = framing.lost

    private val inputChannel = ByteChannel(autoFlush = true)
    private val inputView = DeliverThenFail(inputChannel)
    private val outputChannel = ByteChannel(autoFlush = true)
    private val verification = Verification(config)
    private var presented: List<Certificate> = emptyList()
    private var reference: HostName? = null
    private var overrideCtx: KslContext.Lease? = null
    private var cacheKey: String? = null
    private var reused = false

    /** Set once by [close] or when the pumps' job ends; read by every thread (the pumps, the owner's close, a timeout). */
    private val closedFlag = AtomicBoolean(false)
    private val closed: Boolean get() = closedFlag.load()
    private var readerJob: Job? = null
    private var writerJob: Job? = null

    /** The most plaintext one ksl_tcp_write takes (a record), learnt from a write that took less than offered; the writer's alone. */
    private var recordBytes = Int.MAX_VALUE

    /** Plaintext from the peer. Closed cleanly after `close_notify`; closed with a [TlsException] on any other end. */
    public val input: ByteReadChannel get() = inputView

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

    /**
     * Whether the peer attempted a TLS 1.2 renegotiation on this connection: a server's HelloRequest, a client's ClientHello
     * after the handshake. Every renegotiation is refused (a no_renegotiation warning) and the connection goes on, except on a
     * connection that negotiated `h2`: RFC 9113 section 9.2.1, "An endpoint MUST treat a TLS renegotiation as a connection error
     * (Section 5.4.1) of type PROTOCOL_ERROR", so there [input] fails with [TlsException.Protocol] once the plaintext that came
     * before the attempt was read, and [output] stays open for the HTTP/2 layer's GOAWAY. True from before that failure on.
     */
    @InternalKuicksilverApi
    public val renegotiationAttempted: Boolean get() = renegotiation

    @Volatile private var renegotiation = false

    /**
     * Whether this TLS 1.3 connection failed because the peer sent a handshake message TLS 1.3 does not allow after the
     * handshake here and OpenSSL refused it with unexpected_message: a server's CertificateRequest, since ksl never offers
     * post_handshake_auth (RFC 9846 section 4.6.2), and any other. RFC 9113 section 9.2.3: "HTTP/2 clients MUST treat a TLS
     * post-handshake CertificateRequest message as a connection error (Section 5.4.1) of type PROTOCOL_ERROR"; OpenSSL fails
     * on the message before anyone sees its type, so the HTTP/2 layer takes every such refusal on `h2` for one. True from
     * before [input] fails with it.
     */
    @InternalKuicksilverApi
    public val postHandshakeMessageRefused: Boolean get() = refusedAfterHandshake

    @Volatile private var refusedAfterHandshake = false

    /** The TLS version in use; [TlsVersion.Tls12] only when [TlsConfig.versions] allowed it. */
    public var protocolVersion: TlsVersion = TlsVersion.Tls13
        private set

    private fun s(): Long {
        if (closed || ssl == 0L) throw IllegalStateException("connection closed")
        return ssl
    }

    init {
        try {
            setUpClient()
        } catch (t: Throwable) {
            // the constructor fails, so nobody can close() this object: free what it holds (the context is the caller's)
            Ksl.sslFree(ssl)
            ssl = 0L
            scope.coroutineContext[Job]?.cancel()
            throw t
        }
        // the native state goes when the pumps' job ends, however it ends: close(), or the caller's job cancelled (the
        // documented "cancelling it ends the connection"), also when the owner never calls close()
        scope.coroutineContext[Job]!!.invokeOnCompletion { ended() }
    }

    private fun setUpClient() {
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
                // ADR-0011: the OpenSSL verifier's verdict is not taken from the cache: an expired leaf or a withdrawn anchor runs a full handshake
                if (ctx.verifyMode == KslConst.VERIFY_OPENSSL && !ctx.cachedChainStillTrusted(e.chain, reference!!)) {
                    e.close()
                    return@let
                }
                // a client identity reloaded since the ticket was issued: that session speaks for the old certificate
                if (e.identityTag != ctx.identityTag) {
                    e.close()
                    return@let
                }
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
            ?: throw TlsException.Protocol(null, "TLS handshake timed out after ${config.handshakeTimeout}", HandshakeTimedOut())
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
                lock.withLock { Ksl.sslSniResume(s(), o.ctx.handle, 0) }
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
        val effective = overrideCtx?.ctx?.config ?: config
        if (effective.role == TlsRole.Client) {
            if (reused) {
                // no Certificate on a resumed handshake: trust is re-established from the cached chain (ADR-0011: resumption never bypasses
                // verification); on the OpenSSL path the chain itself was verified again before the ticket was offered (handshake())
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
            // ClientAuth.Optional: a client without a certificate is accepted (its session can never gain one); a presented one must pass the pins
            val anonymous = effective.clientAuth == ClientAuth.Optional && presented.isEmpty()
            // a resumed session carries only the client's leaf, so a CA pin cannot be re-checked; it resumed under this trust configuration's
            // session context, and with pinned clients ksl encrypts a ticket only on the explicit request below and resumes only tickets
            // stamped that way (ksl_ctx.c ticket callbacks): the verdict travels with it
            if (pinnedClients &&
                !reused &&
                !anonymous
            ) {
                val r = Verification(effective).pinCheck(validated())
                if (r is VerifyResult.Rejected) abort(TlsException.Verify(r.reason, presented))
            }
            // explicit tickets: after the pin verdict (never before), six after a full handshake as KslContext's count for the other
            // servers (RFC 9846 appendix C.4), and one after a resumption (client tickets are single-use)
            if (pinnedClients || reused) {
                lock.withLock { repeat(if (reused) 1 else TCP_TICKETS) { Ksl.sslNewSessionTicket(s()) } }
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
            framing.complete(buf, off, used) // the handshake's reads can end inside the first record after it
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
        drained.trySend(Unit)
    }

    private val drainLock = Mutex()
    private val drainBuffer = ByteArray(16 * 1024)

    /** Times the reader pump woke the drainer after a pass of records (tests: not after passes of application data). */
    @Volatile internal var drainWakeupsForTest: Int = 0

    /** Signalled by the reader pump when what it fed may have produced ciphertext (handshake messages, alerts, key updates). */
    private val drainRequests = Channel<Unit>(Channel.CONFLATED)

    /** Signalled after each drain: a reader pump whose read must write first waits for room here, not for transport input. */
    private val drained = Channel<Unit>(Channel.CONFLATED)

    /** Drains for the reader pump, so that the reader pump never waits on the transport. */
    private suspend fun drainerPump() {
        try {
            while (drainRequests.receiveCatching().isSuccess) drainToTransport()
        } catch (e: CancellationException) {
            throw e
        } catch (e: Throwable) {
            val failure = e as? TlsException ?: TlsException.Protocol(null, e.message ?: "transport failure", e)
            drained.close(failure)
            inputChannel.cancel(failure)
            outputChannel.cancel(failure)
        }
    }

    /**
     * Decrypts the peer's records into [input]. Per pass it takes all the ciphertext the transport holds (up to
     * [READ_CHUNK]), feeds it a record's worth at a time and gathers the plaintext of every record decrypted meanwhile,
     * handing it to [input] in one write. Each hand-over to another coroutine can cost a thread wake-up, which cost more
     * than the decryption: the drainer is asked to send what reading produced only when it can have produced something
     * (a pass of records that carried no application data: a KeyUpdate, a NewSessionTicket, an alert; a renegotiation
     * refused; the peer's close_notify; ksl waiting to write), not after every pass of application data.
     */
    private suspend fun readerPump() {
        val cipher = ByteArray(READ_CHUNK)
        val plain = ByteArray(READ_CHUNK)
        var have = 0 // plaintext gathered in [plain], not handed to the application yet
        // the records of a pass: those whose last byte was fed, and the reads that gave application data (one per record,
        // SSL_read takes one record at a time); more of the first means a record without application data
        var recordsInPass = 0
        var dataReadsInPass = 0
        var firstPass = true

        // a ticket that preceded these bytes is cached before the application sees them: a client that reads one response
        // and closes would otherwise cancel this pump first
        suspend fun deliver() {
            rememberSession()
            if (have == 0) return
            inputChannel.writeFully(plain, 0, have)
            have = 0
        }

        /** Reads every record ksl can decrypt now; false when the input ended (close_notify, or the drainer failed). */
        suspend fun decryptAvailable(): Boolean {
            while (true) {
                if (plain.size - have < MAX_PLAINTEXT_RECORD) deliver()
                val r =
                    try {
                        // at most one record per call (SSL_read): offering more only makes the JNI layer copy and wipe more
                        lock.withLock { Ksl.tcpRead(s(), plain, have, MAX_PLAINTEXT_RECORD) }
                    } catch (
                        e: KslException.Internal,
                    ) {
                        deliver() // the plaintext before the failure stays the application's
                        if (refusedPostHandshakeMessage(protocolVersion, e)) refusedAfterHandshake = true
                        throw e.toTlsFailure(presented).first
                    }
                when {
                    r > 0 -> {
                        have += r
                        dataReadsInPass++
                    }

                    r == 0 -> {
                        // a read that refused the peer's renegotiation answers nothing read (ksl_tcp_read): the plaintext
                        // before it goes first, and what came after it is read only once this looked
                        deliver()
                        checkRenegotiation()
                        // ksl must write first (a handshake message under way) and its pair is full: the records already
                        // fed are read once the drainer made room, not when the transport brings more input
                        drained.tryReceive()
                        drainRequests.trySend(Unit)
                        // closed when the drainer failed, which ended the input with its failure
                        if (drained.receiveCatching().isClosed) return false
                    }

                    r == -KslConst.EOF -> {
                        deliver()
                        drainRequests.trySend(Unit)
                        inputChannel.flushAndClose()
                        return false
                    }

                    else -> {
                        return true
                    } // WANT_READ
                }
            }
        }
        try {
            if (!decryptAvailable()) return
            while (true) {
                // nothing more to decrypt: what was gathered goes to the application before the pump waits for the transport.
                // A record without application data may have produced ciphertext (an alert; an answer to the peer's
                // KeyUpdate, which RFC 9846 section 4.7.3 wants "prior to sending its next Application Data record", and the
                // writer pump drains before that anyway): the drainer sends it now. The pass before the first transport read
                // always asks (records that came with the handshake's last flight), and so does every pass once the record
                // framing could not be followed
                if (firstPass || framing.lost || recordsInPass > dataReadsInPass) {
                    drainWakeupsForTest++
                    drainRequests.trySend(Unit)
                }
                firstPass = false
                recordsInPass = 0
                dataReadsInPass = 0
                deliver()
                var n = transportIn.readAvailable(cipher, 0, cipher.size)
                if (n < 0) throw TlsException.Protocol(null, "transport closed without close_notify (truncation)", null)
                // one read gives at most one buffer segment (8 KiB): what else is there already joins this pass. A transport
                // that failed meanwhile throws its cause here even with bytes buffered (ktor's readBuffer): the bytes read so
                // far are fed first, and the next pass's read reports the failure
                try {
                    while (n < cipher.size && transportIn.availableForRead > 0) {
                        val more = transportIn.readAvailable(cipher, n, cipher.size - n)
                        if (more <= 0) break
                        n += more
                    }
                } catch (e: CancellationException) {
                    throw e
                } catch (_: Throwable) {
                    // reported by the next pass's first read
                }
                var off = 0
                while (off < n) {
                    // a record's worth at a time: ksl's pair takes some 17 KiB, and the JNI layer copies all it is offered
                    val len = minOf(n - off, FEED_CHUNK)
                    val used = if (refuseFeedForTest?.invoke() == true) 0 else lock.withLock { Ksl.tcpFeed(s(), cipher, off, len) }
                    if (used <= 0) {
                        deliver() // the plaintext of this pass before the refusal stays the application's
                        throw TlsException.Protocol(null, "ksl refused ciphertext", null)
                    }
                    recordsInPass += framing.complete(cipher, off, used)
                    off += used
                    if (!decryptAvailable()) return
                }
            }
        } catch (
            e: CancellationException,
        ) {
            inputChannel.cancel(e)
            throw e
        } catch (
            e: Throwable,
        ) {
            // the plaintext decrypted before the failure (a truncation: the transport ended without close_notify) is still
            // the application's; it gets the failure once it has read that, never a clean end
            inputView.failAfterBuffered(e as? TlsException ?: TlsException.Protocol(null, e.message ?: "transport failure", e))
        }
    }

    /**
     * Notes a renegotiation the peer attempted (TLS 1.2 only; ksl refused it) and lets its no_renegotiation warning leave. On a
     * connection that negotiated `h2` it ends the input (RFC 9113 section 9.2.1: a connection error of type PROTOCOL_ERROR,
     * which the HTTP/2 layer sends); elsewhere the connection goes on.
     */
    private suspend fun checkRenegotiation() {
        if (renegotiation || protocolVersion != TlsVersion.Tls12) return
        if (lock.withLock { Ksl.sslGet(s(), KslConst.GET_RENEGOTIATION)[0].toInt() } == 0) return
        renegotiation = true
        drainRequests.trySend(Unit)
        if (negotiatedAlpn == HTTP2_ALPN) {
            throw TlsException.Protocol(
                null,
                "the peer attempted a TLS renegotiation, which HTTP/2 forbids (RFC 9113 section 9.2.1: a connection error of type PROTOCOL_ERROR)",
                null,
            )
        }
    }

    private suspend fun writerPump() {
        val buf = ByteArray(16 * 1024)
        try {
            while (true) {
                val n =
                    try {
                        outputChannel.readAvailable(buf, 0, buf.size)
                    } catch (e: Throwable) {
                        // a reader suspended when the output fails gets the cause thrown, one that comes later gets -1
                        if (outputChannel.closedCause == null) throw e
                        -1
                    }
                if (n < 0) {
                    // ktor answers -1 for an output failed with a cause as for one closed: a failed one (the application's
                    // stream failed) gets no close_notify, which would end the stream for the peer as if complete, but an
                    // error alert where OpenSSL can send one (RFC 9846 section 6.1)
                    outputChannel.closedCause?.let {
                        sendFailureAlert()
                        throw it
                    }
                    shutdownSend()
                    return
                }
                var off = 0
                while (off < n) {
                    // ksl takes one record per call: offering more only makes the JNI layer copy bytes it does not take (32
                    // times what it takes with a 512-byte max_fragment_length)
                    val ask = minOf(n - off, recordBytes)
                    val w =
                        try {
                            lock.withLock { Ksl.tcpWrite(s(), buf, off, ask) }
                        } catch (
                            e: KslException.Internal,
                        ) {
                            alertAfterFailedWrite(e)
                            throw e.toTlsFailure(presented).first
                        }
                    if (w > 0) {
                        if (w < ask) recordBytes = w // a whole record was less than offered: that is the session's record size
                        off += w
                    }
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

    /**
     * RFC 9846 section 6.1: "Each party MUST send a 'close_notify' alert before closing its write side of the connection,
     * unless it has already sent some error alert". The application's stream failed: internal_error (80) follows what was
     * already sent, where OpenSSL can send one ([canSendFailureAlert]); never close_notify. The session takes no more data.
     */
    private suspend fun sendFailureAlert() {
        val sent = lock.withLock { ssl != 0L && !closed && canSendFailureAlert() && Ksl.tcpAbort(ssl) }
        if (sent) {
            drainToTransport()
            failureAlertSent = true
        }
    }

    /**
     * Whether OpenSSL 3.5 can send an alert on this established connection: it sends one only when building a handshake
     * message fails, and only two of those run a callback of ksl first (`ksl_tcp_abort`): a TLS 1.3 server's
     * NewSessionTicket and a TLS 1.2 client's renegotiation ClientHello. A TLS 1.3 client and a TLS 1.2 server have none.
     */
    private fun canSendFailureAlert(): Boolean = (protocolVersion == TlsVersion.Tls13) == (config.role == TlsRole.Server)

    @Volatile private var failureAlertSent = false

    /**
     * A write ksl refused may have ended the session with a fatal alert it queued: at the sending keys' record limit (RFC 9846
     * section 5.5) internal_error where one can be sent, or an alert OpenSSL raised. It leaves on the transport now, after
     * everything sent before, as [sendFailureAlert]'s does, and the connection then counts as alerted ([abortOutput] true: the
     * socket ends with a FIN, the peer failing on the alert); a failure with no alert sent leaves it reset.
     */
    private suspend fun alertAfterFailedWrite(e: KslException.Internal) {
        val sent = e.alert and 0x100 == 0 && e.alert and 0xff != 0
        if (!sent) return
        try {
            drainToTransport()
            failureAlertSent = true
        } catch (c: CancellationException) {
            throw c // the writer's cancellation stays its cause
        } catch (_: Throwable) {
            // the transport failed: no alert reached it, and the ksl failure stays the writer's cause
        }
    }

    /**
     * Fails [output] with [cause] (the application's stream failed) and waits, at most [timeout], until the internal_error
     * alert that ends the connection is written and flushed to the transport after everything sent before it. True when it
     * was: the caller may end the transport gracefully, the peer fails on the alert. False when no alert can be sent (a TLS
     * 1.3 client, a TLS 1.2 server: OpenSSL offers no way, see [canSendFailureAlert]), when the transport did not take it in
     * time, or when the connection had ended already: the caller resets the transport, so that the peer never sees a clean end.
     */
    @InternalKuicksilverApi
    public suspend fun abortOutput(
        cause: Throwable,
        timeout: Duration = SHUTDOWN_TIMEOUT,
    ): Boolean {
        outputChannel.cancel(cause)
        if (closed || !canSendFailureAlert()) return false
        withTimeoutOrNull(timeout) { writerJob?.join() }
        return failureAlertSent
    }

    /**
     * The handle of the newest session stored, compared only: once ksl has handed out every new ticket it returns the session's
     * current one, which is that one (the session holds it, so the address is not reused while they compare equal).
     */
    private var lastStored = 0L

    /**
     * After a NewSessionTicket the session changes; every new one is stored (a server sends several, RFC 9846 appendix C.4, so
     * that parallel connections each resume; each ticket is used once). ksl hands out the tickets in the order they came, then
     * the current session, which is the last one stored.
     */
    private suspend fun rememberSession() {
        while (rememberOneSession()) continue
    }

    /** Stores the next ticket ksl hands out; false when there is none. */
    private suspend fun rememberOneSession(): Boolean {
        val key = cacheKey ?: return false
        val entry =
            try {
                lock.withLock {
                    if (ssl == 0L) return false
                    val session = Ksl.sslGet1Session(ssl) // a native handle: the ticket and its secret never reach the heap
                    if (session == 0L) return false
                    if (session == cached?.session || session == lastStored) {
                        Ksl.sessionFree(session)
                        return false
                    } // the consumed ticket itself (single-use), or one stored already
                    lastStored = session
                    try {
                        val validated =
                            if (ctx.verifyMode == KslConst.VERIFY_OPENSSL &&
                                !reused
                            ) {
                                validated()
                            } else {
                                (cached?.validated ?: presented)
                            }
                        SessionCache.Entry(session, presented, validated, identityTag = ctx.identityTag)
                    } catch (t: Throwable) {
                        Ksl.sessionFree(session)
                        throw t
                    }
                }
            } catch (_: KslException.Internal) {
                return false
            }
        sessionCache.put(key, entry)
        return true
    }

    private suspend fun shutdownSend() {
        lock.withLock { runCatching { Ksl.tcpShutdown(s()) } }
        drainToTransport()
    }

    // ---- public operations ----

    /** RFC 5705 / RFC 9846 section 7.5 exporter; only after the handshake. Throws [IllegalStateException] when the exporter is unavailable, [TlsException.Protocol] for other TLS errors. */
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

    /** RFC 9846 section 4.7.3 key update; takes effect with the next write. */
    public suspend fun keyUpdate(requestPeer: Boolean = false) {
        lock.withLock { Ksl.sslKeyUpdate(s(), requestPeer) }
    }

    /**
     * Sends what the application wrote and `close_notify`, waits for the peer's, then releases the native session. The wait is
     * bounded: after 3 s in all, also when the peer stopped reading and the transport is full, the connection is closed
     * ([close]) with whatever was not sent.
     */
    public suspend fun shutdown(): Unit = shutdown(SHUTDOWN_TIMEOUT)

    /**
     * [shutdown] with the bound owned by the caller: [drainTimeout] bounds the whole shutdown, or, when null, sending what is
     * queued is not bounded (a slow reader gets the last response whole; the caller bounds the connection) and only the wait
     * for the peer's close_notify after it is (3 s).
     */
    @InternalKuicksilverApi
    public suspend fun shutdown(drainTimeout: Duration?) {
        if (closed) return
        val drain: suspend () -> Unit = {
            outputChannel.flushAndClose()
            writerJob?.join() // the writer pump sends close_notify after draining the output channel; a peer that stops reading stops it
        }
        // the reader pump ends on the peer's close_notify; never read the input channel here (its consumer may be mid-read)
        if (drainTimeout != null) {
            withTimeoutOrNull(drainTimeout) {
                drain()
                readerJob?.join()
            }
        } else {
            drain()
            withTimeoutOrNull(SHUTDOWN_TIMEOUT) { readerJob?.join() }
        }
        close()
    }

    /**
     * [close], then waits until the pumps have stopped: from then on nothing of this session reads the transport's input,
     * and its owner may read and drop what the peer still sends before it closes the transport (after a fatal alert, so
     * that a reset does not erase the alert before the peer read it). The caller bounds the wait.
     */
    @InternalKuicksilverApi
    public suspend fun closeAndAwaitPumps() {
        close()
        scope.coroutineContext[Job]!!.join()
    }

    /** Cancels the pumps and frees the native session once they have stopped and nobody holds the lock (never while any caller is inside ksl). */
    override fun close() {
        if (!closedFlag.compareAndSet(false, true)) return
        inputChannel.cancel(TlsException.Protocol(null, "connection closed", null))
        outputChannel.cancel(TlsException.Protocol(null, "connection closed", null))
        scope.coroutineContext[Job]!!.cancel() // its completion frees the native session ([ended])
    }

    /**
     * The pumps' job ended: through [close], or because the caller's job was cancelled, which ends the connection as a close
     * does: the channels fail (after [close] they have already). The native session is freed once nobody holds the lock.
     */
    private fun ended() {
        if (closedFlag.compareAndSet(false, true)) {
            inputChannel.cancel(TlsException.Protocol(null, "connection closed", null))
            outputChannel.cancel(TlsException.Protocol(null, "connection closed", null))
        }
        @OptIn(kotlinx.coroutines.DelicateCoroutinesApi::class)
        kotlinx.coroutines.GlobalScope.launch(Dispatchers.Default) { lock.withLock { freeNative() } }
    }

    /** Whether the native session was freed (tests). */
    internal val nativeFreedForTest: Boolean get() = ssl == 0L

    private fun freeNative() {
        if (ssl != 0L) {
            Ksl.sslFree(ssl)
            ssl = 0L
        }
        cached?.close()
        cached = null
        overrideCtx?.close()
        lease.close()
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
        /** How long [shutdown] waits for the pumps in all: the writer's last ciphertext and close_notify, then the peer's close_notify. */
        internal val SHUTDOWN_TIMEOUT: Duration = 3.seconds

        /**
         * Tickets a TCP server issues after a full handshake: RFC 9846 appendix C.4, "Servers that issue tickets SHOULD offer at least
         * as many tickets as the number of connections that a client might use; for example, a web browser using HTTP/1.1 `RFC9112`
         * might open six connections to a server". Six, the RFC's example; every resumption then brings one more, so a client
         * keeps as many as it uses at once. A server cannot see the client's parallelism before the connections arrive.
         */
        internal const val TCP_TICKETS: Int = 6

        /** Ciphertext the reader pump takes from the transport, and plaintext it gathers, per pass. */
        internal const val READ_CHUNK: Int = 64 * 1024

        /** The most plaintext one TLS record carries (RFC 9846 section 5.1: 2^14 bytes). */
        internal const val MAX_PLAINTEXT_RECORD: Int = 16 * 1024

        /** Ciphertext fed to ksl per call: a whole record (2^14 + 256 bytes and its header) fits ksl's pair of some 17 KiB. */
        internal const val FEED_CHUNK: Int = 16 * 1024 + 256 + 5

        /** The ALPN identifier of HTTP/2 over TLS (RFC 9113 section 3.2), whose connections a renegotiation ends (section 9.2.1). */
        private const val HTTP2_ALPN = "h2"

        /**
         * Whether [e], a read's failure on an established connection of [version], is OpenSSL refusing a post-handshake
         * message: TLS 1.3, unexpected_message (10) sent by us, OpenSSL's SSL_R_UNEXPECTED_MESSAGE (ERR_LIB_SSL 20, reason 244).
         * Tied to OpenSSL 3.5 (the pinned 3.5.9, gradle/openssl.toml): in `ssl/statem/statem_clnt.c`,
         * `ossl_statem_client13_read_transition` accepts in TLS_ST_OK only NewSessionTicket, KeyUpdate and a CertificateRequest
         * after post_handshake_auth was sent (`s->post_handshake_auth == SSL_PHA_EXT_SENT`, which ksl never sends), and
         * `ossl_statem_client_read_transition` ends any other message with `SSLfatal(s, SSL3_AD_UNEXPECTED_MESSAGE,
         * SSL_R_UNEXPECTED_MESSAGE)` before its body is read, so no message callback sees it; ksl packs that error
         * (`ksl_pack_openssl_error`) and the alert sent (`info_cb`). Check both again when the OpenSSL pin moves to another
         * minor or major version. No peer can be driven to send the message (an OpenSSL server refuses
         * SSL_verify_client_post_handshake without the client's extension), so tests build the failure ksl reports.
         */
        internal fun refusedPostHandshakeMessage(
            version: TlsVersion,
            e: KslException.Internal,
        ): Boolean =
            version == TlsVersion.Tls13 && e.alert and 0x1ff == UNEXPECTED_MESSAGE_ALERT && e.lib == ERR_LIB_SSL &&
                e.reason == SSL_R_UNEXPECTED_MESSAGE

        private const val UNEXPECTED_MESSAGE_ALERT = 10
        private const val ERR_LIB_SSL = 20
        private const val SSL_R_UNEXPECTED_MESSAGE = 244

        /**
         * Runs a client handshake over `transportIn`/`transportOut` and returns once it completed and the server passed
         * [TlsConfig.trust] and the host name check. A cached session for the same name and trust is resumed automatically
         * and re-checked. The pumps run in [context] (their parent job, if any); cancelling it ends the connection as [close] does
         * (the channels fail, the native session is freed).
         * Throws [TlsException]: [TlsException.Config] for a server configuration or a client without a reference identifier,
         * [TlsException.Verify], [TlsException.AlertReceived], or [TlsException.Protocol] (also after
         * [TlsConfig.handshakeTimeout]). On failure the alert is flushed and `transportOut` is closed.
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
         * Runs a server handshake over `transportIn`/`transportOut` and returns once it completed: the identity is chosen
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
            val ctx = KslContext.acquire(config, quic = false)
            val c =
                try {
                    TlsConnection(ctx, transportIn, transportOut, context, sessionCache)
                } catch (t: Throwable) {
                    ctx.close() // a connection that could not be built never owned it
                    throw t
                }
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

    /** TLS 1.3 (RFC 9846). */
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
        /** The client identity the session was authenticated with (`KslContext.identityTag`); resumed only under the same one. */
        val identityTag: String? = null,
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

    // per origin the tickets oldest first; insertion order of the origins: the head is the least recently stored one
    private val entries = LinkedHashMap<String, ArrayDeque<Entry>>()
    private var count = 0
    internal val mutex = Mutex() // internal for the tests

    /** The process-wide cache, key derivation and the default bound. */
    @InternalKuicksilverApi
    public companion object {
        /**
         * Sessions a cache keeps before the oldest is evicted: the [TICKETS_PER_ORIGIN] tickets of each of 64 TCP origins (or 384
         * QUIC origins, one ticket each).
         */
        public const val DEFAULT_MAX_ENTRIES: Int = 384

        /**
         * Tickets kept per TCP origin (RFC 9846 appendix C.4: one for each of the client's parallel connections; six, as a server's
         * [TlsConnection.TCP_TICKETS]); a QUIC origin keeps one.
         */
        internal const val TICKETS_PER_ORIGIN: Int = 6
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

    /** Removes and returns the newest live ticket of [key]: a ticket is used at most once (RFC 9846 appendix C.4). */
    internal suspend fun take(key: String): Entry? =
        mutex.withLock {
            val list = entries[key] ?: return null
            var found: Entry? = null
            while (found == null && list.isNotEmpty()) {
                val e = list.removeLast()
                count--
                if (nowSeconds() - e.created > TTL_SECONDS) e.close() else found = e
            }
            if (list.isEmpty()) entries.remove(key)
            found
        }

    private var closed = false

    /**
     * Stores [entry] and drops every expired session, so the cache never keeps dead tickets (and their native secrets) until
     * their key is asked for. The cache owns [entry] from the call on: a closed cache releases it at once, and so does a
     * caller cancelled while it waited for the lock (a TLS reader whose connection closed), or nothing would free it.
     */
    internal suspend fun put(
        key: String,
        entry: Entry,
        keep: Int = TICKETS_PER_ORIGIN,
    ) {
        var taken = false
        try {
            mutex.withLock {
                taken = true
                if (closed) {
                    entry.close()
                    return
                }
                store(key, entry, keep)
            }
        } finally {
            if (!taken) entry.close()
        }
    }

    private fun store(
        key: String,
        entry: Entry,
        keep: Int,
    ) {
        val list = entries.remove(key) ?: ArrayDeque() // re-inserted at the tail: a fresh ticket makes its origin the most recent
        entries[key] = list
        list.addLast(entry)
        count++
        while (list.size > keep) {
            list.removeFirst().close()
            count--
        }
        val now = nowSeconds()
        val lists = entries.values.iterator()
        while (lists.hasNext()) {
            val l = lists.next()
            val expired = l.filter { e -> now - e.created > TTL_SECONDS }
            expired.forEach { e -> e.close() }
            l.removeAll(expired)
            count -= expired.size
            if (l.isEmpty()) lists.remove()
        }
        while (count > maxEntries) {
            val oldest = entries.entries.iterator().next()
            oldest.value.removeFirst().close()
            count--
            if (oldest.value.isEmpty()) entries.remove(oldest.key)
        }
    }

    /** Drops every cached session and releases whatever is stored later: the owner (an engine, an endpoint) is gone. */
    public suspend fun close() {
        mutex.withLock {
            closed = true
            entries.values.forEach { l -> l.forEach { it.close() } }
            entries.clear()
            count = 0
        }
    }

    /** Drops every cached session (tests, credential rotation). */
    public suspend fun clear() {
        mutex.withLock {
            entries.values.forEach { l -> l.forEach { it.close() } }
            entries.clear()
            count = 0
        }
    }

    /** Number of cached sessions. */
    public suspend fun size(): Int = mutex.withLock { count }

    internal suspend fun peek(key: String): Boolean = mutex.withLock { entries[key]?.isNotEmpty() == true }

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
        put(quicKey(config), ticket.entry, keep = 1)
    }

    private fun quicKey(config: TlsConfig): String =
        "quic|" + config.alpn.joinToString(",") + "|" +
            key(config.serverName, HostName.normalize(referenceOf(config)).value, config.trust, config.identity)
}

internal expect fun nowSeconds(): Long

/** Test hook: seconds added to the clock of a resumption's re-verification, to age a cached chain without waiting. */
@kotlin.concurrent.Volatile
internal var resumptionClockSkewForTest: Long = 0L

/**
 * Verifies a chain cached from a full handshake again with this context's OpenSSL verifier (AnchoredCa, Platform on Linux, Pinned or
 * ExpectedName over them): validity at the current time, the anchors, the name and the purpose, as the handshake did (ADR-0011:
 * resumption never bypasses verification). The platform and custom verifiers re-run through [Verification.verify] instead.
 */
internal fun KslContext.cachedChainStillTrusted(
    chain: List<Certificate>,
    reference: HostName,
): Boolean =
    chain.isNotEmpty() &&
        Ksl.ctxVerifyChain(handle, chain.map { it.encoded }, reference.value, nowSeconds() + resumptionClockSkewForTest) == 0

internal fun TrustConfig.cacheKey(): String =
    when (this) {
        is TrustConfig.Platform -> "platform"
        is TrustConfig.AnchoredCa -> "ca:" + roots.joinToString(",") { it.spkiSha256.toString() }
        is TrustConfig.ExpectedName -> "name:$name/" + base.cacheKey()
        is TrustConfig.Pinned -> "pin:$scope:" + pins.map { it.toString() }.sorted().joinToString(",") + "/" + base.cacheKey()
        is TrustConfig.Tofu -> "tofu:${store.hashCode()}"
        is TrustConfig.Custom -> "custom:${verifier.hashCode()}"
    }

/**
 * [TlsConnection.input]: [inner] as the reader pump fills it, failing with a recorded failure only once what [inner]
 * already holds was read. ktor-io's own channel drops its buffered bytes when it is cancelled (`readBuffer` throws as soon
 * as a cause is set), so bytes the peer sent right before an abortive close were lost. A failure is never a clean end:
 * `isClosedForRead` stays false and every read past the delivered bytes throws it, as `cancel` made it before
 * (ClosedByteChannelException with the TLS failure as its cause).
 */
@OptIn(io.ktor.utils.io.InternalAPI::class)
private class DeliverThenFail(
    private val inner: ByteChannel,
) : ByteReadChannel {
    @Volatile private var failure: Throwable? = null

    /** Records [cause] and closes [inner] cleanly: its bytes stay readable, then reads fail with [cause]. */
    suspend fun failAfterBuffered(cause: Throwable) {
        if (failure == null) {
            failure =
                io.ktor.utils.io
                    .ClosedByteChannelException(cause)
        }
        // an input the application cancelled already has its own cause and nothing to deliver
        runCatching { inner.flushAndClose() }
    }

    override val closedCause: Throwable? get() = failure ?: inner.closedCause

    // in this order: the failure is recorded before inner closes, so a failure between the two reads is never a clean end
    override val isClosedForRead: Boolean get() = inner.isClosedForRead && failure == null

    override val readBuffer: kotlinx.io.Source get() {
        val f = failure
        if (f != null && inner.isClosedForRead) throw f
        return inner.readBuffer
    }

    override suspend fun awaitContent(min: Int): Boolean {
        val enough = inner.awaitContent(min)
        if (!enough) failure?.let { throw it }
        return enough
    }

    override fun cancel(cause: Throwable?) {
        inner.cancel(cause)
    }
}

/**
 * Follows the TLS record framing of the ciphertext fed to ksl (RFC 9846 section 5.1: a 5-byte header whose last two bytes
 * are the length) to count the records whose last byte went in; it follows a connection from its first byte, the
 * handshake's included. A header that cannot be one (anything unexpected) makes it [lost] for good: the reader pump then wakes the drainer after every pass, as
 * it always did.
 */
internal class RecordFraming {
    private val header = ByteArray(5)
    private var headerHave = 0
    private var bodyLeft = 0

    var lost: Boolean = false
        private set

    /** Accounts for [len] bytes of [buf] from [off]; returns how many records they completed. */
    fun complete(
        buf: ByteArray,
        off: Int,
        len: Int,
    ): Int {
        var p = off
        val end = off + len
        var done = 0
        while (p < end && !lost) {
            if (bodyLeft > 0) {
                val k = minOf(bodyLeft, end - p)
                bodyLeft -= k
                p += k
                if (bodyLeft == 0) done++
                continue
            }
            header[headerHave++] = buf[p++]
            if (headerHave < header.size) continue
            headerHave = 0
            val type = header[0].toInt() and 0xff
            val length = ((header[3].toInt() and 0xff) shl 8) or (header[4].toInt() and 0xff)
            // content types 20..24 (RFC 9846 section 5.1, RFC 6520), legacy version 3.x, at most 2^14 + 2048 bytes (TLS 1.2)
            if (type !in 20..24 || header[1].toInt() != 3 || length > (1 shl 14) + 2048) {
                lost = true
            } else if (length == 0) {
                done++
            } else {
                bodyLeft = length
            }
        }
        return done
    }
}

/** The cause of the [TlsException.Protocol] a handshake fails with at its own deadline ([TlsConfig.handshakeTimeout]). */
private class HandshakeTimedOut : kotlinx.io.IOException("no handshake within its deadline")

/**
 * Whether this failure is a handshake that ran out its own deadline ([TlsConfig.handshakeTimeout]): the peer has been
 * silent, so its owner need not wait for anything more from it before closing the transport.
 */
@InternalKuicksilverApi
public val Throwable.isHandshakeTimeout: Boolean get() = this is TlsException.Protocol && cause is HandshakeTimedOut
