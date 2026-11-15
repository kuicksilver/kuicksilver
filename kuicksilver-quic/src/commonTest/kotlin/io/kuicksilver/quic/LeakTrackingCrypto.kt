// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic

import io.kuicksilver.annotations.DelicateKuicksilverApi
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.annotations.InternalKuicksilverApi
import io.kuicksilver.native.Ksl
import io.kuicksilver.native.KslConst
import io.kuicksilver.native.packetBuffersOpenOnThisThread
import io.kuicksilver.tls.LoadBalancerKey
import io.kuicksilver.tls.PacketProtector
import io.kuicksilver.tls.QuicCrypto
import io.kuicksilver.tls.QuicTlsSession
import io.kuicksilver.tls.ResetKey
import io.kuicksilver.tls.TlsConfig
import io.kuicksilver.tls.TlsEvent
import io.kuicksilver.tls.TlsRole
import io.kuicksilver.tls.TokenKey

/**
 * A [QuicCrypto] that counts every native-backed object it hands out (TLS sessions, packet protectors, including those
 * that arrive in [TlsEvent.Keys] and those made by [PacketProtector.next], token, reset and load-balancer keys) and every
 * one closed again. [live] lists the ones still open, by kind and where they came from: after a connection reached its
 * terminal state it must be empty, whatever ended it. Closing twice counts once (the protectors' close is idempotent).
 *
 * [failInitialProtectors] (the call number from which [QuicCrypto.initialProtectors] fails), [failTransportParameters]
 * (the role whose sessions fail [QuicTlsSession.setTransportParameters]) and [failNext] stand for a native failure, an
 * allocation that fails, on the paths that build a connection or derive its next keys.
 */
@OptIn(DelicateKuicksilverApi::class, InternalKuicksilverApi::class, ExperimentalKuicksilverApi::class)
internal class LeakTrackingCrypto(
    private val inner: QuicCrypto,
    var failInitialProtectors: Int = Int.MAX_VALUE,
    var failTransportParameters: TlsRole? = null,
    /** The call number of [PacketProtector.next] (counted over every protector) from which it fails. */
    var failNext: Int = Int.MAX_VALUE,
) : QuicCrypto by inner {
    private var nextCalls = 0

    private var nextId = 0
    private val open = LinkedHashMap<Int, String>()
    private var initialCalls = 0

    /** What is still open: one line per object, its kind and its origin. */
    val live: List<String> get() = open.values.toList()

    /** Objects handed out so far. */
    var made = 0
        private set

    private fun opened(what: String): () -> Unit {
        val id = nextId++
        made++
        open[id] = what
        var done = false
        return {
            if (!done) {
                done = true
                open.remove(id)
            }
        }
    }

    private fun track(
        p: PacketProtector,
        what: String,
    ): PacketProtector {
        val closed = opened(what)
        return object : PacketProtector by p {
            override fun next(): PacketProtector {
                if (++nextCalls >= failNext) throw IllegalStateException("key derivation refused (test)")
                return track(p.next(), "$what+next")
            }

            override fun close() {
                closed()
                p.close()
            }
        }
    }

    private fun track(
        s: QuicTlsSession,
        role: TlsRole,
    ): QuicTlsSession {
        val closed = opened("session $role")
        return object : QuicTlsSession by s {
            override fun setTransportParameters(encoded: ByteArray) {
                if (failTransportParameters == role) throw IllegalStateException("transport parameters refused (test)")
                s.setTransportParameters(encoded)
            }

            override fun nextEvent(): TlsEvent? =
                when (val e = s.nextEvent()) {
                    is TlsEvent.Keys -> TlsEvent.Keys(e.level, e.direction, track(e.protector, "$role ${e.level} ${e.direction}"))
                    else -> e
                }

            override fun close() {
                closed()
                s.close()
            }
        }
    }

    override fun newSession(config: TlsConfig): QuicTlsSession = track(inner.newSession(config), config.role)

    override fun newSession(
        config: TlsConfig,
        earlyData: Boolean,
    ): QuicTlsSession = track(inner.newSession(config, earlyData), config.role)

    override fun initialProtectors(
        dcid: ByteArray,
        version: Int,
        role: TlsRole,
    ): Pair<PacketProtector, PacketProtector> {
        if (++initialCalls >= failInitialProtectors) throw IllegalStateException("initial keys refused (test)")
        val (r, w) = inner.initialProtectors(dcid, version, role)
        return track(r, "$role initial read v$version") to track(w, "$role initial write v$version")
    }

    override fun newTokenKey(): TokenKey {
        val k = inner.newTokenKey()
        val closed = opened("token key")
        return object : TokenKey by k {
            override fun close() {
                closed()
                k.close()
            }
        }
    }

    override fun newResetKey(): ResetKey {
        val k = inner.newResetKey()
        val closed = opened("reset key")
        return object : ResetKey by k {
            override fun close() {
                closed()
                k.close()
            }
        }
    }

    override fun newLoadBalancerKey(key: ByteArray?): LoadBalancerKey {
        val k = inner.newLoadBalancerKey(key)
        val closed = opened("load-balancer key")
        return object : LoadBalancerKey by k {
            override fun close() {
                closed()
                k.close()
            }
        }
    }
}

/**
 * The process-wide counts of the native objects a connection makes and frees itself (ksl's live-object counters): TLS
 * sessions (`ksl_ssl`), keys (`ksl_key`) and session references. Contexts and private keys are cached and shared across
 * connections, so they are not counted here. Read it before and after a sans-IO scenario on one thread: nothing else in a
 * test JVM makes these objects meanwhile once earlier tests closed their endpoints. The last element counts the
 * [io.kuicksilver.native.PacketBuffer]s open on this thread (the scratch buffers a connection allocates and frees).
 */
@OptIn(InternalKuicksilverApi::class)
internal fun nativeConnectionObjects(): List<Long> =
    Ksl.liveObjects().let { listOf(it[KslConst.LIVE_SSL], it[KslConst.LIVE_KEY], it[KslConst.LIVE_SESSION]) } +
        packetBuffersOpenOnThisThread()
