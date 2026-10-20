// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.bench

import kotlinx.benchmark.Benchmark
import kotlinx.benchmark.BenchmarkMode
import kotlinx.benchmark.Mode
import kotlinx.benchmark.Param
import kotlinx.benchmark.Scope
import kotlinx.benchmark.Setup
import kotlinx.benchmark.State
import kotlinx.benchmark.TearDown

/**
 * One operation moves one MiB of stream data client → server through [CoreLoopback]; ops/s is therefore MiB/s. [crypto]: `null`
 * (the Null provider: the transport alone) or `ksl` (AES-128-GCM and header protection through `ksl`, as on the wire).
 */
@State(Scope.Benchmark)
@BenchmarkMode(Mode.Throughput)
@OptIn(io.kuicksilver.annotations.InternalKuicksilverApi::class)
public class CoreThroughputBenchmark {
    @Param("null", "ksl") public var crypto: String = "null"
    private lateinit var loop: CoreLoopback

    @Setup public fun setup() {
        loop = CoreLoopback(streams = 1, payload = 1200, crypto = if (crypto == "ksl") io.kuicksilver.tls.KslQuicCrypto else io.kuicksilver.quic.NullCryptoProvider)
        check(loop.handshake()) { "handshake" }
    }
    @TearDown public fun tearDown() { loop.close() }

    @Benchmark public fun transfer(): Long {
        val target = loop.bytesReceived + (1L shl 20)
        while (loop.bytesReceived < target) loop.step()
        return loop.bytesReceived
    }
}
