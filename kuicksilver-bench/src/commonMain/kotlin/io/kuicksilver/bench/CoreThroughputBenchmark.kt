// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.bench

import kotlinx.benchmark.Benchmark
import kotlinx.benchmark.BenchmarkMode
import kotlinx.benchmark.Mode
import kotlinx.benchmark.Scope
import kotlinx.benchmark.Setup
import kotlinx.benchmark.State
import kotlinx.benchmark.TearDown

/** One operation moves one MiB of stream data client → server through [CoreLoopback]; ops/s is therefore MiB/s. */
@State(Scope.Benchmark)
@BenchmarkMode(Mode.Throughput)
public class CoreThroughputBenchmark {
    private lateinit var loop: CoreLoopback

    @Setup public fun setup() { loop = CoreLoopback(streams = 1, payload = 1200); check(loop.handshake()) { "handshake" } }
    @TearDown public fun tearDown() { loop.close() }

    @Benchmark public fun transfer(): Long {
        val target = loop.bytesReceived + (1L shl 20)
        while (loop.bytesReceived < target) loop.step()
        return loop.bytesReceived
    }
}
