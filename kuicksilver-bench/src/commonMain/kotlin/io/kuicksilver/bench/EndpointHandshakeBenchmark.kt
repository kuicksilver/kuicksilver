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
import kotlinx.coroutines.runBlocking

/**
 * One operation is one QUIC connection through two endpoints over a `MemoryNetwork` ([EndpointHandshakes]): the client
 * connects, the server accepts, the client closes. Unlike [HandshakeBenchmark] this includes the runtimes (endpoint loops,
 * coroutines, timers) of both sides; ops/s is connections per second for the pair in one process.
 */
@State(Scope.Benchmark)
@BenchmarkMode(Mode.Throughput)
public class EndpointHandshakeBenchmark {
    private lateinit var pair: EndpointHandshakes

    @Setup public fun setup() {
        pair = runBlocking { EndpointHandshakes.open().also { it.connection() } }
    }
    @TearDown public fun tearDown() { pair.close() }

    @Benchmark public fun connection() { runBlocking { pair.connection() } }
}
