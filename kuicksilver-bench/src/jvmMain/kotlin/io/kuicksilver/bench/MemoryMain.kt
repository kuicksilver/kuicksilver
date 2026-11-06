// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.bench

import kotlinx.coroutines.runBlocking

/** `MemoryMain [connections] [transferMiB] [section...]`: [MemoryBench] on the JVM (`./gradlew :kuicksilver-bench:jvmMemory`). */
public fun main(args: Array<String>) {
    runBlocking { MemoryBench.run(args.getOrNull(0)?.toInt() ?: 1000, args.getOrNull(1)?.toInt() ?: 256, args.drop(2).toSet().ifEmpty { MemoryBench.sections.toSet() }) }
}
