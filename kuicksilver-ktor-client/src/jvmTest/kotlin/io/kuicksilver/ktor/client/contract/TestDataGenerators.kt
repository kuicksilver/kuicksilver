// Copyright 2014-2025 JetBrains s.r.o and contributors. Use of this source code is governed by the Apache 2.0 license.
// Modifications Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
// Vendored from Ktor 3.6.0 ktor-client/ktor-client-tests/common/test/io/ktor/client/tests/utils/TestDataGenerators.kt, adapted to the Kuicksilver engine.
package io.kuicksilver.ktor.client.contract

import kotlin.random.Random

internal fun generateRandomByteArray(
    minSize: Int,
    maxSize: Int = minSize + 1,
): ByteArray {
    require(minSize >= 0)
    require(minSize < maxSize) { "Failed to generate in range: [$minSize, $maxSize)" }

    val resultSize = Random.nextInt(minSize, maxSize)
    return Random.nextBytes(resultSize)
}
