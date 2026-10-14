// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.network

import kotlin.test.Test
import kotlin.test.assertNull

/** On Android the Ktor version cannot be read (dex classes, packages defined as "0.0"): the check passes instead of failing every engine. */
class KtorVersionPolicyAndroidTest {
    @Test fun theVersionOfADexedKtorIsUnknownAndAccepted() {
        assertNull(ktorArtifactVersion(io.ktor.network.selector.SelectorManager::class))
        @OptIn(io.kuicksilver.annotations.InternalKuicksilverApi::class)
        KtorVersionPolicy.check("ktor-network" to io.ktor.network.selector.SelectorManager::class)
    }
}
