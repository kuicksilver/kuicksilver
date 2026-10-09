// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(ExperimentalKuicksilverApi::class)

package io.kuicksilver.native

import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertSame

/** Kotlin/Native: the statically linked library is unavailable only when initialization or the ABI check fails. */
class KslAvailabilityNativeTest {
    @Test fun staticLibraryIsAvailable() {
        assertSame(NativeAvailability.Available, KslLoader.attempt())
    }

    @Test fun abiMismatchIsReportedWithoutThrowing() {
        val a = KslLoader.attempt(expectedAbi = 99)
        assertIs<NativeAvailability.Unavailable>(a)
        assertEquals(NativeUnavailableReason.AbiMismatch, a.reason)
        assertIs<KslException.AbiMismatch>(a.cause)
    }
}
