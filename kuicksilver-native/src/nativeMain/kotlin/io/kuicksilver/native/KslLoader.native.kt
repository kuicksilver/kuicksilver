// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(ExperimentalForeignApi::class, InternalKuicksilverApi::class, ExperimentalKuicksilverApi::class)

package io.kuicksilver.native

import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.annotations.InternalKuicksilverApi
import io.kuicksilver.native.cinterop.ksl_abi_version
import io.kuicksilver.native.cinterop.ksl_init
import kotlinx.cinterop.ExperimentalForeignApi
import kotlin.concurrent.AtomicReference

/**
 * Kotlin/Native links ksl and OpenSSL statically into the binary: loading is initialization plus the ABI check. The first
 * outcome is published once and kept; threads racing on the first call may each run the idempotent `ksl_init`, but all of
 * them see the same outcome.
 */
public actual object KslLoader {
    private val outcome = AtomicReference<NativeAvailability?>(null)

    public actual fun ensureLoaded() {
        val a = availability() as? NativeAvailability.Unavailable ?: return
        throw a.cause ?: KslException.NativeLoad("native", "static", a.detail, null, a.reason)
    }

    @ExperimentalKuicksilverApi
    public actual fun availability(): NativeAvailability {
        outcome.value?.let { return it }
        outcome.compareAndSet(null, attempt())
        return outcome.value!!
    }

    @ExperimentalKuicksilverApi
    public actual fun isAvailable(): Boolean = availability() is NativeAvailability.Available

    internal fun attempt(expectedAbi: Int = KSL_ABI_VERSION): NativeAvailability {
        if (ksl_init() != 0) {
            val e = KslException.NativeLoad("native", "static", "ksl_init failed")
            return NativeAvailability.Unavailable(NativeUnavailableReason.LoadFailed, e.message!!, e)
        }
        val native = ksl_abi_version().toInt()
        if (native != expectedAbi) {
            val e = KslException.AbiMismatch(native, expectedAbi)
            return NativeAvailability.Unavailable(NativeUnavailableReason.AbiMismatch, e.message!!, e)
        }
        return NativeAvailability.Available
    }
}
