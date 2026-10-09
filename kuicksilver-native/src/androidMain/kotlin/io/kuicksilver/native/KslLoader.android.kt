// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(ExperimentalKuicksilverApi::class)

package io.kuicksilver.native

import io.kuicksilver.annotations.ExperimentalKuicksilverApi

/**
 * Android: libksl.so ships in the AAR's jniLibs; the system loader handles extraction (minSdk 24 needs no ReLinker). One
 * attempt per process, its outcome kept (see [availability]).
 */
public actual object KslLoader {
    private val state = KslLoadState { attemptLoad(::load) }

    public actual fun ensureLoaded() {
        state.ensureLoaded()
    }

    @ExperimentalKuicksilverApi
    public actual fun availability(): NativeAvailability = state.availability()

    @ExperimentalKuicksilverApi
    public actual fun isAvailable(): Boolean = availability() is NativeAvailability.Available

    private fun load() {
        val abi = System.getProperty("os.arch") ?: "?"
        try {
            System.loadLibrary("ksl")
        } catch (e: UnsatisfiedLinkError) {
            // `couldn't find "libksl.so"`: the APK carries no library for this CPU ABI (an ABI split, an unsupported ABI)
            val missing = e.message?.contains("couldn't find") == true
            throw KslException.NativeLoad(
                "android",
                abi,
                e.message ?: "loadLibrary failed",
                e,
                if (missing) NativeUnavailableReason.NoLibraryForPlatform else NativeUnavailableReason.LoadFailed,
            )
        }
        val native = KslNative.abiVersion()
        if (native != KSL_ABI_VERSION) throw KslException.AbiMismatch(native, KSL_ABI_VERSION)
        val init = KslNative.init()
        if (init != 0) throw KslException.NativeLoad("android", abi, "ksl_init failed ($init)")
    }
}
