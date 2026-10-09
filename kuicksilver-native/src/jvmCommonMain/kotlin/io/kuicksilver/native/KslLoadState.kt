// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(ExperimentalKuicksilverApi::class)

package io.kuicksilver.native

import io.kuicksilver.annotations.ExperimentalKuicksilverApi

/**
 * The outcome of the one load attempt of a process (JVM and Android): [attempt] runs at most once, under a lock, and its
 * answer, available or not, is kept. [ensureLoaded] rethrows the attempt's own exception, so it reports exactly what
 * [availability] saw.
 */
internal class KslLoadState(
    private val attempt: () -> NativeAvailability,
) {
    @Volatile private var outcome: NativeAvailability? = null

    fun availability(): NativeAvailability =
        outcome ?: synchronized(this) {
            outcome ?: attempt().also { outcome = it }
        }

    fun ensureLoaded() {
        val a = availability() as? NativeAvailability.Unavailable ?: return
        throw a.cause ?: KslException.NativeLoad(JvmNativeNames.os, JvmNativeNames.classifier, a.detail, null, a.reason)
    }
}

/**
 * Runs [load] (which throws on failure) and turns its failure into [NativeAvailability.Unavailable]; fatal VM errors
 * ([VirtualMachineError], e.g. out of memory) propagate, since caching them would misreport a healthy installation.
 */
internal inline fun attemptLoad(load: () -> Unit): NativeAvailability =
    try {
        load()
        NativeAvailability.Available
    } catch (e: VirtualMachineError) {
        throw e
    } catch (e: Throwable) {
        unavailable(e)
    }

/** Classifies a load failure: the kind a [KslException.NativeLoad] was thrown with, [KslException.AbiMismatch], else [NativeUnavailableReason.LoadFailed]. */
internal fun unavailable(failure: Throwable): NativeAvailability.Unavailable {
    val reason =
        when (failure) {
            is KslException.NativeLoad -> failure.kind
            is KslException.AbiMismatch -> NativeUnavailableReason.AbiMismatch
            else -> NativeUnavailableReason.LoadFailed
        }
    return NativeAvailability.Unavailable(reason, failure.message ?: failure.toString(), failure)
}
