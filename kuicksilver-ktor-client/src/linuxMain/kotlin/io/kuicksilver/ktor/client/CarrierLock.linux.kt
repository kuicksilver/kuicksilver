// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(kotlinx.cinterop.ExperimentalForeignApi::class)

package io.kuicksilver.ktor.client

import kotlinx.cinterop.alloc
import kotlinx.cinterop.nativeHeap
import kotlinx.cinterop.ptr
import platform.posix.pthread_mutex_init
import platform.posix.pthread_mutex_lock
import platform.posix.pthread_mutex_t
import platform.posix.pthread_mutex_unlock

/** One mutex for every carrier (allocated once, never freed): a suppressed list is not thread-safe on Kotlin/Native. */
private val carrierMutex = nativeHeap.alloc<pthread_mutex_t>().also { pthread_mutex_init(it.ptr, null) }

internal actual fun <T> withCarrierLock(
    e: Throwable,
    block: () -> T,
): T {
    pthread_mutex_lock(carrierMutex.ptr)
    try {
        return block()
    } finally {
        pthread_mutex_unlock(carrierMutex.ptr)
    }
}
