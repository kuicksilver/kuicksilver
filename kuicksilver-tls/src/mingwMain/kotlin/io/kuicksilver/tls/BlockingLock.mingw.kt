// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(kotlinx.cinterop.ExperimentalForeignApi::class, kotlin.experimental.ExperimentalNativeApi::class)

package io.kuicksilver.tls

import kotlinx.cinterop.alloc
import kotlinx.cinterop.nativeHeap
import kotlinx.cinterop.ptr
import platform.windows.AcquireSRWLockExclusive
import platform.windows.InitializeSRWLock
import platform.windows.ReleaseSRWLockExclusive
import platform.windows.SRWLOCK
import kotlin.native.ref.createCleaner

/** A slim reader/writer lock in native memory, taken exclusively; freed with the object (an SRW lock needs no destroy). */
internal actual class BlockingLock actual constructor() {
    private val srw = nativeHeap.alloc<SRWLOCK>().also { InitializeSRWLock(it.ptr) }

    @Suppress("unused") // frees the lock once it is unreachable
    private val cleaner = createCleaner(srw) { nativeHeap.free(it.rawPtr) }

    actual fun lock() {
        AcquireSRWLockExclusive(srw.ptr)
    }

    actual fun unlock() {
        ReleaseSRWLockExclusive(srw.ptr)
    }
}
