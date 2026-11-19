// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(kotlinx.cinterop.ExperimentalForeignApi::class)

package io.kuicksilver.quic

import kotlinx.cinterop.ByteVar
import kotlinx.cinterop.CFunction
import kotlinx.cinterop.COpaquePointer
import kotlinx.cinterop.CPointed
import kotlinx.cinterop.CPointer
import kotlinx.cinterop.CPointerVar
import kotlinx.cinterop.UIntVar
import kotlinx.cinterop.UShortVar
import kotlinx.cinterop.alloc
import kotlinx.cinterop.allocArray
import kotlinx.cinterop.get
import kotlinx.cinterop.invoke
import kotlinx.cinterop.memScoped
import kotlinx.cinterop.plus
import kotlinx.cinterop.pointed
import kotlinx.cinterop.ptr
import kotlinx.cinterop.reinterpret
import kotlinx.cinterop.set
import kotlinx.cinterop.toCPointer
import kotlinx.cinterop.value
import platform.windows.CloseHandle
import platform.windows.DWORDVar
import platform.windows.GetCurrentProcess
import platform.windows.GetCurrentProcessId
import platform.windows.GetHandleInformation
import platform.windows.GetModuleHandleW
import platform.windows.GetProcAddress
import platform.windows.GetProcessHandleCount

internal actual fun openHandleCount(): Int =
    memScoped {
        val count = alloc<DWORDVar>()
        check(GetProcessHandleCount(GetCurrentProcess(), count.ptr) != 0) { "GetProcessHandleCount failed" }
        count.value.toInt()
    }

/** NtQueryObject (ntdll): the object type of a handle, ObjectTypeInformation (2) without its name lookup, which cannot block. */
private typealias NtQueryObject = CFunction<(COpaquePointer?, Int, COpaquePointer?, UInt, CPointer<UIntVar>?) -> Int>

/** CreateToolhelp32Snapshot and Thread32First/Next (kernel32; tlhelp32.h is not in Kotlin/Native's bindings). */
private typealias Snapshot = CFunction<(UInt, UInt) -> COpaquePointer?>
private typealias ThreadWalk = CFunction<(COpaquePointer?, COpaquePointer?) -> Int>

/**
 * The process's handles by object type (NtQueryObject: "Event", "Thread", "File", "IoCompletion", ...), the handle table read
 * from value 4 up until every counted handle was seen, plus "threads (Toolhelp)", the threads the process runs.
 */
internal actual fun handleBreakdown(): Map<String, Int> =
    memScoped {
        val out = HashMap<String, Int>()
        val query = GetProcAddress(GetModuleHandleW("ntdll.dll"), "NtQueryObject")?.reinterpret<NtQueryObject>()
        val info = allocArray<UIntVar>(256) // 1 KiB, 8-byte aligned: PUBLIC_OBJECT_TYPE_INFORMATION and its name
        val returned = alloc<UIntVar>()
        val flags = alloc<DWORDVar>()
        val total = openHandleCount()
        var seen = 0
        var value = 4L
        while (seen < total && value < 0x400000L) {
            val h = value.toCPointer<CPointed>()
            if (GetHandleInformation(h, flags.ptr) != 0) {
                seen++
                val type =
                    if (query != null && query(h, 2, info, 1024u, returned.ptr) >= 0) {
                        // UNICODE_STRING TypeName: USHORT Length (bytes), USHORT MaximumLength, 4 bytes padding, PWSTR Buffer
                        val bytes =
                            info
                                .reinterpret<UShortVar>()
                                .pointed.value
                                .toInt()
                        val name = (info.reinterpret<ByteVar>() + 8)!!.reinterpret<CPointerVar<UShortVar>>().pointed.value
                        if (name == null) "?" else CharArray(bytes / 2) { i -> name[i].toInt().toChar() }.concatToString()
                    } else {
                        "?"
                    }
                out[type] = (out[type] ?: 0) + 1
            }
            value += 4
        }
        out["threads (Toolhelp)"] = threadCount()
        out
    }

/** The threads of this process (Toolhelp's thread snapshot); -1 when it cannot be read. */
private fun threadCount(): Int =
    memScoped {
        val kernel32 = GetModuleHandleW("kernel32.dll")
        val snapshot = GetProcAddress(kernel32, "CreateToolhelp32Snapshot")?.reinterpret<Snapshot>() ?: return -1
        val first = GetProcAddress(kernel32, "Thread32First")?.reinterpret<ThreadWalk>() ?: return -1
        val next = GetProcAddress(kernel32, "Thread32Next")?.reinterpret<ThreadWalk>() ?: return -1
        val snap = snapshot(0x4u, 0u) ?: return -1 // TH32CS_SNAPTHREAD
        if (snap.rawValue.toLong() == -1L) return -1 // INVALID_HANDLE_VALUE
        try {
            // THREADENTRY32: dwSize, cntUsage, th32ThreadID, th32OwnerProcessID, tpBasePri, tpDeltaPri, dwFlags
            val entry = allocArray<UIntVar>(7)
            entry[0] = 28u
            val pid = GetCurrentProcessId()
            var n = 0
            var more = first(snap, entry)
            while (more != 0) {
                if (entry[3] == pid) n++
                entry[0] = 28u
                more = next(snap, entry)
            }
            n
        } finally {
            CloseHandle(snap)
        }
    }
