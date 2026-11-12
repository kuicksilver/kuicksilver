// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(kotlinx.cinterop.ExperimentalForeignApi::class)

package io.kuicksilver.ktor.client.pac

import kotlinx.cinterop.ByteVar
import kotlinx.cinterop.CPointer
import kotlinx.cinterop.alloc
import kotlinx.cinterop.allocArray
import kotlinx.cinterop.allocArrayOf
import kotlinx.cinterop.get
import kotlinx.cinterop.memScoped
import kotlinx.cinterop.ptr
import kotlinx.cinterop.staticCFunction
import kotlinx.cinterop.toKString
import kotlinx.cinterop.value
import platform.JavaScriptCore.JSContextGetGlobalObject
import platform.JavaScriptCore.JSContextRef
import platform.JavaScriptCore.JSEvaluateScript
import platform.JavaScriptCore.JSGlobalContextCreate
import platform.JavaScriptCore.JSGlobalContextRef
import platform.JavaScriptCore.JSGlobalContextRelease
import platform.JavaScriptCore.JSObjectCallAsFunction
import platform.JavaScriptCore.JSObjectGetProperty
import platform.JavaScriptCore.JSObjectIsFunction
import platform.JavaScriptCore.JSObjectMakeFunctionWithCallback
import platform.JavaScriptCore.JSObjectRef
import platform.JavaScriptCore.JSObjectSetProperty
import platform.JavaScriptCore.JSStringCreateWithUTF8CString
import platform.JavaScriptCore.JSStringGetLength
import platform.JavaScriptCore.JSStringGetMaximumUTF8CStringSize
import platform.JavaScriptCore.JSStringGetUTF8CString
import platform.JavaScriptCore.JSStringRef
import platform.JavaScriptCore.JSStringRelease
import platform.JavaScriptCore.JSValueIsNull
import platform.JavaScriptCore.JSValueIsObject
import platform.JavaScriptCore.JSValueIsString
import platform.JavaScriptCore.JSValueIsUndefined
import platform.JavaScriptCore.JSValueMakeNull
import platform.JavaScriptCore.JSValueMakeString
import platform.JavaScriptCore.JSValueProtect
import platform.JavaScriptCore.JSValueRef
import platform.JavaScriptCore.JSValueRefVar
import platform.JavaScriptCore.JSValueToObject
import platform.JavaScriptCore.JSValueToStringCopy
import platform.JavaScriptCore.JSValueUnprotect
import platform.JavaScriptCore.kJSPropertyAttributeDontDelete
import platform.JavaScriptCore.kJSPropertyAttributeReadOnly

/** A PAC script that cannot be loaded or run: its syntax, a throw, no `FindProxyForURL`, an answer that is no string. */
internal class PacScriptException(
    message: String,
) : Exception(message)

/**
 * One PAC script in a JavaScriptCore context of its own (`JSGlobalContextCreate`): ECMAScript's built-ins, the PAC
 * utility functions ([PAC_UTILS_JS]) and four native ones ([PacHost]: `dnsResolve`, `dnsResolveEx`, `myIpAddress`,
 * `myIpAddressEx`), nothing else: no network, file, timer or module API, and nothing of the process reaches the script.
 * Not thread-safe: [PacRunner] creates, uses and releases it on its one thread.
 */
internal class PacContext(
    script: String,
) {
    private val ctx: JSGlobalContextRef = JSGlobalContextCreate(null) ?: throw PacScriptException("no JavaScript context")

    init {
        try {
            for ((name, fn) in NATIVES) define(name, fn)
            evaluate(PAC_UTILS_JS, "pac-utils.js")
            evaluate(script, "proxy.pac")
            if (function("FindProxyForURLEx") == null && function("FindProxyForURL") == null) {
                throw PacScriptException("the script defines no FindProxyForURL")
            }
        } catch (e: Throwable) {
            JSGlobalContextRelease(ctx)
            throw e
        }
    }

    /**
     * The script's answer for [url] and [host]: `FindProxyForURLEx` when the script has it (Microsoft's IPv6 extension),
     * else `FindProxyForURL`.
     */
    fun findProxy(
        url: String,
        host: String,
    ): String {
        val fn = function("FindProxyForURLEx") ?: function("FindProxyForURL") ?: throw PacScriptException("no FindProxyForURL")
        val u = stringValue(url)
        val h = stringValue(host)
        // kept from the garbage collector while the call holds them only through a C array
        JSValueProtect(ctx, u)
        JSValueProtect(ctx, h)
        try {
            return memScoped {
                val args = allocArrayOf(u, h)
                val exception = alloc<JSValueRefVar>()
                val result = JSObjectCallAsFunction(ctx, fn, null, 2u, args, exception.ptr)
                exception.value?.let { throw PacScriptException("FindProxyForURL threw: ${toText(it)}") }
                if (result == null || !JSValueIsString(ctx, result)) throw PacScriptException("FindProxyForURL returned no string")
                toText(result)
            }
        } finally {
            JSValueUnprotect(ctx, u)
            JSValueUnprotect(ctx, h)
        }
    }

    /** What `typeof` [expression] gives in the script's context (tests: the sandbox). */
    fun typeOf(expression: String): String = toText(evaluate("typeof ($expression)", "typeof.js") ?: return "undefined")

    /** Evaluates [code] and returns its value as a string (tests: the utility functions). */
    fun eval(code: String): String? =
        evaluate(code, "eval.js")?.takeUnless { JSValueIsUndefined(ctx, it) || JSValueIsNull(ctx, it) }?.let { toText(it) }

    fun close() {
        JSGlobalContextRelease(ctx)
    }

    private fun evaluate(
        code: String,
        source: String,
    ): JSValueRef? =
        memScoped {
            val s = jsString(code)
            val url = jsString(source)
            try {
                val exception = alloc<JSValueRefVar>()
                val v = JSEvaluateScript(ctx, s, null, url, 1, exception.ptr)
                exception.value?.let { throw PacScriptException("$source: ${toText(it)}") }
                v
            } finally {
                JSStringRelease(s)
                JSStringRelease(url)
            }
        }

    private fun function(name: String): JSObjectRef? {
        val global = JSContextGetGlobalObject(ctx) ?: return null
        val n = jsString(name)
        try {
            val v = JSObjectGetProperty(ctx, global, n, null) ?: return null
            if (!JSValueIsObject(ctx, v)) return null
            val o = JSValueToObject(ctx, v, null) ?: return null
            return if (JSObjectIsFunction(ctx, o)) o else null
        } finally {
            JSStringRelease(n)
        }
    }

    private fun define(
        name: String,
        fn: JSCallback,
    ) {
        val n = jsString(name)
        try {
            val f = JSObjectMakeFunctionWithCallback(ctx, n, fn)
            JSObjectSetProperty(
                ctx,
                JSContextGetGlobalObject(ctx),
                n,
                f,
                kJSPropertyAttributeReadOnly or kJSPropertyAttributeDontDelete,
                null,
            )
        } finally {
            JSStringRelease(n)
        }
    }

    private fun stringValue(s: String): JSValueRef? = jsValue(ctx, s)

    private fun toText(v: JSValueRef): String = jsText(ctx, v)
}

private typealias JSCallback = platform.JavaScriptCore.JSObjectCallAsFunctionCallback

private fun jsString(s: String): JSStringRef = JSStringCreateWithUTF8CString(s) ?: throw PacScriptException("string")

private fun jsValue(
    ctx: JSContextRef?,
    s: String,
): JSValueRef? {
    val js = jsString(s)
    try {
        return JSValueMakeString(ctx, js)
    } finally {
        JSStringRelease(js)
    }
}

private fun jsText(
    ctx: JSContextRef?,
    v: JSValueRef?,
): String {
    val js = JSValueToStringCopy(ctx, v, null) ?: return ""
    try {
        val size = JSStringGetMaximumUTF8CStringSize(js)
        return memScoped {
            val buf = allocArray<ByteVar>(size.toLong())
            JSStringGetUTF8CString(js, buf, size)
            buf.toKString()
        }
    } finally {
        JSStringRelease(js)
    }
}

/** The longest argument a native function takes (a host name has at most 253 characters). */
private const val MAX_NATIVE_ARGUMENT = 1024

/** The first argument as a string, or null without one or when it is longer than [MAX_NATIVE_ARGUMENT]. */
private fun firstArgument(
    ctx: JSContextRef?,
    count: ULong,
    args: CPointer<JSValueRefVar>?,
): String? {
    if (count == 0uL || args == null) return null
    val js = JSValueToStringCopy(ctx, args[0], null) ?: return null
    try {
        if (JSStringGetLength(js) > MAX_NATIVE_ARGUMENT.toULong()) return null
    } finally {
        JSStringRelease(js)
    }
    return jsText(ctx, args[0])
}

private fun answer(
    ctx: JSContextRef?,
    s: String?,
): JSValueRef? = if (s == null) JSValueMakeNull(ctx) else jsValue(ctx, s)

private val NATIVES: List<Pair<String, JSCallback>> =
    listOf(
        "dnsResolve" to
            staticCFunction {
                ctx: JSContextRef?,
                _: JSObjectRef?,
                _: JSObjectRef?,
                n: ULong,
                a: CPointer<JSValueRefVar>?,
                _: CPointer<JSValueRefVar>?,
                ->
                answer(ctx, firstArgument(ctx, n, a)?.let { PacDns.resolve(it, ipv4Only = true).firstOrNull() })
            },
        "dnsResolveEx" to
            staticCFunction {
                ctx: JSContextRef?,
                _: JSObjectRef?,
                _: JSObjectRef?,
                n: ULong,
                a: CPointer<JSValueRefVar>?,
                _: CPointer<JSValueRefVar>?,
                ->
                answer(ctx, firstArgument(ctx, n, a)?.let { PacDns.resolve(it, ipv4Only = false).joinToString(";") } ?: "")
            },
        "myIpAddress" to
            staticCFunction {
                ctx: JSContextRef?,
                _: JSObjectRef?,
                _: JSObjectRef?,
                _: ULong,
                _: CPointer<JSValueRefVar>?,
                _: CPointer<JSValueRefVar>?,
                ->
                answer(ctx, PacHost.current.myAddresses(ipv4Only = true).firstOrNull() ?: "127.0.0.1")
            },
        "myIpAddressEx" to
            staticCFunction {
                ctx: JSContextRef?,
                _: JSObjectRef?,
                _: JSObjectRef?,
                _: ULong,
                _: CPointer<JSValueRefVar>?,
                _: CPointer<JSValueRefVar>?,
                ->
                answer(ctx, PacHost.current.myAddresses(ipv4Only = false).joinToString(";"))
            },
    )
