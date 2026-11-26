// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic

import android.util.Log

/** Logcat, tag `Kuicksilver` (SLF4J has no provider on Android unless the app adds one, so it would drop every line). */
internal actual fun platformLogger(minLevel: LogLevel): KuicksilverLogger = LogcatLogger(minLevel)

private class LogcatLogger(
    private val minLevel: LogLevel,
) : KuicksilverLogger {
    override fun isEnabled(level: LogLevel): Boolean = level >= minLevel

    override fun log(
        level: LogLevel,
        message: String,
        cause: Throwable?,
    ) {
        if (level < minLevel) return
        when (level) {
            LogLevel.Debug -> Log.d(TAG, message, cause)
            LogLevel.Info -> Log.i(TAG, message, cause)
            LogLevel.Warn -> Log.w(TAG, message, cause)
            LogLevel.Error -> Log.e(TAG, message, cause)
        }
    }

    override fun toString(): String = "KuicksilverLogger.platform($minLevel) (Logcat)"

    private companion object {
        const val TAG = "Kuicksilver"
    }
}
