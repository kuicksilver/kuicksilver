// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic

import org.slf4j.Logger
import org.slf4j.LoggerFactory
import org.slf4j.helpers.NOPLogger

/**
 * SLF4J, the logging API Ktor itself logs through (`io.kuicksilver` is the logger's name). Without an SLF4J provider on the
 * classpath, SLF4J would drop every line: the warnings go to standard error then, as before 0.3.0.
 */
internal actual fun platformLogger(minLevel: LogLevel): KuicksilverLogger {
    val logger = LoggerFactory.getLogger("io.kuicksilver")
    return if (logger is NOPLogger) KuicksilverLogger.stderr(minLevel) else Slf4jLogger(logger, minLevel)
}

private class Slf4jLogger(
    private val logger: Logger,
    private val minLevel: LogLevel,
) : KuicksilverLogger {
    override fun isEnabled(level: LogLevel): Boolean =
        level >= minLevel &&
            when (level) {
                LogLevel.Debug -> logger.isDebugEnabled
                LogLevel.Info -> logger.isInfoEnabled
                LogLevel.Warn -> logger.isWarnEnabled
                LogLevel.Error -> logger.isErrorEnabled
            }

    override fun log(
        level: LogLevel,
        message: String,
        cause: Throwable?,
    ) {
        if (level < minLevel) return
        when (level) {
            LogLevel.Debug -> logger.debug(message, cause)
            LogLevel.Info -> logger.info(message, cause)
            LogLevel.Warn -> logger.warn(message, cause)
            LogLevel.Error -> logger.error(message, cause)
        }
    }

    override fun toString(): String = "KuicksilverLogger.platform($minLevel) (SLF4J)"
}
