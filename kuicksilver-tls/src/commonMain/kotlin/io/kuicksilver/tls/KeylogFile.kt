// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.tls

import io.kuicksilver.annotations.DelicateKuicksilverApi

/**
 * A [KeylogSink] appending RFC 9850 lines to [path]; the file is created with mode 0600 (docs/guide/tls.md, Key logging).
 * The path is checked here, before any secret exists: a symlink, a file that is not a regular file, has more than one hard
 * link or belongs to another user, or a file system without POSIX permissions throws [IllegalArgumentException]; an existing file readable by the
 * group or others is tightened to 0600 (Windows only creates the file). On the JVM the file is opened once, here, and every
 * line goes through that descriptor, so a file removed and recreated at the path later receives nothing; the JVM sink is
 * also `java.io.Closeable` and keeps the descriptor until it is closed (or collected, or the process exits). Kotlin/Native
 * reopens the file for every line without following links and repeats the checks on the new descriptor.
 * A line that cannot be written is dropped, not retried. The library never consults `SSLKEYLOGFILE` on its own;
 * [keylogFromEnvironment] reads it when the application calls it.
 */
@DelicateKuicksilverApi
public expect fun keylogFile(path: String): KeylogSink

/**
 * A [keylogFile] sink for the path in `SSLKEYLOGFILE`, read when this is called; null when the variable is unset or blank.
 * Only for explicit, deliberate use in debug builds. Throws as [keylogFile] for a path it refuses.
 */
@DelicateKuicksilverApi
public expect fun keylogFromEnvironment(): KeylogSink?
