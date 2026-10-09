// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.tls

import io.kuicksilver.annotations.DelicateKuicksilverApi

/**
 * A [KeylogSink] appending RFC 9850 lines to [path]; the file is created with mode 0600 (docs/guide/tls.md, Key logging).
 * `SSLKEYLOGFILE` is never consulted by the library; [keylogFromEnvironment] reads it explicitly when you ask.
 */
@DelicateKuicksilverApi
public expect fun keylogFile(path: String): KeylogSink

/** The value of `SSLKEYLOGFILE` in this process, or null. Only for explicit, deliberate use in debug builds. */
@DelicateKuicksilverApi
public expect fun keylogFromEnvironment(): KeylogSink?
