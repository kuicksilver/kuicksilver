// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.client

import io.kuicksilver.ktor.client.dns.SvcbRecord
import kotlin.time.Duration

// the system resolver is not asked yet on this platform: every lookup counts as failed (HttpsRecordSource.System)
internal actual suspend fun platformHttpsQuery(
    name: String,
    timeout: Duration,
): List<SvcbRecord>? = null
