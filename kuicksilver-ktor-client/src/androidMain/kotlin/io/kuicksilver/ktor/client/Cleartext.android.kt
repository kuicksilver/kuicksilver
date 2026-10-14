// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.client

import android.security.NetworkSecurityPolicy

// API 24 (minSdk): the per-host check honours <domain-config cleartextTrafficPermitted> as well as the base config
internal actual fun platformCleartextPermitted(host: String): Boolean =
    NetworkSecurityPolicy.getInstance().isCleartextTrafficPermitted(host)
