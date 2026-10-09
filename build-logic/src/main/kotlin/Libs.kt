// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0

import org.gradle.api.Project
import org.gradle.api.artifacts.VersionCatalog
import org.gradle.api.artifacts.VersionCatalogsExtension
import org.gradle.kotlin.dsl.getByType

/** Version catalog accessor for precompiled script plugins. */
val Project.catalog: VersionCatalog get() = extensions.getByType<VersionCatalogsExtension>().named("libs")
