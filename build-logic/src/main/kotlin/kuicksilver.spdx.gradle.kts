// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0

// Every source file carries the two-line SPDX header; see tools/check/spdx.sh.
val checkSpdxHeaders by tasks.registering(Exec::class) {
    group = "verification"
    description = "Checks SPDX headers in all source files"
    commandLine("bash", rootProject.file("tools/check/spdx.sh").path, rootProject.projectDir.path)
}
tasks.matching { it.name == "check" }.configureEach { dependsOn(checkSpdxHeaders) }
