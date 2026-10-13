#!/bin/sh
# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
# Xcode Run Script phase: builds the Kotlin framework slice Xcode is building for (SDK, architecture, configuration come
# from Xcode's environment) and puts it where FRAMEWORK_SEARCH_PATHS looks. KUICKSILVER_GRADLE overrides the Gradle command.
set -e
if [ "YES" = "$OVERRIDE_KOTLIN_BUILD_IDE_SUPPORTED" ]; then
  echo "Skipping the Gradle build: the IDE already built the Kotlin framework (OVERRIDE_KOTLIN_BUILD_IDE_SUPPORTED=YES)"
  exit 0
fi
cd "$SRCROOT/../.."
# shellcheck disable=SC2086 # KUICKSILVER_GRADLE is a command with arguments
${KUICKSILVER_GRADLE:-./gradlew --max-workers=2} -p samples/ios :shared:embedAndSignAppleFrameworkForXcode
