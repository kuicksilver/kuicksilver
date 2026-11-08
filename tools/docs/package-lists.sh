#!/usr/bin/env bash
# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
# Refreshes the package-lists of the external API references the API reference links to (docs/api/package-lists/): the
# Kotlin standard library, the JDK (17, the JVM API level of the published jars), Android and AndroidX (Dokka's default
# links, kuicksilver.kmp.gradle.kts), kotlinx-coroutines, kotlinx-io and Ktor. They are kept in the repository so the
# Dokka build reads no URL at build time: an offline build keeps every external link, and Dokka's own download of the
# Ktor list timed out. Run it after a Kotlin, coroutines, kotlinx-io or Ktor bump and review the diff.
#   Usage: bash tools/docs/package-lists.sh
set -euo pipefail
cd "$(dirname "$0")/../.."
dir=docs/api/package-lists
fetch() {
  local file="$1" url="$2" tmp
  tmp="$(mktemp)"
  curl -fsSL --retry 3 -o "$tmp" "$url"
  # a Dokka package-list starts with $dokka.format, a javadoc element-list with module:; AndroidX's lists bare packages
  head -1 "$tmp" | grep -Eq '^(\$dokka\.format:|module:|[a-z][a-z0-9_]*(\.[a-z0-9_]+)+$)' \
    || { echo "package-lists.sh: $url is not a package-list" >&2; rm -f "$tmp"; exit 1; }
  mv "$tmp" "$dir/$file"
  echo "$dir/$file: $(grep -Evc '^\$dokka\.|^module:' "$dir/$file") packages"
}
fetch kotlinStdlib.package-list https://kotlinlang.org/api/core/package-list
fetch jdk.element-list https://docs.oracle.com/en/java/javase/17/docs/api/element-list
fetch androidSdk.package-list https://developer.android.com/reference/kotlin/package-list
fetch androidX.package-list https://developer.android.com/reference/kotlin/androidx/package-list
fetch kotlinx-coroutines.package-list https://kotlinlang.org/api/kotlinx.coroutines/package-list
fetch kotlinx-io.package-list https://kotlinlang.org/api/kotlinx-io/package-list
fetch ktor.package-list https://api.ktor.io/package-list
