#!/usr/bin/env bash
# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
# SPDX header check: every source file must carry the two-line header within its first 5 lines.
# Scope: Kotlin, Gradle scripts, C, shell, Python, cinterop .def, TOML, YAML, Dockerfiles (review M7). JSON is excluded on purpose:
# it has no comment syntax (tools/interop/required.json, renovate.json); its licence is the repository's (LICENSE, REUSE-style).
set -uo pipefail
root="${1:-.}"; rc=0
while IFS= read -r f; do
  head -5 "$f" | grep -q 'Copyright 2026 The Kuicksilver Authors' && head -5 "$f" | grep -q 'SPDX-License-Identifier: Apache-2.0' || { echo "missing SPDX header: $f"; rc=1; }
done < <(find "$root" \( -path '*/build' -o -path '*/.gradle' -o -path '*/.git' -o -path '*/spikes' -o -path '*/.superpowers' -o -path '*/.kotlin' -o -path '*/.worktrees' -o -path '*/.idea' -o -path '*/.claude' \) -prune -o -type f \
  \( -name '*.kt' -o -name '*.kts' -o -name '*.c' -o -name '*.h' -o -name '*.sh' -o -name '*.py' -o -name '*.def' \
     -o -name '*.toml' -o -name '*.yml' -o -name '*.yaml' -o -name 'Dockerfile' -o -name 'Dockerfile.*' -o -name '*.Dockerfile' \) ! -name gradlew -print)
exit $rc
