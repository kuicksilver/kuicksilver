#!/usr/bin/env bash
# SPDX header check: every source file must carry the two-line header within its first 5 lines.
# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
set -uo pipefail
root="${1:-.}"; rc=0
while IFS= read -r f; do
  head -5 "$f" | grep -q 'Copyright 2026 The Kuicksilver Authors' && head -5 "$f" | grep -q 'SPDX-License-Identifier: Apache-2.0' || { echo "missing SPDX header: $f"; rc=1; }
done < <(find "$root" \( -path '*/build' -o -path '*/.gradle' -o -path '*/.git' -o -path '*/spikes' -o -path '*/.superpowers' -o -path '*/.kotlin' -o -path '*/.worktrees' -o -path '*/.claude' \) -prune -o -type f \( -name '*.kt' -o -name '*.kts' -o -name '*.c' -o -name '*.h' -o -name '*.sh' -o -name '*.py' -o -name '*.def' -o -name '*.toml' -o -name '*.yml' -o -name '*.yaml' -o -name '*.Dockerfile' -o -name 'Dockerfile' \) ! -name gradlew -print)
exit $rc
