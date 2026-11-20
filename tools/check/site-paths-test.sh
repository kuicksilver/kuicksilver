#!/usr/bin/env bash
# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
# Negative controls of tools/check/site-paths.sh on a fixture tree: clean sources pass; a temporary or home directory in
# the guide, in llms-full.txt or in docs/process.md fails; a published source that is missing is a usage error.
# Usage: site-paths-test.sh
set -uo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
rc=0
fixture() { # <dir>: a clean tree with every published source
  mkdir -p "$1/docs/guide" "$1/docs/benchmarks" "$1/docs/spec"
  printf '# TLS\n\n```kotlin\nval path = "keys/kuicksilver-keys.txt"\n```\n' > "$1/docs/guide/tls.md"
  printf 'results\n' > "$1/docs/benchmarks/results.md"; printf '| RFC |\n' > "$1/docs/spec/rfc-compliance.md"
  printf '# Process\n' > "$1/docs/process.md"; printf '# llms\n' > "$1/llms.txt"; printf 'all docs\n' > "$1/llms-full.txt"
}
expect() { # <exit> <what> <root>
  bash "$here/site-paths.sh" "$3" > "$tmp/out.txt" 2>&1; local got=$?
  if [ "$got" = "$1" ]; then echo "ok: $2"; else echo "FAIL: $2 (exit $got, want $1)"; sed 's/^/  | /' "$tmp/out.txt"; rc=1; fi
}
fixture "$tmp/clean"; expect 0 "clean published sources pass" "$tmp/clean"
fixture "$tmp/g"; printf 'val path = "/tmp/kuicksilver-keys.txt"\n' >> "$tmp/g/docs/guide/tls.md"
expect 1 "negative: /tmp/ in a guide sample" "$tmp/g"
fixture "$tmp/l"; printf 'see /Users/someone/kuicksilver/README.md\n' >> "$tmp/l/llms-full.txt"
expect 1 "negative: a home directory in llms-full.txt" "$tmp/l"
fixture "$tmp/p"; printf 'logs in /private/var/folders/xy/T/gate\n' >> "$tmp/p/docs/process.md"
expect 1 "negative: a macOS temporary directory in docs/process.md" "$tmp/p"
fixture "$tmp/m"; rm "$tmp/m/llms-full.txt"; expect 2 "negative: a missing published source" "$tmp/m"
[ "$rc" = 0 ] && echo "all passed"
exit "$rc"
