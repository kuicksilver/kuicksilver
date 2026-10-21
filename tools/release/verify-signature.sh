#!/usr/bin/env bash
# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
# Exit 0 only if each <file> has a <file>.asc made by the Kuicksilver release key (docs/release.md, "Supply chain"). The
# public key is tools/release/kuicksilver-release-key.asc (the key gradle/verification-metadata.xml trusts for
# io.kuicksilver); its import must succeed with exactly the pinned fingerprint, and each signature must be good (GOODSIG)
# and valid (VALIDSIG) for that primary fingerprint. Consumers can run it on the GitHub release files.
# Usage: verify-signature.sh <file>...
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
fpr=22C1F2E4FCE94B28EB2C7DB0492ABD95C8D0EC68
key="$here/kuicksilver-release-key.asc"
[ $# -gt 0 ] || { echo "usage: $0 <file>..." >&2; exit 2; }
home=$(mktemp -d /tmp/ksl-gpg.XXXXXX)   # short path: macOS limits gpg-agent socket paths
trap 'gpgconf --homedir "$home" --kill all >/dev/null 2>&1 || true; rm -rf "$home"' EXIT
chmod 700 "$home"
imported=$(gpg --homedir "$home" --batch --status-fd 1 --import "$key" 2>/dev/null | sed -n 's/^\[GNUPG:\] IMPORT_OK [0-9]* \([0-9A-F]*\)$/\1/p')
[ "$imported" = "$fpr" ] || { echo "FAIL: importing $key gave '${imported:-nothing}', not $fpr"; exit 2; }
rc=0
for f in "$@"; do
  if [ ! -f "$f.asc" ]; then echo "FAIL: $f.asc missing"; rc=1; continue; fi
  st=$(gpg --homedir "$home" --batch --status-fd 1 --verify "$f.asc" "$f" 2>/dev/null || true)
  if grep -q '^\[GNUPG:\] GOODSIG ' <<< "$st" && grep -Eq "^\[GNUPG:\] VALIDSIG .* $fpr\$" <<< "$st"; then
    echo "OK: $(basename "$f").asc by $fpr"
  else
    echo "FAIL: $(basename "$f").asc is not a good signature by $fpr"; rc=1
  fi
done
exit $rc
