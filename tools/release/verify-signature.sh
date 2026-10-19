#!/usr/bin/env bash
# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
# Exit 0 only if each <file> has a <file>.asc made by the Kuicksilver release key (docs/release.md, "Supply chain"): the
# public key comes from gradle/verification-keyring.keys (the one Gradle's dependency verification trusts for io.kuicksilver),
# the signature must be valid and from exactly that primary fingerprint. Consumers can run it on the GitHub release files.
# Usage: verify-signature.sh <file>...
set -euo pipefail
root="$(cd "$(dirname "$0")/../.." && pwd)"
fpr=22C1F2E4FCE94B28EB2C7DB0492ABD95C8D0EC68
[ $# -gt 0 ] || { echo "usage: $0 <file>..." >&2; exit 2; }
home=$(mktemp -d /tmp/ksl-gpg.XXXXXX); trap 'gpgconf --homedir "$home" --kill all >/dev/null 2>&1 || true; rm -rf "$home"' EXIT
chmod 700 "$home"
# the armored block that follows "pub    <long id>" in the keyring Gradle writes
awk -v id="${fpr: -16}" '/^pub /{take=($2==id)} take' "$root/gradle/verification-keyring.keys" \
  | sed -n '/-----BEGIN PGP PUBLIC KEY BLOCK-----/,/-----END PGP PUBLIC KEY BLOCK-----/p' > "$home/release.asc"
[ -s "$home/release.asc" ] || { echo "FAIL: release key ${fpr: -16} not in gradle/verification-keyring.keys"; exit 2; }
gpg --homedir "$home" --batch --quiet --import "$home/release.asc" 2>/dev/null
rc=0
for f in "$@"; do
  if [ ! -f "$f.asc" ]; then echo "FAIL: $f.asc missing"; rc=1; continue; fi
  if gpg --homedir "$home" --batch --status-fd 1 --verify "$f.asc" "$f" 2>/dev/null | grep -Eq "^\[GNUPG:\] VALIDSIG .* $fpr\$"; then
    echo "OK: $(basename "$f").asc by $fpr"
  else
    echo "FAIL: $(basename "$f").asc is not a valid signature by $fpr"; rc=1
  fi
done
exit $rc
