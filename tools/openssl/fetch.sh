#!/usr/bin/env bash
# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
# Download OpenSSL source, verify the PGP signature and SHA-256 from openssl.lock, unpack.
# Usage: fetch.sh   (pin from gradle/openssl.toml)
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
root="$here/../.."; out="${KSL_OPENSSL_WORK:-$root/build/openssl-work}"
src="$out/src"
mkdir -p "$src"

toml="$root/gradle/openssl.toml"
version=$(sed -n 's/^version = "\(.*\)"/\1/p' "$toml")
sha256=$(sed -n 's/^sha256 = "\(.*\)"/\1/p' "$toml")
fpr=$(sed -n 's/^pgp_fingerprint = "\(.*\)"/\1/p' "$toml")
tarball="openssl-$version.tar.gz"
base="https://github.com/openssl/openssl/releases/download/openssl-$version"

cd "$src"
[ -f "$tarball" ] || curl -sfL -o "$tarball" "$base/$tarball"
[ -f "$tarball.asc" ] || curl -sfL -o "$tarball.asc" "$base/$tarball.asc"

export GNUPGHOME="${KSL_GNUPGHOME:-/tmp/kuicksilver-gnupg}"   # short path: macOS limits Unix socket paths to 104 bytes
mkdir -p "$GNUPGHOME"; chmod 700 "$GNUPGHOME"
# The release key is vendored (fingerprint pinned in openssl.toml); keyservers are only a fallback.
gpg --batch --import "$here/openssl-release-key.asc" >/dev/null 2>&1 || true
if ! gpg --batch --list-keys "$fpr" >/dev/null 2>&1; then
  gpg --batch --keyserver hkps://keys.openpgp.org --recv-keys "$fpr" \
    || gpg --batch --keyserver hkps://keyserver.ubuntu.com --recv-keys "$fpr"
fi
# Signature must be made by exactly the pinned fingerprint, not merely "some key in the ring".
# VALIDSIG's last field is the primary key fingerprint (the signing subkey comes first).
gpg --batch --status-fd 1 --verify "$tarball.asc" "$tarball" 2>/dev/null | grep -Eq "VALIDSIG .* $fpr\$" \
  || { echo "FAILED: PGP signature is not from $fpr" >&2; exit 1; }

echo "$sha256  $tarball" | shasum -a 256 -c - || { echo "FAILED: sha256 mismatch" >&2; exit 1; }

rm -rf "openssl-$version"
tar xzf "$tarball"
echo "OK: $src/openssl-$version verified (pgp $fpr, sha256 $sha256)"
