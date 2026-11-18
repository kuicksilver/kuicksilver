#!/usr/bin/env bash
# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
# Download OpenSSL source, verify the PGP signature and SHA-256 from the pin profile, unpack; the same for the compression
# libraries of gradle/compression-libs.toml that build.sh links into libcrypto (RFC 8879 certificate compression): zlib
# (PGP signature by the pinned fingerprint and SHA-256) and brotli (SHA-256 and the tag commit; brotli signs no release).
# Usage: fetch.sh   (pin from gradle/openssl.toml, or the profile KSL_OPENSSL_PIN names)
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
root="$here/../.."; out="${KSL_OPENSSL_WORK:-$root/build/openssl-work}"
src="$out/src"
mkdir -p "$src"

# KSL_OPENSSL_PIN: another pin profile, a path from the repository root (gradle/openssl-next.toml: the CI job openssl-next)
pin="${KSL_OPENSSL_PIN:-gradle/openssl.toml}"; case "$pin" in /*) toml="$pin" ;; *) toml="$root/$pin" ;; esac
[ -f "$toml" ] || { echo "no pin profile $toml" >&2; exit 1; }
version=$(sed -n 's/^version = "\(.*\)"/\1/p' "$toml")
sha256=$(sed -n 's/^sha256 = "\(.*\)"/\1/p' "$toml")
fpr=$(sed -n 's/^pgp_fingerprint = "\(.*\)"/\1/p' "$toml")
tarball="openssl-$version.tar.gz"
base="https://github.com/openssl/openssl/releases/download/openssl-$version"

cd "$src"
# bounded: a stalled mirror fails the build instead of hanging it; a partial download never stays as the tarball
dl() { if curl -sfL --retry 3 --connect-timeout 20 --max-time 600 -o "$1.part" "$2"; then mv "$1.part" "$1"; else rm -f "$1.part"; return 1; fi; }
[ -f "$tarball" ] || dl "$tarball" "$base/$tarball"
[ -f "$tarball.asc" ] || dl "$tarball.asc" "$base/$tarball.asc"

# A keyring of this run only (KSL_GNUPGHOME names another): a shared one could hold keys another run imported.
# Short path: macOS limits Unix socket paths to 104 bytes.
if [ -n "${KSL_GNUPGHOME:-}" ]; then export GNUPGHOME="$KSL_GNUPGHOME"; mkdir -p "$GNUPGHOME"
else export GNUPGHOME; GNUPGHOME=$(mktemp -d /tmp/ksl-ossl.XXXXXX); trap 'gpgconf --kill all >/dev/null 2>&1 || true; rm -rf "$GNUPGHOME"' EXIT; fi
chmod 700 "$GNUPGHOME"
with_timeout() { # <seconds> <command...>: the command, killed after <seconds>
  local s="$1"; shift; "$@" & local p=$!
  ( sleep "$s"; kill "$p" 2>/dev/null ) & local w=$!
  wait "$p"; local rc=$?; kill "$w" 2>/dev/null || true; wait "$w" 2>/dev/null || true; return $rc
}
# The release key is vendored (fingerprint pinned in openssl.toml); keyservers are only a fallback, 60 s each.
gpg --batch --import "$here/openssl-release-key.asc" >/dev/null 2>&1 || true
if ! gpg --batch --list-keys "$fpr" >/dev/null 2>&1; then
  with_timeout 60 gpg --batch --keyserver hkps://keys.openpgp.org --recv-keys "$fpr" \
    || with_timeout 60 gpg --batch --keyserver hkps://keyserver.ubuntu.com --recv-keys "$fpr" || true
fi
# Signature must be made by exactly the pinned fingerprint, not merely "some key in the ring".
# VALIDSIG's last field is the primary key fingerprint (the signing subkey comes first).
# The status lines are read whole first: piped into `grep -q`, gpg could die of SIGPIPE writing the lines after VALIDSIG and
# pipefail would turn a good signature into a refusal.
status=$(gpg --batch --status-fd 1 --verify "$tarball.asc" "$tarball" 2>/dev/null || true)
grep -Eq "VALIDSIG .* $fpr\$" <<< "$status" \
  || { echo "FAILED: PGP signature is not from $fpr" >&2; exit 1; }

# sha256sum (coreutils, the Linux build images) or shasum (macOS); the Docker steps run this script in a Linux image without perl
if command -v sha256sum >/dev/null 2>&1; then sum=(sha256sum -c -); else sum=(shasum -a 256 -c -); fi
echo "$sha256  $tarball" | "${sum[@]}" || { echo "FAILED: sha256 mismatch" >&2; exit 1; }

# The compression libraries (gradle/compression-libs.toml, the same for every OpenSSL pin profile)
ctoml="$root/gradle/compression-libs.toml"
tv() { # <table> <key>: the string value of key in [table]
  awk -v t="[$1]" -v k="$2" '$0 == t { f = 1; next } /^\[/ { f = 0 } f && $1 == k && $2 == "=" { v = $0; sub(/^[^"]*"/, "", v); sub(/".*$/, "", v); print v; exit }' "$ctoml"
}
zv=$(tv zlib version); zsha=$(tv zlib sha256); zfpr=$(tv zlib pgp_fingerprint); zurl=$(tv zlib url)
bv=$(tv brotli version); bsha=$(tv brotli sha256); bcommit=$(tv brotli commit); burl=$(tv brotli url)
for v in zv zsha zfpr zurl bv bsha bcommit burl; do [ -n "${!v}" ] || { echo "FAILED: $v missing in $ctoml" >&2; exit 1; }; done
[ -f "zlib-$zv.tar.gz" ] || dl "zlib-$zv.tar.gz" "$zurl"
[ -f "zlib-$zv.tar.gz.asc" ] || dl "zlib-$zv.tar.gz.asc" "$zurl.asc"
[ -f "brotli-$bv.tar.gz" ] || dl "brotli-$bv.tar.gz" "$burl"
gpg --batch --import "$here/zlib-release-key.asc" >/dev/null 2>&1 || true
zstatus=$(gpg --batch --status-fd 1 --verify "zlib-$zv.tar.gz.asc" "zlib-$zv.tar.gz" 2>/dev/null || true)
grep -Eq "VALIDSIG .* $zfpr\$" <<< "$zstatus" || { echo "FAILED: PGP signature of zlib-$zv.tar.gz is not from $zfpr" >&2; exit 1; }
echo "$zsha  zlib-$zv.tar.gz" | "${sum[@]}" || { echo "FAILED: sha256 mismatch (zlib)" >&2; exit 1; }
echo "$bsha  brotli-$bv.tar.gz" | "${sum[@]}" || { echo "FAILED: sha256 mismatch (brotli)" >&2; exit 1; }
# git archive records the commit it archived as the pax global header's comment: the tag must still name the pinned commit
# (pipefail off for it: head closes the pipe early, and gzip's SIGPIPE is not a failure)
bpax=$(set +o pipefail; gzip -dc "brotli-$bv.tar.gz" | head -c 1024 | tr '\0' '\n' | sed -n 's/^[0-9]* comment=\([0-9a-f]\{40\}\)$/\1/p' | head -1)
[ "$bpax" = "$bcommit" ] || { echo "FAILED: brotli-$bv.tar.gz archives commit '${bpax:-none}', $bcommit is pinned" >&2; exit 1; }
unpack() { # <dir> <tarball> <sha256>: unpacked once per verified tarball (marker as for OpenSSL below)
  if [ "$(cat "$1/.ksl-unpacked-sha256" 2>/dev/null || true)" != "$3" ]; then rm -rf "$1"; tar xzf "$2"; echo "$3" > "$1/.ksl-unpacked-sha256"; fi
}
unpack "zlib-$zv" "zlib-$zv.tar.gz" "$zsha"; unpack "brotli-$bv" "brotli-$bv.tar.gz" "$bsha"
echo "OK: zlib-$zv (pgp $zfpr, sha256 $zsha) and brotli-$bv (sha256 $bsha, commit $bcommit) verified"

# Unpacked once per verified tarball: the marker names the sha256 the tree came from, so a later run (the Docker JVM steps
# run this script again inside an image whose tar cannot write into the bind-mounted checkout) leaves the tree alone.
marker="openssl-$version/.ksl-unpacked-sha256"
if [ "$(cat "$marker" 2>/dev/null || true)" != "$sha256" ]; then
  rm -rf "openssl-$version"
  tar xzf "$tarball"
  echo "$sha256" > "$marker"
fi
echo "OK: $src/openssl-$version verified (pgp $fpr, sha256 $sha256)"
