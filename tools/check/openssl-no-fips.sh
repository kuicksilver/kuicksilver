#!/usr/bin/env bash
# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
# Exit 0 only if the OpenSSL build of <target> has no FIPS provider (docs/stability.md, "FIPS"): the configure flags do not
# say enable-fips, OpenSSL's own configdata.pm lists "fips" among the disabled features (its default; no-module also rules out
# any loadable provider), and no FIPS module or its config file was produced. Kuicksilver is not FIPS-certified either way.
# Usage: openssl-no-fips.sh <target>   (build/openssl/<target> and $KSL_OPENSSL_WORK/build/<target>, as tools/openssl/build.sh)
set -uo pipefail
root="$(cd "$(dirname "$0")/../.." && pwd)"
t="${1:?target}"; out="$root/build/openssl/$t"; work="${KSL_OPENSSL_WORK:-$root/build/openssl-work}/build/$t"
[ -d "$out" ] || { echo "FAIL: $out missing (tools/openssl/build.sh $t)"; exit 2; }
for f in "$root/tools/openssl/configure-flags.txt" "$out/configure-flags.txt" "$out/configure-target.txt"; do
  [ -f "$f" ] || continue
  grep -qw 'enable-fips' "$f" && { echo "FAIL: $f asks for enable-fips"; exit 1; }
done
echo "OK: no enable-fips in the configure flags"
if [ -f "$work/configdata.pm" ]; then
  # read, not run: the Docker builds' configdata.pm names the container's paths
  dis=$(awk '/^our %disabled = \(/{f=1;next} f&&/^\);/{exit} f' "$work/configdata.pm")
  fips=$(printf '%s\n' "$dis" | sed -n 's/^ *"fips" => "\(.*\)",$/\1/p'); module=$(printf '%s\n' "$dis" | sed -n 's/^ *"module" => "\(.*\)",$/\1/p')
  [ -n "$fips" ] || { echo "FAIL: configdata.pm does not list fips as disabled ($work/configdata.pm)"; exit 1; }
  echo "OK: configdata.pm: fips disabled ($fips), module disabled (${module:-NO})"
else
  echo "note: no $work/configdata.pm (a build taken from the cache); the flags above decide"
fi
# the provider a FIPS build makes (providers/fips.so|.dylib|.dll) and the config `make install_fips` writes
found=$(find "$out" "$work/providers" \( -name 'fips.so' -o -name 'fips.dylib' -o -name 'fips.dll' -o -name 'fipsmodule.cnf' \) 2>/dev/null | head -3)
[ -z "$found" ] || { echo "FAIL: a FIPS module was built: $found"; exit 1; }
echo "OK: no FIPS module (providers/fips.*) or fipsmodule.cnf"
