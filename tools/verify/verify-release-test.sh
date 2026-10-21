#!/usr/bin/env bash
# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
# Negative controls of tools/verify/verify-release.sh on fixtures, without network: a Maven repository of a made-up
# version 9.9.9 (a jar, an AAR and a cinterop klib carrying stand-in native libraries, a BOM), its GitHub release files
# (an in-toto statement whose subjects are those files, an SBOM zip) and a directory of "rebuilt" libraries (--rebuilt),
# all signed with a throwaway key handed to the script through KSL_VERIFY_KEY/KSL_VERIFY_FPR. Each case copies the
# fixture, breaks one thing and expects an exit code and the lines the report must (and must not) contain. curl is a stub
# that fails, so no case reaches the network. Usage: verify-release-test.sh
set -uo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
script="$here/verify-release.sh"
tmp=$(mktemp -d /tmp/ksl-vrt.XXXXXX)   # short path: macOS limits gpg-agent socket paths
trap 'for h in "$tmp"/gpg-*; do gpgconf --homedir "$h" --kill all >/dev/null 2>&1 || true; done; rm -rf "$tmp"' EXIT
mkdir -p "$tmp/bin"; printf '#!/bin/sh\necho "curl called in a test: $*" >&2; exit 7\n' > "$tmp/bin/curl"; chmod +x "$tmp/bin/curl"
export PATH="$tmp/bin:$PATH"
sha256() { (sha256sum "$1" 2>/dev/null || shasum -a 256 "$1") | cut -d' ' -f1; }
sha1() { (sha1sum "$1" 2>/dev/null || shasum -a 1 "$1") | cut -d' ' -f1; }

key() { # <name>: a throwaway signing key in $tmp/gpg-<name>; prints its fingerprint
  local h="$tmp/gpg-$1"; mkdir -p "$h"; chmod 700 "$h"
  gpg --homedir "$h" --batch --pinentry-mode loopback --passphrase '' --quick-gen-key "$1 <$1@example.invalid>" ed25519 sign never >/dev/null 2>&1
  gpg --homedir "$h" --batch --with-colons --list-keys 2>/dev/null | awk -F: '$1 == "fpr" {print $10; exit}'
}
sign() { # <key name> <file>: <file>.asc
  rm -f "$2.asc"; gpg --homedir "$tmp/gpg-$1" --batch --pinentry-mode loopback --passphrase '' --armor --detach-sign -o "$2.asc" "$2"
}
fpr=$(key test); other=$(key other)
[ -n "$fpr" ] && [ -n "$other" ] || { echo "FAIL: could not make the test keys"; exit 2; }
gpg --homedir "$tmp/gpg-test" --batch --armor --export "$fpr" > "$tmp/test-key.asc"

# the fixture: stand-in libraries, the three archives that carry them, the BOM, the GitHub files, the rebuilt copies
v=9.9.9; fx="$tmp/fixture"; m="$fx/io/kuicksilver"; rb="$tmp/rebuilt"
mkdir -p "$tmp/x/META-INF/native" "$tmp/x/jni/arm64-v8a" "$tmp/x/default/targets/macos_arm64/included" "$fx/github" \
  "$rb/jni/osx-aarch_64" "$rb/android/arm64-v8a" "$rb/klib/macos_arm64"
printf 'dylib for osx-aarch_64\n' > "$rb/jni/osx-aarch_64/libksl_6_osx_aarch_64.dylib"
printf 'so for arm64-v8a\n' > "$rb/android/arm64-v8a/libksl.so"
for a in libksl.a libssl.a libcrypto.a; do printf 'archive %s\n' "$a" > "$rb/klib/macos_arm64/$a"; done
cp "$rb/jni/osx-aarch_64/libksl_6_osx_aarch_64.dylib" "$tmp/x/META-INF/native/"
cp "$rb/android/arm64-v8a/libksl.so" "$tmp/x/jni/arm64-v8a/"
cp "$rb/klib/macos_arm64"/*.a "$tmp/x/default/targets/macos_arm64/included/"
mk() { mkdir -p "$m/$1/$v"; printf '%s' "$m/$1/$v/$1-$v$2"; }
(cd "$tmp/x" && zip -qr "$(mk kuicksilver-native-jvm .jar)" META-INF)
(cd "$tmp/x" && zip -qr "$(mk kuicksilver-native-android .aar)" jni)
(cd "$tmp/x" && zip -qr "$(mk kuicksilver-native-macosarm64 -cinterop-ksl.klib)" default)
printf '<project><artifactId>kuicksilver-bom</artifactId></project>\n' > "$(mk kuicksilver-bom .pom)"
printf '{"cyclonedx":"stand-in"}\n' > "$tmp/x/bom.cdx.json"; (cd "$tmp/x" && zip -q "$fx/github/kuicksilver-$v-sbom.zip" bom.cdx.json)
python3 - "$fx" "$v" > "$fx/github/kuicksilver-$v.intoto.json" <<'PY'
import hashlib, json, os, sys
fx, v = sys.argv[1:3]
subj = []
for d, _, fs in os.walk(os.path.join(fx, "io")):
    for f in sorted(fs):
        p = os.path.join(d, f); subj.append({"name": os.path.relpath(p, fx), "digest": {"sha256": hashlib.sha256(open(p, "rb").read()).hexdigest()}})
z = os.path.join(fx, "github", f"kuicksilver-{v}-sbom.zip")
subj.append({"name": os.path.basename(z), "digest": {"sha256": hashlib.sha256(open(z, "rb").read()).hexdigest()}})
src = {"uri": "git+https://github.com/kuicksilver/kuicksilver", "digest": {"gitCommit": "0" * 40}}
print(json.dumps({"_type": "https://in-toto.io/Statement/v1", "subject": sorted(subj, key=lambda s: s["name"]),
                  "predicateType": "https://slsa.dev/provenance/v1",
                  "predicate": {"buildDefinition": {"externalParameters": {"source": src, "version": v}}}}, indent=1))
PY
for f in $(cd "$fx" && find io -type f); do sign test "$fx/$f"; sha1 "$fx/$f" > "$fx/$f.sha1"; done
for f in "$fx/github"/*; do sign test "$f"; done

pass=0; fail=0
t() { # <name> <expected exit> <setup command, run in the case's copy> [+<line the report must match> | -<line it must not>]... -- [script args]
  local name="$1" want="$2" setup="$3"; shift 3
  local c="$tmp/case"; rm -rf "$c"; mkdir -p "$c"; cp -R "$fx" "$c/repo"; cp -R "$rb" "$c/rebuilt"
  local pats=(); while [ $# -gt 0 ] && [ "$1" != -- ]; do pats+=("$1"); shift; done; [ "${1:-}" = -- ] && shift
  (cd "$c" && eval "$setup") || { echo "FAIL $name: setup failed"; fail=$((fail+1)); return; }
  local out rc why=""
  local env=(KSL_VERIFY_KEY="$tmp/test-key.asc" KSL_VERIFY_FPR="$fpr"); [ "${PINNED:-0}" = 1 ] && env=(-u KSL_VERIFY_KEY -u KSL_VERIFY_FPR)
  out=$(cd "$c" && env "${env[@]}" bash "$script" "$v" --offline "$c/repo" \
    --rebuilt "$c/rebuilt" --targets macos-arm64,android-arm64 --work "$c/work" "$@" 2>&1); rc=$?
  [ "$rc" = "$want" ] || why="exit $rc, want $want"
  for p in ${pats[@]+"${pats[@]}"}; do
    case "$p" in
      +*) grep -Eq -- "${p#+}" <<< "$out" || why="${why:+$why; }no line matching '${p#+}'" ;;
      -*) ! grep -Eq -- "${p#-}" <<< "$out" || why="${why:+$why; }a line matching '${p#-}'" ;;
    esac
  done
  # shellcheck disable=SC2001
  if [ -z "$why" ]; then printf 'ok   %s\n' "$name"; pass=$((pass+1))
  else printf 'FAIL %s: %s\n' "$name" "$why"; sed 's/^/     | /' <<< "$out"; fail=$((fail+1)); fi
}
jar="repo/io/kuicksilver/kuicksilver-native-jvm/$v/kuicksilver-native-jvm-$v.jar"
aar="repo/io/kuicksilver/kuicksilver-native-android/$v/kuicksilver-native-android-$v.aar"
prov="repo/github/kuicksilver-$v.intoto.json"
flip() { python3 -c 'import sys; p=sys.argv[1]; b=bytearray(open(p,"rb").read()); b[len(b)//2]^=1; open(p,"wb").write(b)' "$1"; }

t "good release"                       0 ':' \
  '+^OK +signature +io/kuicksilver/kuicksilver-native-jvm/9.9.9/kuicksilver-native-jvm-9.9.9.jar' \
  '+^OK +signature +github/kuicksilver-9.9.9.intoto.json' '+^OK +provenance +io/kuicksilver/kuicksilver-native-android/9.9.9/' \
  '+^OK +rebuild +jni/osx-aarch_64/libksl_6_osx_aarch_64.dylib' '+^OK +rebuild +android/arm64-v8a/libksl.so' \
  '+^OK +rebuild +klib/macos_arm64/libcrypto.a' '+^SKIPPED +rebuild +jni/linux-x86_64' '+^SKIPPED +provenance +source commit' \
  '-^(DIFF|FAIL)' '+0 DIFF, [0-9]+ SKIPPED, 0 FAIL$'
t "tampered byte in the published jar" 1 "flip $jar" \
  '+^FAIL +signature +.*kuicksilver-native-jvm-9.9.9.jar +\(not a good signature' \
  '+^DIFF +provenance +.*kuicksilver-native-jvm-9.9.9.jar' '+^OK +rebuild +android/arm64-v8a'
# a published library that is not what the sources build, in a jar signed with the right key (a stolen key, a dirty build)
t "published library differs, signed"  1 "mkdir -p y/META-INF/native; printf 'other dylib\\n' > y/META-INF/native/libksl_6_osx_aarch_64.dylib
    rm $jar; (cd y && zip -qr ../$jar META-INF); sign test $jar; sha1 $jar > $jar.sha1" \
  '+^OK +signature +.*kuicksilver-native-jvm-9.9.9.jar' '+^DIFF +rebuild +jni/osx-aarch_64/libksl_6_osx_aarch_64.dylib' \
  '+^DIFF +provenance +.*kuicksilver-native-jvm-9.9.9.jar'
t "rebuilt library differs by a byte"  1 'flip rebuilt/android/arm64-v8a/libksl.so' \
  '+^DIFF +rebuild +android/arm64-v8a/libksl.so +\(rebuilt [0-9a-f]{16}, published [0-9a-f]{16}' '+^OK +signature' '-^FAIL'
t "signature by another key"           1 "rm $aar.asc; gpg --homedir $tmp/gpg-other --batch --armor --detach-sign -o $aar.asc $aar" \
  '+^FAIL +signature +.*kuicksilver-native-android-9.9.9.aar +\(not a good signature' '+^OK +rebuild +android/arm64-v8a'
t "provenance signed by another key"   1 "rm $prov.asc; gpg --homedir $tmp/gpg-other --batch --armor --detach-sign -o $prov.asc $prov" \
  '+^FAIL +signature +github/kuicksilver-9.9.9.intoto.json'
t "missing signature"                  1 "rm $jar.asc" '+^FAIL +signature +.*kuicksilver-native-jvm-9.9.9.jar +\(no \.asc\)'
t "missing artifact"                   1 "rm $aar $aar.asc $aar.sha1" \
  '+^FAIL +provenance +.*kuicksilver-native-android-9.9.9.aar +\(a subject of the provenance, missing here' \
  '+^FAIL +rebuild +android/arm64-v8a/libksl.so +\(kuicksilver-native-android-9.9.9.aar is not among'
t "published file not in the provenance" 1 "cp $jar ${jar%.jar}-extra.jar; cp $jar.asc ${jar%.jar}-extra.jar.asc" \
  '+^FAIL +provenance +.*-extra.jar +\(published, but not a subject'
t "wrong .sha1"                        1 "echo 0000000000000000000000000000000000000000 > $aar.sha1" '+^DIFF +sha1 +.*\.aar'
t "missing rebuilt library"            1 'rm rebuilt/klib/macos_arm64/libssl.a' '+^FAIL +rebuild +klib/macos_arm64/libssl.a +\(the rebuild produced no'
t "no GitHub release files"            0 'rm -r repo/github' '+^SKIPPED +provenance +kuicksilver-9.9.9.intoto.json +\(not on the GitHub release' '-^(DIFF|FAIL)'
t "--no-rebuild"                       0 ':' '+^SKIPPED +rebuild +native libraries +\(--no-rebuild\)' '-^OK +rebuild' -- --no-rebuild
# without the override the pinned release key is used: a fixture signed by any other key must fail every signature
PINNED=1 t "the pinned key, not the fixture's" 1 ':' '+^FAIL +signature +io/kuicksilver/kuicksilver-bom/' '-^OK +signature'
echo "passed $pass, failed $fail"
[ "$fail" = 0 ]
