#!/usr/bin/env bash
# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
# Verifies a published Kuicksilver release without trusting the machine that built it (docs/verifying.md):
#   0. the tag v<version> (fetched from origin when this clone lacks it): signed by the release key (GOODSIG and VALIDSIG
#      for the pinned fingerprint), whose commit the provenance and the rebuild are compared with;
#   1. signatures: every file of every io.kuicksilver publication of <version> on Maven Central (repo1.maven.org) has a
#      good detached signature (.asc) by the release key, whose fingerprint is pinned here and in docs/release.md
#      (tools/release/kuicksilver-release-key.asc, the key gradle/verification-metadata.xml trusts); Central's .sha1
#      matches; a file that is listed but does not download, or has no .sha1, fails;
#   2. supply chain: kuicksilver-<version>.intoto.json and kuicksilver-<version>-sbom.zip of the GitHub release are signed
#      by the same key, every subject digest of the provenance matches the file from Central (and no Central file is left
#      out), and its source commit is the commit of the verified tag. From 0.2.1 their absence fails; older releases have
#      none (SKIPPED). No answer from GitHub fails for any version;
#   3. rebuild: the verified tag is exported with git archive, OpenSSL is fetched and verified as the release does it
#      (tools/openssl/fetch.sh), and the native libraries this host can build are built with the tag's own scripts and
#      compared byte for byte with the ones inside the published artifacts:
#        macOS host: osx-aarch_64 and osx-x86_64 JNI dylibs (in kuicksilver-native-jvm), the static archives libksl.a,
#        libssl.a, libcrypto.a of the macosarm64, iosarm64, iossimulatorarm64, linuxx64 and linuxarm64 cinterop klibs,
#        and the three Android libksl.so (in the kuicksilver-native-android AAR); Linux host: the Android libksl.so.
#      A target whose pinned toolchain (gradle/toolchains.toml of the tag: Xcode, NDK) is not the one installed is SKIPPED
#      (--allow-toolchain-drift builds it anyway; a difference is then expected). Everything else is reported SKIPPED with
#      the reason: the Linux and Windows JNI libraries and the mingwx64 archives (built in Docker images), and the
#      Kotlin/Gradle outputs (class files, klib IR, cstubs.bc, POMs, Gradle module files, sources and javadoc jars).
# Every line is OK, DIFF, SKIPPED or FAIL (a bad or missing signature, a missing file, a build that failed). Names that
# come from the server (BOM artifact ids, module file URLs, directory listings, provenance subjects) must be plain names;
# anything else fails and is not downloaded or opened. Exit 0 when nothing is DIFF or FAIL, 1 otherwise, 2 on a usage error.
#
# Usage: tools/verify/verify-release.sh <version> [options]
#   --offline <dir>   no network for the artifacts: <dir> is a Maven repository (<dir>/io/kuicksilver/<artifactId>/<version>/,
#                     with the .asc and, when present, .sha1 files; build/release/m2 of a signed release run is one: it has
#                     no .sha1, and offline their absence is not reported) and <dir>/github/ holds the GitHub release files.
#                     For a rebuild, openssl-<v>.tar.gz and its .asc in <dir>/openssl/ keep that offline too, and the tag
#                     must already be in this clone.
#   --no-rebuild      steps 0 to 2 only.
#   --rebuilt <dir>   compare against libraries built elsewhere instead of building them: <dir>/jni/<classifier>/<lib>,
#                     <dir>/android/<abi>/libksl.so, <dir>/klib/<konan target>/lib{ksl,ssl,crypto}.a (the layout this
#                     script writes into its work directory).
#   --targets <list>  comma-separated OpenSSL targets to rebuild (default: all this host can build, see above).
#   --allow-toolchain-drift   build targets whose Xcode or NDK is not the tag's pin.
#   --work <dir>      work directory (default build/verify/<version>; downloads, the exported tag, builds, logs).
# Env: KSL_VERIFY_CENTRAL (https://repo1.maven.org/maven2), KSL_VERIFY_GITHUB
#      (https://github.com/kuicksilver/kuicksilver/releases/download), JOBS (OpenSSL make jobs, 4),
#      KSL_VERIFY_KEY + KSL_VERIFY_FPR (another key) and KSL_VERIFY_REPO (another clone for the tag): for the tests only
#      (tools/verify/verify-release-test.sh); a warning says so on every run that sets them.
# The script and the key file are those of your checkout: compare the fingerprint above with the one in README.md,
# SECURITY.md and on a key server before trusting the result.
set -uo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"; root="$(cd "$here/../.." && pwd)"
fpr=22C1F2E4FCE94B28EB2C7DB0492ABD95C8D0EC68
key="$root/tools/release/kuicksilver-release-key.asc"
repo="$root"
central="${KSL_VERIFY_CENTRAL:-https://repo1.maven.org/maven2}"; github="${KSL_VERIFY_GITHUB:-https://github.com/kuicksilver/kuicksilver/releases/download}"
first_with_provenance=0.2.1   # docs/release.md, "Supply chain": every release from 0.2.1 has both files

usage() { sed -n '4,/^set -uo/p' "$0" | sed '$d' | sed 's/^# \{0,1\}//'; }
version=""; offline=""; rebuild=1; rebuilt=""; targets=""; drift=0; work=""
while [ $# -gt 0 ]; do case "$1" in
  --offline) offline="${2:?--offline <dir>}"; shift ;;
  --no-rebuild) rebuild=0 ;;
  --rebuilt) rebuilt="${2:?--rebuilt <dir>}"; shift ;;
  --targets) targets="${2:?--targets <list>}"; shift ;;
  --allow-toolchain-drift) drift=1 ;;
  --work) work="${2:?--work <dir>}"; shift ;;
  -h|--help) usage; exit 0 ;;
  -*) echo "unknown option $1 (see --help)" >&2; exit 2 ;;
  *) [ -z "$version" ] || { echo "one version only" >&2; exit 2; }; version="$1" ;;
esac; shift; done
[ -n "$version" ] || { echo "usage: $0 <version> [--offline <dir>] [--no-rebuild] [--rebuilt <dir>] (see --help)" >&2; exit 2; }
[[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[A-Za-z0-9.]+)?$ ]] || { echo "not a version: $version" >&2; exit 2; }
if [ -n "${KSL_VERIFY_KEY:-}${KSL_VERIFY_FPR:-}" ]; then
  key="${KSL_VERIFY_KEY:?KSL_VERIFY_KEY with KSL_VERIFY_FPR}"; fpr="${KSL_VERIFY_FPR:?KSL_VERIFY_FPR with KSL_VERIFY_KEY}"
  echo "WARNING: KSL_VERIFY_KEY/KSL_VERIFY_FPR are set: checking against $fpr, NOT the Kuicksilver release key (tests only)"
fi
if [ -n "${KSL_VERIFY_REPO:-}" ]; then
  repo="$KSL_VERIFY_REPO"; echo "WARNING: KSL_VERIFY_REPO is set: the tag is read from $repo, not from this clone (tests only)"
fi
[ -z "$offline" ] || { offline="$(cd "$offline" 2>/dev/null && pwd)" || { echo "no directory $offline" >&2; exit 2; }; }
[ -z "$rebuilt" ] || { rebuilt="$(cd "$rebuilt" 2>/dev/null && pwd)" || { echo "no directory $rebuilt" >&2; exit 2; }; }
for t in gpg python3 unzip curl git; do command -v "$t" >/dev/null || { echo "needs $t" >&2; exit 2; }; done
work="${work:-$root/build/verify/$version}"; mkdir -p "$work/logs"; work="$(cd "$work" && pwd)"
sha256() { (sha256sum "$1" 2>/dev/null || shasum -a 256 "$1") | cut -d' ' -f1; }
sha1() { (sha1sum "$1" 2>/dev/null || shasum -a 1 "$1") | cut -d' ' -f1; }
ver_ge() { # <a> <b>: a >= b, release part only (0.3.0-rc1 counts as 0.3.0)
  [ "$(printf '%s\n%s\n' "${1%%-*}" "${2%%-*}" | sort -V | head -1)" = "${2%%-*}" ]
}
ID_RE='^[A-Za-z0-9][A-Za-z0-9._-]*$'; FILE_RE='^[A-Za-z0-9][A-Za-z0-9._+-]*$'   # no "/", no leading ".": no traversal

n_ok=0; n_diff=0; n_skip=0; n_fail=0
res() { # <OK|DIFF|SKIPPED|FAIL> <check> <subject> [detail]
  printf '%-7s %-10s %s%s\n' "$1" "$2" "$3" "${4:+  ($4)}"
  case "$1" in OK) n_ok=$((n_ok+1)) ;; DIFF) n_diff=$((n_diff+1)) ;; SKIPPED) n_skip=$((n_skip+1)) ;; *) n_fail=$((n_fail+1)) ;; esac
}
CURL=(curl -sL --retry 2 --connect-timeout 15 --max-time 300)
fetch() { # <url> <file>: 0 downloaded (HTTP 200), 1 absent (HTTP 404), 2 anything else (no answer, another status)
  local code; mkdir -p "$(dirname "$2")"
  code=$("${CURL[@]}" -w '%{http_code}' -o "$2.part" "$1" 2>/dev/null) || code=000
  case "$code" in
    200) mv "$2.part" "$2"; return 0 ;;
    404) rm -f "$2.part"; return 1 ;;
    *) rm -f "$2.part"; return 2 ;;
  esac
}

echo "== Kuicksilver $version: verification ($([ -n "$offline" ] && echo "offline, $offline" || echo "$central"))"

# ------------------------------------------------------------------------------------------------- the release key
gh=$(mktemp -d /tmp/ksl-verify.XXXXXX)   # short path: macOS limits gpg-agent socket paths
trap 'gpgconf --homedir "$gh" --kill all >/dev/null 2>&1 || true; rm -rf "$gh"' EXIT
chmod 700 "$gh"
imported=$(gpg --homedir "$gh" --batch --status-fd 1 --import "$key" 2>/dev/null | sed -n 's/^\[GNUPG:\] IMPORT_OK [0-9]* \([0-9A-F]*\)$/\1/p')
[ "$imported" = "$fpr" ] || { echo "FAIL: importing $key gave '${imported:-nothing}', not $fpr" >&2; exit 2; }
echo "-- release key $fpr ($key)"
good_status() { # <gpg status lines>: a good signature (not expired, not revoked), valid for the pinned primary fingerprint
  printf '%s\n' "$1" | grep -q '^\[GNUPG:\] GOODSIG ' && printf '%s\n' "$1" | grep -Eq "^\[GNUPG:\] VALIDSIG .* $fpr\$"
}
sig_ok() { # <file> <signature>
  good_status "$(gpg --homedir "$gh" --batch --status-fd 1 --verify "$2" "$1" 2>/dev/null || true)"
}

# ------------------------------------------------------------------------------------------------------- 0. the tag
echo "-- tag v$version"
tag_commit=$(git -C "$repo" rev-parse -q --verify "refs/tags/v$version^{commit}" 2>/dev/null || true)
if [ -z "$tag_commit" ] && [ -z "$offline" ]; then
  git -C "$repo" fetch -q origin "refs/tags/v$version:refs/tags/v$version" 2>/dev/null || true
  tag_commit=$(git -C "$repo" rev-parse -q --verify "refs/tags/v$version^{commit}" 2>/dev/null || true)
fi
tag_ok=0   # only a tag signed by the release key is compared with or built from
if [ -z "$tag_commit" ]; then
  if [ "$rebuild" = 1 ] && [ -z "$rebuilt" ]; then res FAIL tag "v$version" "not in this clone$([ -z "$offline" ] && echo ", nor on origin"): nothing to rebuild from"
  else res SKIPPED tag "v$version" "not in this clone$([ -z "$offline" ] && echo ", nor on origin")"; fi
elif good_status "$(GNUPGHOME="$gh" git -c gpg.format=openpgp -c gpg.program=gpg -C "$repo" verify-tag --raw "v$version" 2>&1)"; then
  res OK tag "v$version" "commit $tag_commit, signed by $fpr"; tag_ok=1
else res FAIL tag "v$version" "commit $tag_commit, not a good signature by $fpr: not compared with, not rebuilt from"; fi

# ------------------------------------------------------------------------------------------------ 1. the artifacts
SIDE='\.(asc|md5|sha1|sha256|sha512)$'
expected=""   # online: the files Central listed, each must have arrived
if [ -n "$offline" ]; then
  m2="$offline"
  [ -d "$m2/io/kuicksilver" ] || { echo "FAIL: $m2/io/kuicksilver missing (--offline wants a Maven repository layout)" >&2; exit 2; }
else
  m2="$work/m2"
  echo "-- downloading $version from $central into $m2"
  bom="io/kuicksilver/kuicksilver-bom/$version/kuicksilver-bom-$version.pom"
  fetch "$central/$bom" "$m2/$bom"; rc=$?
  if [ "$rc" != 0 ]; then
    res FAIL central "$bom" "$([ "$rc" = 1 ] && echo "not on Maven Central (HTTP 404)" || echo "no answer from Maven Central")"
  else
    # the BOM names the root modules; each root .module names its platform publications ("available-at")
    mods=$(python3 - "$m2/$bom" <<'PY'
import re, sys
t = open(sys.argv[1], encoding="utf-8").read()
for d in re.findall(r"<dependency>(.*?)</dependency>", t, re.S):
    g = re.search(r"<groupId>\s*([^<\s]+)", d); a = re.search(r"<artifactId>\s*([^<\s]+)", d)
    if g and a and g.group(1) == "io.kuicksilver": print(a.group(1))
PY
)
    artifacts="kuicksilver-bom"
    for m in $mods; do
      [[ "$m" =~ $ID_RE ]] || { res FAIL central "BOM artifactId '$m'" "not a plain artifact id: not downloaded"; continue; }
      f="io/kuicksilver/$m/$version/$m-$version.module"
      artifacts="$artifacts $m"
      fetch "$central/$f" "$m2/$f"; rc=$?
      if [ "$rc" = 0 ]; then
        for p in $(python3 -c 'import json,sys
for v in json.load(open(sys.argv[1])).get("variants", []):
    u = v.get("available-at", {}).get("url")
    if u: print(u)' "$m2/$f" | sort -u); do
          # ../../<artifactId>/<version>/<file>, relative to the module's own directory
          a=$(printf '%s' "$p" | cut -d/ -f3)
          if [[ "$p" =~ ^\.\./\.\./[^/]+/[^/]+/[^/]+$ ]] && [[ "$a" =~ $ID_RE ]]; then artifacts="$artifacts $a"
          else res FAIL central "$f" "available-at '$p' is not ../../<artifactId>/<version>/<file>: not downloaded"; fi
        done
      else res FAIL central "$f" "the BOM names $m, but its Gradle module file $([ "$rc" = 1 ] && echo "is not on Central" || echo "did not download")"; fi
    done
    list="$work/downloads.txt"; : > "$list"
    artifacts=$(tr -s ' ' '\n' <<< "$artifacts" | grep . | sort -u)
    for a in $artifacts; do
      d="io/kuicksilver/$a/$version"
      fetch "$central/$d/" "$work/listing/$a.html"; rc=$?
      [ "$rc" = 0 ] || { res FAIL central "$d/" "$([ "$rc" = 1 ] && echo "not on Central" || echo "the listing did not download")"; continue; }
      files=$(sed -n 's/.*href="\([^"]*\)".*/\1/p' "$work/listing/$a.html" | grep -v '^\.\./$' | grep -Ev "$SIDE" || true)
      [ -n "$files" ] || { res FAIL central "$d/" "no files listed"; continue; }
      for f in $files; do
        [[ "$f" =~ $FILE_RE ]] || { res FAIL central "$d/$f" "not a plain file name: not downloaded"; continue; }
        expected="$expected $d/$f"
        for s in "" .asc .sha1; do printf '%s %s\n' "$central/$d/$f$s" "$m2/$d/$f$s" >> "$list"; done
      done
    done
    echo "     $(($(wc -l < "$list") / 3)) files of $(wc -l <<< "$artifacts" | tr -d ' ') publications, with .asc and .sha1"
    # shellcheck disable=SC2016
    xargs -P 6 -n 2 sh -c 'mkdir -p "$(dirname "$2")"; [ -s "$2" ] && exit 0
      code=$(curl -sL --retry 2 --connect-timeout 15 --max-time 300 -w "%{http_code}" -o "$2.part" "$1" 2>/dev/null) || code=000
      if [ "$code" = 200 ]; then mv "$2.part" "$2"; else rm -f "$2.part"; fi' sh < "$list"
    for f in $expected; do [ -f "$m2/$f" ] || res FAIL central "$f" "listed on Central, but the download failed"; done
  fi
fi

echo "-- signatures and checksums"
published=$(cd "$m2" && find io/kuicksilver -path "*/$version/*" -type f | grep -Ev "$SIDE" | grep -v '\.part$' | sort)
[ -n "$published" ] || res FAIL central "io/kuicksilver/*/$version" "no files"
for f in $published; do
  if [ ! -f "$m2/$f.asc" ]; then res FAIL signature "$f" "no .asc"
  elif ! sig_ok "$m2/$f" "$m2/$f.asc"; then res FAIL signature "$f" "not a good signature by $fpr"
  elif [ ! -f "$m2/$f.sha1" ]; then
    if [ -n "$offline" ]; then res OK signature "$f"; else res FAIL sha1 "$f" "good signature, but no .sha1 (Central serves one for every file)"; fi
  elif [ "$(cut -d' ' -f1 < "$m2/$f.sha1" | tr -d '[:space:]')" = "$(sha1 "$m2/$f")" ]; then res OK signature "$f" ".sha1 matches"
  else res DIFF sha1 "$f" "good signature, but the .sha1 does not match"; fi
done

# ------------------------------------------------------------------------------------------------ 2. SBOM, provenance
echo "-- GitHub release: SBOM and provenance"
ghd="${offline:+$offline/github}"; ghd="${ghd:-$work/github}"
prov="kuicksilver-$version.intoto.json"; sbom="kuicksilver-$version-sbom.zip"
noanswer=""
if [ -z "$offline" ]; then
  for f in "$prov" "$prov.asc" "$sbom" "$sbom.asc"; do fetch "$github/v$version/$f" "$ghd/$f"; [ $? != 2 ] || noanswer="$noanswer $f"; done
fi
if [ -n "$noanswer" ]; then
  for f in $noanswer; do res FAIL provenance "github/$f" "no answer from $github (not a 404): cannot tell whether it exists"; done
elif [ ! -f "$ghd/$prov" ] && [ ! -f "$ghd/$sbom" ] && ! ver_ge "$version" "$first_with_provenance"; then
  res SKIPPED provenance "$prov" "not on the GitHub release v$version (releases before $first_with_provenance have none)"
else
  prov_ok=1
  for f in "$prov" "$sbom"; do
    if [ ! -f "$ghd/$f" ]; then res FAIL provenance "github/$f" "not on the GitHub release v$version"; [ "$f" = "$sbom" ] || prov_ok=0
    elif [ ! -f "$ghd/$f.asc" ]; then res FAIL signature "github/$f" "no .asc"; [ "$f" = "$sbom" ] || prov_ok=0
    elif sig_ok "$ghd/$f" "$ghd/$f.asc"; then res OK signature "github/$f"
    else res FAIL signature "github/$f" "not a good signature by $fpr"; [ "$f" = "$sbom" ] || prov_ok=0; fi
  done
  if [ "$prov_ok" = 0 ]; then
    [ ! -f "$ghd/$prov" ] || res SKIPPED provenance "subjects of $prov" "its signature is not good: its contents are not used"
  else
    # subjects against the files; every Central file must be a subject; the source commit against the verified tag
    while IFS='|' read -r st check subject detail; do res "$st" "$check" "$subject" "$detail"
    done < <(python3 - "$ghd/$prov" "$m2" "$ghd" "$version" "$([ "$tag_ok" = 1 ] && echo "$tag_commit")" <<'PY'
import hashlib, json, os, re, sys
prov, m2, ghd, version, tag = sys.argv[1:6]
def sha(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""): h.update(b)
    return h.hexdigest()
try:
    st = json.load(open(prov, encoding="utf-8"))
    subj = st["subject"]
except Exception as e:
    print(f"FAIL|provenance|{os.path.basename(prov)}|unreadable: {e}"); sys.exit()
names = set()
for s in subj:
    name, want = str(s.get("name", "")), str(s.get("digest", {}).get("sha256", ""))
    names.add(name)
    parts = name.split("/")
    if not name or name.startswith("/") or "\\" in name or any(x in ("", ".", "..") for x in parts) \
            or not all(re.match(r"^[A-Za-z0-9][A-Za-z0-9._+-]*$", x) for x in parts):
        print(f"FAIL|provenance|{name!r}|not a plain relative path: not opened"); continue
    p = os.path.join(m2, name) if name.startswith("io/kuicksilver/") else os.path.join(ghd, name)
    if not os.path.isfile(p): print(f"FAIL|provenance|{name}|a subject of the provenance, missing here")
    elif sha(p) == want: print(f"OK|provenance|{name}|sha256 {want[:16]}")
    else: print(f"DIFF|provenance|{name}|sha256 {sha(p)[:16]}, the provenance says {want[:16]}")
base = os.path.join(m2, "io", "kuicksilver")
side = (".asc", ".md5", ".sha1", ".sha256", ".sha512", ".part")
for a in sorted(os.listdir(base)) if os.path.isdir(base) else []:
    d = os.path.join(base, a, version)
    if not os.path.isdir(d): continue
    for f in sorted(os.listdir(d)):
        rel = f"io/kuicksilver/{a}/{version}/{f}"
        if not f.endswith(side) and not f.startswith("maven-metadata") and rel not in names:
            print(f"FAIL|provenance|{rel}|published, but not a subject of the provenance")
src = st.get("predicate", {}).get("buildDefinition", {}).get("externalParameters", {}).get("source", {}).get("digest", {}).get("gitCommit", "")
if not tag: print(f"SKIPPED|provenance|source commit {src[:12]}|no verified tag v{version} to compare with")
elif src == tag: print(f"OK|provenance|source commit {src[:12]}|the commit of tag v{version}")
else: print(f"DIFF|provenance|source commit {src[:12]}|tag v{version} is {tag[:12]}")
PY
)
  fi
fi

# ------------------------------------------------------------------------------------------------------ 3. rebuild
published_file() { # <artifactId> <suffix>: the path of the published file, or nothing
  local p="$m2/io/kuicksilver/$1/$version/$1-$version$2"; [ -f "$p" ] && printf '%s\n' "$p"
}
from_zip() { # <zip> <entry regex> <out file>: 0 when extracted
  local e; e=$(unzip -Z1 "$1" 2>/dev/null | grep -E "^$2\$" | head -1); [ -n "$e" ] || return 1
  unzip -p "$1" "$e" > "$3"
}
compare() { # <what> <rebuilt file> <artifactId> <suffix> <entry regex in it>
  local what="$1" mine="$2" art; art=$(published_file "$3" "$4")
  if [ -z "$art" ]; then res FAIL rebuild "$what" "$3-$version$4 is not among the downloaded files"; return; fi
  if [ ! -f "$mine" ]; then res FAIL rebuild "$what" "the rebuild produced no $(basename "$mine")"; return; fi
  local theirs="$work/published/$what"; mkdir -p "$(dirname "$theirs")"
  if ! from_zip "$art" "$5" "$theirs"; then res FAIL rebuild "$what" "no $5 in $(basename "$art")"; return; fi
  if cmp -s "$mine" "$theirs"; then res OK rebuild "$what" "$(wc -c < "$mine" | tr -d ' ') bytes, sha256 $(sha256 "$mine" | cut -c1-16), in $(basename "$art")"
  else res DIFF rebuild "$what" "rebuilt $(sha256 "$mine" | cut -c1-16), published $(sha256 "$theirs" | cut -c1-16) in $(basename "$art")"; fi
}
products() { # <OpenSSL target>: what it yields, as "<kind> <name>" lines (jni <classifier>, android <abi>, klib <konan target>)
  case "$1" in
    macos-arm64) echo "jni osx-aarch_64"; echo "klib macos_arm64" ;; macos-x64) echo "jni osx-x86_64" ;;
    ios-arm64) echo "klib ios_arm64" ;; ios-sim-arm64) echo "klib ios_simulator_arm64" ;;
    linux-x64-kn) echo "klib linux_x64" ;; linux-arm64-kn) echo "klib linux_arm64" ;;
    android-arm64) echo "android arm64-v8a" ;; android-x86_64) echo "android x86_64" ;; android-arm) echo "android armeabi-v7a" ;;
  esac
}
klib_art() { case "$1" in macos_arm64) echo macosarm64 ;; ios_arm64) echo iosarm64 ;; ios_simulator_arm64) echo iossimulatorarm64 ;; linux_x64) echo linuxx64 ;; linux_arm64) echo linuxarm64 ;; esac; }
# the ksl ABI in the JNI library names: from the verified tag, else from the name of the one rebuilt library
abi=""; [ "$tag_ok" = 1 ] && abi=$(git -C "$repo" show "v$version:kuicksilver-native/src/c/ksl.h" 2>/dev/null | sed -n 's/^#define KSL_ABI_VERSION \([0-9]*\)u/\1/p')
compare_target() { # <OpenSSL target> <dir with jni/, android/, klib/>
  local kind name lib
  while read -r kind name; do case "$kind" in
    jni) if [ -n "$abi" ]; then lib="libksl_${abi}_${name/-/_}.dylib"
         else lib=$( (cd "$2/jni/$name" 2>/dev/null && ls libksl_*_"${name/-/_}".dylib 2>/dev/null) | head -1); lib="${lib:-libksl_<abi>_${name/-/_}.dylib}"; fi
         compare "jni/$name/$lib" "$2/jni/$name/$lib" kuicksilver-native-jvm .jar "META-INF/native/$lib" ;;
    android) compare "android/$name/libksl.so" "$2/android/$name/libksl.so" kuicksilver-native-android .aar "jni/$name/libksl\\.so" ;;
    klib) for a in libksl.a libssl.a libcrypto.a; do
            compare "klib/$name/$a" "$2/klib/$name/$a" "kuicksilver-native-$(klib_art "$name")" -cinterop-ksl.klib "default/targets/$name/included/${a//./\\.}"
          done ;;
  esac; done < <(products "$1")
}
echo "-- rebuild of the native libraries, compared byte for byte"
host=$(uname -s)
all_targets="android-arm64 android-x86_64 android-arm"; [ "$host" = Darwin ] && all_targets="macos-arm64 macos-x64 ios-arm64 ios-sim-arm64 $all_targets linux-x64-kn linux-arm64-kn"
[ -n "$targets" ] && all_targets="${targets//,/ }"
src=""
if [ "$rebuild" = 0 ]; then
  res SKIPPED rebuild "native libraries" "--no-rebuild"
elif [ -n "$rebuilt" ]; then
  echo "     against the libraries in $rebuilt (--rebuilt), not built here"
  for t in $all_targets; do
    [ -n "$(products "$t")" ] || { res FAIL rebuild "$t" "not a target this script rebuilds"; continue; }
    compare_target "$t" "$rebuilt"
  done
elif [ "$tag_ok" = 1 ]; then
  for v in LLVM_OBJCOPY LLVM_NM LLVM_OBJDUMP LLVM_READELF; do   # tools/check/llvm-tool.sh would take them over the NDK's
    [ -z "${!v:-}" ] || { echo "     note: $v=${!v} is ignored: the rebuild uses the pinned NDK's tool"; unset "$v"; }
  done
  src="$work/src"; rm -rf "$src"; mkdir -p "$src"
  git -C "$repo" archive "v$version" tools gradle kuicksilver-native/src | tar -x -C "$src"
  ndk_pin=$(sed -n 's/^ndk = "\(.*\)".*/\1/p' "$src/gradle/toolchains.toml" 2>/dev/null || true)
  xcode_pin=$(sed -n 's/^xcode = "\(.*\)".*/\1/p' "$src/gradle/toolchains.toml" 2>/dev/null || true)
  xcode_have=$(xcodebuild -version 2>/dev/null | sed -n 's/^Xcode //p' || true)
  ndk_dir=""
  for d in "${ANDROID_NDK_ROOT:-}" "$HOME/Library/Android/sdk/ndk/$ndk_pin" "$HOME/Android/Sdk/ndk/$ndk_pin"; do
    [ -n "$d" ] && [ "$(sed -n 's/^Pkg.Revision *= *//p' "$d/source.properties" 2>/dev/null)" = "$ndk_pin" ] && { ndk_dir="$d"; break; }
  done
  ossl=$(sed -n 's/^version = "\(.*\)"/\1/p' "$src/gradle/openssl.toml")
  if [ -n "$offline" ] && [ -f "$offline/openssl/openssl-$ossl.tar.gz" ]; then
    mkdir -p "$src/build/openssl-work/src"; cp "$offline/openssl/openssl-$ossl.tar.gz"* "$src/build/openssl-work/src/"
  fi
  if ! bash "$src/tools/openssl/fetch.sh" > "$work/logs/openssl-fetch.log" 2>&1; then
    res FAIL rebuild "OpenSSL $ossl" "fetch or verification failed, see $work/logs/openssl-fetch.log"; all_targets=""
  else res OK openssl "openssl-$ossl.tar.gz" "signature and SHA-256 of gradle/openssl.toml (tools/openssl/fetch.sh of the tag)"; fi
  out="$work/rebuilt"; rm -rf "$out"; mkdir -p "$out"
  for t in $all_targets; do
    [ -n "$(products "$t")" ] || { res FAIL rebuild "$t" "not a target this script rebuilds"; continue; }
    hard=""; soft=""   # hard: this host cannot build it; soft: it can, with another toolchain than the tag pins
    case "$t" in
      macos-*|ios-*) if [ "$host" != Darwin ]; then hard="needs a macOS host"
                     elif [ "$xcode_have" != "$xcode_pin" ]; then soft="Xcode ${xcode_have:-none} here, the tag pins $xcode_pin"; fi ;;
      *-kn) if [ "$host" != Darwin ]; then hard="the release builds it on a macOS host"
            elif ! ls -d "${KONAN_DEPS:-$HOME/.konan/dependencies}"/llvm-*-essentials-* >/dev/null 2>&1; then
              hard="no Kotlin/Native LLVM in ~/.konan/dependencies (a Gradle build of the tag downloads it)"; fi ;;
    esac
    # Android: the NDK compiles; the static archives are renamed with llvm-objcopy, which tools/check/llvm-tool.sh takes from the NDK
    [ -n "$hard" ] || [ -n "$soft" ] || [ -n "$ndk_dir" ] || soft="NDK $ndk_pin (the tag's pin) is not installed"
    [ -n "$soft" ] && [ "$drift" = 0 ] && hard="$soft (--allow-toolchain-drift builds it anyway)"
    if [ -n "$hard" ]; then
      while read -r kind name; do res SKIPPED rebuild "$kind/$name" "$hard"; done < <(products "$t"); continue
    fi
    [ -z "$soft" ] || echo "     $t: $soft; built anyway (--allow-toolchain-drift), a difference is expected"
    log="$work/logs/$t.log"; printf '     building %-16s' "$t"; t0=$SECONDS
    if ( set -e; export KSL_OPENSSL_FRESH=1; [ -z "$ndk_dir" ] || export ANDROID_NDK_ROOT="$ndk_dir"
         nice -n 10 bash "$src/tools/openssl/build.sh" "$t"
         while read -r kind name; do case "$kind" in
           jni) bash "$src/tools/build-jni.sh" "$name" "$out/jni-work"; mkdir -p "$out/jni/$name"; cp "$out/jni-work/$name"/libksl_* "$out/jni/$name/" ;;
           android) bash "$src/tools/build-android-so.sh" "$name" "$out/android" ;;
           klib) bash "$src/tools/build-ksl-a.sh" "$t"; mkdir -p "$out/klib/$name"; cp "$src/build/openssl-prefixed/$t/lib"/lib{ksl,ssl,crypto}.a "$out/klib/$name/" ;;
         esac; done < <(products "$t") ) > "$log" 2>&1
    then echo "done ($((SECONDS-t0)) s)"; compare_target "$t" "$out"
    else echo "failed ($((SECONDS-t0)) s)"
      while read -r kind name; do res FAIL rebuild "$kind/$name" "the build failed, see $log"; done < <(products "$t")
    fi
  done
else
  res FAIL rebuild "native libraries" "no verified tag v$version to build from (see the tag line above)"
fi
# what no option of this script rebuilds: said explicitly, so a report never reads as more than it checked
for x in "jni/linux-x86_64|built in the manylinux2014 Docker image (tools/openssl/docker), not rebuilt by this script" \
         "jni/linux-aarch_64|built in the manylinux2014 Docker image (tools/openssl/docker), not rebuilt by this script" \
         "jni/windows-x86_64|built in the mingw-w64 Docker image, whose mingw-w64 comes unpinned from Ubuntu's archive" \
         "klib/mingw_x64|its OpenSSL is built in the mingw-w64 Docker image" \
         "Kotlin and Gradle outputs|class files, klib IR, cstubs.bc, POMs, module files, sources and javadoc jars: signed, not rebuilt"; do
  res SKIPPED rebuild "${x%%|*}" "${x#*|}"
done

echo
echo "== $version: $n_ok OK, $n_diff DIFF, $n_skip SKIPPED, $n_fail FAIL"
[ "$n_diff" = 0 ] && [ "$n_fail" = 0 ]
