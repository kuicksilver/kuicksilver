#!/usr/bin/env bash
# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
# Every class a published artifact names in META-INF/services must survive an application's shrinker: ServiceLoader creates it
# by name (kuicksilver-ktor-client's KuicksilverEngineContainer: HttpClient() finds the engine that way; R8 in class-file mode
# removed it and emptied the services file, found in the 0.2.1 review). Usage: service-keep-rules.sh <jar|aar>...
# 1. The artifact's keep rules (proguard.txt in an AAR, META-INF/proguard/*.pro in a jar) keep every such class.
# 2. When R8 is in the Gradle cache (nothing is installed), R8 shrinks the artifact's classes in class-file mode with only those
#    rules (a jar's embedded rules as R8 reads them itself): each class, its services file and the file's entry naming the
#    class must survive; a failure says which of the three is missing. Negative control: without the rules the same run must
#    lose them. KSL_R8_REQUIRED=1 fails instead of skipping when R8 is missing.
# Work files go to build/check/service-keep-rules/<pid>/ (not $TMPDIR): removed when every check passed, kept on a failure
# with R8's output, its log and the configuration it ran with, and the path printed.
# Nothing here pipes into `grep -q`: under pipefail a reader that exits at its first match can kill the writer with SIGPIPE
# (status 141) and turn a pass into a failure. A gate run reported "R8 ... loses KuicksilverEngineContainer" for a jar that
# kept it; `unzip -Z1 | grep -qx` failed 288 times in 20000 on a host with 28 busy loops (14 cores), 0 times quiet.
set -uo pipefail
[ $# -gt 0 ] || { echo "usage: service-keep-rules.sh <jar|aar>..."; exit 2; }
root="$(cd "$(dirname "$0")/../.." && pwd)"
work="$root/build/check/service-keep-rules/$$"; rm -rf "$work"; mkdir -p "$work" || { echo "FAIL: cannot create $work"; exit 2; }
rc=0
trap 'if [ "$rc" = 0 ]; then rm -rf "$work"; else echo "kept for diagnosis: $work"; fi' EXIT
trap 'rc=130; exit 130' INT TERM HUP
r8="${KSL_R8_JAR:-$( (cd "$root" && ./gradlew -q ksR8Jar 2>/dev/null) | tail -1)}"   # the R8 pinned in gradle/libs.versions.toml
jdk="${JAVA_HOME:-$(/usr/libexec/java_home 2>/dev/null || dirname "$(dirname "$(readlink -f "$(command -v java)")")")}"
sha() { sha256sum "$1" 2>/dev/null || shasum -a 256 "$1"; }
# lists <file>: the entry names of a zip, one per line (read whole, so no pipe ends early)
lists() { unzip -Z1 "$1" 2>/dev/null; }
# r8_keeps <classes jar> <out name> <class> <service file> [R8 options]: 0 when the class, its services file and the entry
# naming it survive, 1 (and what is missing) when not, 2 when R8 itself failed
r8_keeps() {
  local in="$1" name="$2" cls="$3" svc="$4"; shift 4; local out="$work/$name.jar" entries missing=""
  printf -- '-dontwarn **\n' > "$work/$name.base.pro"
  printf '%s\n' "R8 $r8" "input $in" "options --release --classfile --lib $jdk --pg-conf $work/$name.base.pro $*" > "$work/$name.cmd"
  java -cp "$r8" com.android.tools.r8.R8 --release --classfile --lib "$jdk" --pg-conf "$work/$name.base.pro" "$@" \
    --pg-map-output "$work/$name.map" --output "$out" "$in" > "$work/$name.log" 2>&1 \
    || { echo "FAIL: R8 failed ($name, log $work/$name.log)"; tail -5 "$work/$name.log"; return 2; }
  entries=$(lists "$out")
  grep -qxF "${cls//.//}.class" <<< "$entries" || missing="$missing class ${cls//.//}.class;"
  if grep -qxF "$svc" <<< "$entries"; then
    grep -qxF "$cls" <<< "$(unzip -p "$out" "$svc" 2>/dev/null | sed 's/#.*//' | tr -d ' \r')" || missing="$missing $cls entry in $svc;"
  else missing="$missing services file $svc;"; fi
  [ -z "$missing" ] && return 0
  echo "  $name output ($out) lacks:${missing%;}"; return 1
}
[ -n "$r8" ] && echo "R8: $r8 (version $(java -cp "$r8" com.android.tools.r8.R8 --version 2>/dev/null | head -1)); JDK: $jdk"
n=0
for art in "$@"; do
  [ -f "$art" ] || { echo "FAIL: no artifact at $art"; rc=1; continue; }
  d="$work/a$n"; n=$((n+1)); mkdir -p "$d"
  case "$art" in
    *.aar) unzip -q -o "$art" classes.jar proguard.txt -d "$d" 2>/dev/null; classes="$d/classes.jar"; rules="$d/proguard.txt"; embedded=0 ;;
    *) cp "$art" "$d/classes.jar"; classes="$d/classes.jar"; rules="$d/embedded.pro"; embedded=1; : > "$rules"
       for p in $(lists "$classes" | grep '^META-INF/proguard/' | grep -v '/$'); do unzip -p "$classes" "$p" >> "$rules"; done ;;
  esac
  echo "$(basename "$art"): $(wc -c < "$art" | tr -d ' ') bytes, sha256 $(sha "$classes" | cut -d' ' -f1) (copied to $classes)"
  services=$(lists "$classes" | grep '^META-INF/services/' | grep -v '/$')
  [ -n "$services" ] || { echo "$(basename "$art"): no META-INF/services"; continue; }
  for svc in $services; do
    for cls in $(unzip -p "$classes" "$svc" | sed 's/#.*//' | tr -d ' \r'); do
      if [ -s "$rules" ] && grep -Eq "^-keep[a-z,]* class ${cls//./\\.} *\{?" "$rules"; then echo "$(basename "$art"): rules keep $cls ($svc)"
      else echo "FAIL: $(basename "$art") does not keep $cls, named in $svc"; rc=1; continue; fi
      if [ -z "$r8" ] || [ ! -d "$jdk" ]; then
        echo "R8 run skipped: r8=${r8:-none} jdk=${jdk:-none}"; [ "${KSL_R8_REQUIRED:-0}" = 1 ] && { echo "FAIL: KSL_R8_REQUIRED=1"; rc=1; }; continue
      fi
      if [ "$embedded" = 1 ]; then r8_keeps "$classes" "keep$n" "$cls" "$svc"; else r8_keeps "$classes" "keep$n" "$cls" "$svc" --pg-conf "$rules"; fi
      case $? in
        0) echo "R8 $(basename "$r8" .jar): $cls and its $svc entry survive" ;;
        1) echo "FAIL: R8 with the artifact's rules loses $cls (above: what is missing)"; rc=1 ;;
        *) rc=1 ;;
      esac
      stripped="$d/stripped.jar"; cp "$classes" "$stripped"; zip -q -d "$stripped" 'META-INF/proguard/*' >/dev/null 2>&1
      r8_keeps "$stripped" "bare$n" "$cls" "$svc"; case $? in
        0) echo "FAIL: negative control: R8 without the rules kept $cls, so this check proves nothing"; rc=1 ;;
        1) echo "negative control: without the rules R8 loses $cls, as expected" ;;
        *) rc=1 ;;
      esac
    done
  done
done
exit $rc
