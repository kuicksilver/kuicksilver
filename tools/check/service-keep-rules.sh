#!/usr/bin/env bash
# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
# Every class a published artifact names in META-INF/services must survive an application's shrinker: ServiceLoader creates it
# by name (kuicksilver-ktor-client's KuicksilverEngineContainer: HttpClient() finds the engine that way; R8 in class-file mode
# removed it and emptied the services file, fable review of k8/native-fixes). Usage: service-keep-rules.sh <jar|aar>...
# 1. The artifact's keep rules (proguard.txt in an AAR, META-INF/proguard/*.pro in a jar) keep every such class.
# 2. When R8 is in the Gradle cache (nothing is installed), R8 shrinks the artifact's classes in class-file mode with only those
#    rules (a jar's embedded rules as R8 reads them itself): each class and its services entry must survive. Negative control:
#    without the rules the same run must lose them. KSL_R8_REQUIRED=1 fails instead of skipping when R8 is missing.
set -uo pipefail
[ $# -gt 0 ] || { echo "usage: service-keep-rules.sh <jar|aar>..."; exit 2; }
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT INT TERM HUP; rc=0
r8="${KSL_R8_JAR:-$( (ls "$HOME"/.gradle/caches/modules-2/files-2.1/com.android.tools/r8/*/*/r8-*.jar 2>/dev/null || true) | grep -v sources | sort -V | tail -1)}"
jdk="${JAVA_HOME:-$(/usr/libexec/java_home 2>/dev/null || dirname "$(dirname "$(readlink -f "$(command -v java)")")")}"
# r8_keeps <classes jar> <out name> <class> <service file> [R8 options]: 0 when the class and its services entry survive
r8_keeps() {
  local in="$1" name="$2" cls="$3" svc="$4"; shift 4; local out="$tmp/$name.jar"
  printf -- '-dontwarn **\n' > "$tmp/base.pro"
  java -cp "$r8" com.android.tools.r8.R8 --release --classfile --lib "$jdk" --pg-conf "$tmp/base.pro" "$@" --output "$out" "$in" > "$tmp/$name.log" 2>&1 \
    || { echo "FAIL: R8 failed ($name)"; tail -5 "$tmp/$name.log"; return 2; }
  unzip -Z1 "$out" 2>/dev/null | grep -qx "${cls//.//}.class" && unzip -p "$out" "$svc" 2>/dev/null | grep -qx "$cls"
}
n=0
for art in "$@"; do
  [ -f "$art" ] || { echo "FAIL: no artifact at $art"; rc=1; continue; }
  d="$tmp/a$n"; n=$((n+1)); mkdir -p "$d"
  case "$art" in
    *.aar) unzip -q -o "$art" classes.jar proguard.txt -d "$d" 2>/dev/null; classes="$d/classes.jar"; rules="$d/proguard.txt"; embedded=0 ;;
    *) cp "$art" "$d/classes.jar"; classes="$d/classes.jar"; rules="$d/embedded.pro"; embedded=1
       for p in $(unzip -Z1 "$classes" 'META-INF/proguard/*' 2>/dev/null | grep -v '/$'); do unzip -p "$classes" "$p" >> "$rules"; done ;;
  esac
  services=$(unzip -Z1 "$classes" 'META-INF/services/*' 2>/dev/null | grep -v '/$')
  [ -n "$services" ] || { echo "$(basename "$art"): no META-INF/services"; continue; }
  for svc in $services; do
    for cls in $(unzip -p "$classes" "$svc" | sed 's/#.*//' | tr -d ' \r'); do
      if [ -s "$rules" ] && grep -Eq "^-keep[a-z,]* class ${cls//./\\.} *\{?" "$rules"; then echo "$(basename "$art"): rules keep $cls ($svc)"
      else echo "FAIL: $(basename "$art") does not keep $cls, named in $svc"; rc=1; continue; fi
      if [ -z "$r8" ] || [ ! -d "$jdk" ]; then
        echo "R8 run skipped: r8=${r8:-none} jdk=${jdk:-none}"; [ "${KSL_R8_REQUIRED:-0}" = 1 ] && { echo "FAIL: KSL_R8_REQUIRED=1"; rc=1; }; continue
      fi
      if [ "$embedded" = 1 ]; then r8_keeps "$classes" "keep$n" "$cls" "$svc"; else r8_keeps "$classes" "keep$n" "$cls" "$svc" --pg-conf "$rules"; fi
      case $? in 0) echo "R8 $(basename "$r8" .jar): $cls and its $svc entry survive" ;; *) echo "FAIL: R8 with the artifact's rules loses $cls"; rc=1 ;; esac
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
