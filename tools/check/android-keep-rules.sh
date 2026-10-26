#!/usr/bin/env bash
# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
# An Android app that shrinks with R8 must still be able to load libksl: JNI_OnLoad (kuicksilver-native/src/jni/ksl_jni.c)
# registers KslNative's natives and reads PacketBuffer.buffer by name, and fails the whole load when one is missing (review
# h-native, H1: 0.2.0 shipped no consumer rules). Usage: android-keep-rules.sh <kuicksilver-native AAR>
# 1. The AAR carries proguard.txt (consumer rules) naming every class FindClass looks up and every field GetFieldID reads in
#    ksl_jni.c, and keeping KslNative's natives.
# 2. When R8 is in the Gradle cache and an android.jar in the Android SDK (nothing is installed), R8 shrinks the AAR's classes
#    as an app would (the stock JNI rule of proguard-android-optimize.txt, an app that reaches the library only through
#    KslLoader): with proguard.txt every native and PacketBuffer.buffer must survive under their names; without it the same
#    check must fail (negative control: the check can see the breakage). Otherwise this part is skipped and says so.
# Env: KSL_R8_JAR, ANDROID_HOME (else sdk.dir from local.properties, else ~/Library/Android/sdk), KSL_R8_REQUIRED=1 fails
#      instead of skipping when R8 or android.jar is missing.
set -uo pipefail
root="$(cd "$(dirname "$0")/../.." && pwd)"
aar="${1:?usage: android-keep-rules.sh <aar>}"; [ -f "$aar" ] || { echo "FAIL: no AAR at $aar"; exit 2; }
jni="$root/kuicksilver-native/src/jni/ksl_jni.c"
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT INT TERM HUP; rc=0
unzip -q -o "$aar" proguard.txt classes.jar -d "$tmp/aar" 2>/dev/null
rules="$tmp/aar/proguard.txt"
[ -s "$rules" ] || { echo "FAIL: $aar has no proguard.txt (consumer keep rules): a minified app cannot load libksl"; exit 1; }
[ -s "$tmp/aar/classes.jar" ] || { echo "FAIL: $aar has no classes.jar"; exit 2; }

# 1. every name ksl_jni.c looks up appears in the rules
classes=$(grep -o 'FindClass(env, "[^"]*")' "$jni" | sed 's/.*"\(.*\)")/\1/' | tr / . | sort -u)
fields=$(grep -o 'GetFieldID(env, [a-z_]*, "[^"]*"' "$jni" | sed 's/.*, "\(.*\)"/\1/' | sort -u)
[ -n "$classes" ] || { echo "FAIL: found no FindClass in $jni (the check's pattern is out of date)"; exit 2; }
for c in $classes; do
  if grep -Eq "^-keep[a-z,]* class ${c//./\\.} *\{?" "$rules"; then echo "rules keep class $c"; else echo "FAIL: proguard.txt does not keep class $c (FindClass)"; rc=1; fi
done
for f in $fields; do
  if grep -Eq "^[[:space:]]+[A-Za-z0-9_.$]+ $f;" "$rules"; then echo "rules keep field $f"; else echo "FAIL: proguard.txt does not keep field $f (GetFieldID)"; rc=1; fi
done
if grep -A2 -E '^-keep[a-z,]*includedescriptorclasses class io\.kuicksilver\.native\.KslNative' "$rules" | grep -q 'native <methods>;'; then
  echo "rules keep KslNative's natives with their descriptor classes"
else echo "FAIL: proguard.txt does not keep KslNative's native methods (RegisterNatives) with includedescriptorclasses"; rc=1; fi

# 2. R8 over the AAR's classes, as an app's release build runs it
r8="${KSL_R8_JAR:-$( (cd "$root" && ./gradlew -q ksR8Jar 2>/dev/null) | tail -1)}"   # the R8 pinned in gradle/libs.versions.toml
sdk="${ANDROID_HOME:-$(sed -n 's/^sdk\.dir=//p' "$root/local.properties" 2>/dev/null)}"; sdk="${sdk:-$HOME/Library/Android/sdk}"
android_jar=$( (ls "$sdk"/platforms/android-*/android.jar 2>/dev/null || true) | sort -V | tail -1)
stdlib=$( (ls "$HOME"/.gradle/caches/modules-2/files-2.1/org.jetbrains.kotlin/kotlin-stdlib/*/*/kotlin-stdlib-[0-9]*.jar 2>/dev/null || true) | grep -v sources | sort -V | tail -1)
if [ -z "$r8" ] || [ -z "$android_jar" ] || [ -z "$stdlib" ]; then
  echo "R8 smoke run skipped: r8=${r8:-none} android.jar=${android_jar:-none} kotlin-stdlib=${stdlib:-none}"
  [ "${KSL_R8_REQUIRED:-0}" = 1 ] && { echo "FAIL: KSL_R8_REQUIRED=1"; exit 1; }
  exit $rc
fi
cat > "$tmp/app.pro" <<'EOF'
# what an app's release build gets from getDefaultProguardFile("proguard-android-optimize.txt") for JNI
-keepclasseswithmembernames,includedescriptorclasses class * { native <methods>; }
# an app that reaches the library only through its loader
-keep class io.kuicksilver.native.KslLoader { public *; }
-dontwarn **
EOF
echo "R8: $r8 (version $(java -cp "$r8" com.android.tools.r8.R8 --version 2>/dev/null | head -1)); android.jar: $android_jar"
natives_before=$(javap -cp "$tmp/aar/classes.jar" -p io.kuicksilver.native.KslNative | grep -c ' native ')
# r8_run <name> <extra R8 options...>: shrinks to class files (javap reads them), then answers 0 when every native and
# PacketBuffer.buffer kept their names, 1 when not, 2 when R8 itself failed
r8_run() {
  local name="$1"; shift; local out="$tmp/$name.jar"
  java -cp "$r8" com.android.tools.r8.R8 --release --classfile --lib "$android_jar" --pg-conf "$tmp/app.pro" "$@" \
    --output "$out" "$tmp/aar/classes.jar" "$stdlib" > "$tmp/$name.log" 2>&1 || { echo "FAIL: R8 failed ($name)"; tail -5 "$tmp/$name.log"; return 2; }
  local after field
  after=$(javap -cp "$out" -p io.kuicksilver.native.KslNative 2>/dev/null | grep -c ' native ')
  field=$(javap -cp "$out" -p io.kuicksilver.native.PacketBuffer 2>/dev/null | grep -c ' java\.nio\.ByteBuffer buffer;')
  echo "R8 $(basename "$r8" .jar) $name: KslNative natives $natives_before before, $after after; PacketBuffer.buffer kept: $field"
  [ "$after" = "$natives_before" ] && [ "$field" = 1 ]
}
r8_run with-consumer-rules --pg-conf "$rules" || { echo "FAIL: R8 with the AAR's proguard.txt removes or renames what JNI_OnLoad looks up"; rc=1; }
r8_run without-consumer-rules; neg=$?
case $neg in
  0) echo "FAIL: negative control: R8 without the consumer rules kept everything, so this check proves nothing"; rc=1 ;;
  1) echo "negative control: without the consumer rules R8 breaks JNI_OnLoad's lookups, as expected" ;;
  *) rc=1 ;;
esac
exit $rc
