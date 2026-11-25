#!/usr/bin/env bash
# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
# Members that kuicksilver-ktor-client's consumer rules keep from being inlined stay functions of their own in an Android
# app's release build. The ALTSVC frame learner's coroutine loop (KuicksilverEngine.learnAltSvcFrames, its KDoc says why)
# must make no call through an interface or an open method: ART 7.x aborted in the GC when such a call deoptimized the
# loop. Its work is in helpers that an app's R8 could inline back into the loop; consumer-rules.pro keeps them.
# Usage: r8-inlining.sh <kuicksilver-ktor-client AAR>
# 1. The AAR's proguard.txt has a `-keepclassmembers,allowobfuscation,allowshrinking` block naming the helpers.
# 2. When R8 (./gradlew -q ksR8Jar), an android.jar and dexdump are there (nothing is installed), R8 builds dex as an app's
#    release build would: --min-api 24, the AAR's classes and every class jar the app links with it
#    (./gradlew -q :kuicksilver-ktor-client:ksAndroidRuntimeJars, or the file KSL_RUNTIME_JARS names), the AAR's rules, an
#    app that reaches the engine through io.ktor.client.HttpClientKt, and -dontobfuscate so the names can be read. Every
#    helper the block names must still be defined and called, and the learner (the method that calls takeAltSvcFrames)
#    must make no invoke-interface and no invoke-virtual but on KuicksilverEngine (final) and java.util.concurrent.atomic.
#    The same shape is checked in D8's dex of the AAR, what an app gets without minification.
# Negative controls: without the block the same R8 run must inline at least one helper, else the check could not see an
# inlining; and the shape filter must report the invoke-interface of a small dexdump fixture of a learner.
# R8 9.3 inlines none of the three into the loop even without the block (it inlines learnAltSvcFrameBatch into its lambda,
# outside the loop): the block guards against a later R8 that would, and the negative control shows that the check sees
# an inlining when one happens. KSL_R8_REQUIRED=1 fails instead of skipping when a tool is missing. R8 and D8 run with
# --thread-count KSL_GATE_WORKERS (default 2; the JVM too). Gradle's messages go to a log whose tail is printed on a skip or a failure.
set -uo pipefail
root="$(cd "$(dirname "$0")/../.." && pwd)"
aar="${1:?usage: r8-inlining.sh <kuicksilver-ktor-client AAR>}"; [ -f "$aar" ] || { echo "FAIL: no AAR at $aar"; exit 2; }
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT INT TERM HUP; rc=0
threads="${KSL_GATE_WORKERS:-2}"
# gradle_log: the last lines of Gradle's messages, after a skip or a failure
gradle_log() { if [ -s "$tmp/gradle.log" ]; then echo "Gradle's last messages:"; tail -15 "$tmp/gradle.log" | sed 's/^/  /'; fi; }
unzip -q -o "$aar" proguard.txt classes.jar -d "$tmp/aar" 2>/dev/null
rules="$tmp/aar/proguard.txt"
[ -s "$rules" ] && [ -s "$tmp/aar/classes.jar" ] || { echo "FAIL: $aar lacks proguard.txt or classes.jar"; exit 2; }
engine=io.kuicksilver.ktor.client.KuicksilverEngine
block_start="-keepclassmembers,allowobfuscation,allowshrinking class $engine {"

# 1. the block and the helpers it names
helpers=$(awk -v s="$block_start" '$0 == s {p = 1; next} p && /^}/ {p = 0} p' "$rules" | sed -n 's/.* \([A-Za-z0-9_]*\)(.*/\1/p')
for h in takeAltSvcFrames learnAltSvcFrameBatch finishAltSvcFrames; do
  if grep -qxF "$h" <<< "$helpers"; then echo "rules keep $engine.$h from inlining"
  else echo "FAIL: proguard.txt has no '$block_start' block naming $h"; rc=1; fi
done
[ "$rc" = 0 ] || exit $rc

# the shape filter
# learner_of <dump>: the dexdump code of every method that calls takeAltSvcFrames, up to its catches
learner_of() {
  awk -v t="L${engine//.//};.takeAltSvcFrames:" '
    function flush() { if (index(body, t)) print body; body = ""; inm = 0 }
    /\|\[[0-9a-f]+\] / {flush(); body = $0; inm = 1; next}
    inm && /^      catches/ {flush(); next}
    inm {body = body "\n" $0}
    END {flush()}' "$1"
}
# bad_calls <code>: its invoke-interface calls, and its invoke-virtual calls outside KuicksilverEngine and j.u.c.atomic
bad_calls() {
  grep -o 'invoke-\(interface\|virtual\)[a-z/]* {[^}]*}, [^ ]*' <<< "$1" | sed 's/{[^}]*}, //' \
    | grep -v -e "^invoke-virtual[a-z/]* L${engine//.//};\." -e '^invoke-virtual[a-z/]* Ljava/util/concurrent/atomic/' || true
}
# shape <name> <dump>: 0 when the learner of <dump> makes no call that can deoptimize it, 1 when it does or is not found
shape() {
  local learner bad
  learner=$(learner_of "$2")
  [ -n "$learner" ] || { echo "FAIL: no method of the $1 dex calls takeAltSvcFrames"; return 1; }
  bad=$(bad_calls "$learner")
  if [ -n "$bad" ]; then
    echo "FAIL: in the $1 dex the ALTSVC frame learner makes calls that can deoptimize it on ART 7.x:"; echo "  ${bad//$'\n'/$'\n'  }"
    return 1
  fi
  echo "$1: the learner makes no interface or open call ($(grep -c 'invoke-' <<< "$learner") calls)"
}
# negative control of the filter: a learner that calls Map.isEmpty through its interface (the shape that aborted on API 24)
cat > "$tmp/fixture.dump" <<'FIXTURE'
      |[000100] io.kuicksilver.ktor.client.KuicksilverEngine.learnAltSvcFrames:(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
      |0000: invoke-direct {v5}, Lio/kuicksilver/ktor/client/KuicksilverEngine;.takeAltSvcFrames:()[Ljava/lang/Object; // method@0001
      |0003: invoke-interface {v9}, Ljava/util/Map;.isEmpty:()Z // method@0002
      |0006: invoke-virtual {v6, v4}, Ljava/util/concurrent/atomic/AtomicBoolean;.set:(Z)V // method@0003
      catches       : (none)
FIXTURE
fixture=$(shape fixture "$tmp/fixture.dump"); fx=$?
if [ "$fx" = 1 ] && grep -q 'Ljava/util/Map;.isEmpty' <<< "$fixture" && ! grep -q 'AtomicBoolean' <<< "$fixture"; then
  echo "negative control: the shape filter reports the fixture's Map.isEmpty and not its AtomicBoolean.set, as expected"
else echo "FAIL: negative control: the shape filter did not report the fixture's interface call alone:"; echo "$fixture"; rc=1; fi

# 2. R8 as an app's release build runs it, and D8
r8="${KSL_R8_JAR:-$( (cd "$root" && ./gradlew -q ksR8Jar 2>>"$tmp/gradle.log") | tail -1)}"   # the R8 pinned in gradle/libs.versions.toml
[ -f "$r8" ] || r8=
sdk="${ANDROID_HOME:-$(sed -n 's/^sdk\.dir=//p' "$root/local.properties" 2>/dev/null)}"; sdk="${sdk:-$HOME/Library/Android/sdk}"
android_jar=$( (ls "$sdk"/platforms/android-*/android.jar 2>/dev/null || true) | sort -V | tail -1)
dexdump=$( (ls "$sdk"/build-tools/*/dexdump 2>/dev/null || true) | sort -V | tail -1)
if [ -n "${KSL_RUNTIME_JARS:-}" ]; then cp "$KSL_RUNTIME_JARS" "$tmp/jars.txt"
else (cd "$root" && ./gradlew -q :kuicksilver-ktor-client:ksAndroidRuntimeJars 2>>"$tmp/gradle.log") > "$tmp/jars.txt"; fi
jars=(); classpath=()
while IFS= read -r j; do [ -f "$j" ] && { jars+=("$j"); classpath+=(--classpath "$j"); }; done < "$tmp/jars.txt"
if [ -z "$r8" ] || [ -z "$android_jar" ] || [ -z "$dexdump" ] || [ "${#jars[@]}" = 0 ]; then
  echo "R8 run skipped: r8=${r8:-none} android.jar=${android_jar:-none} dexdump=${dexdump:-none} runtime jars=${#jars[@]}"
  gradle_log
  [ "${KSL_R8_REQUIRED:-0}" = 1 ] && { echo "FAIL: KSL_R8_REQUIRED=1"; exit 1; }
  exit $rc
fi
printf '%s\n' '-dontwarn **' '-dontobfuscate' '-keep class io.ktor.client.HttpClientKt { *; }' > "$tmp/app.pro"
awk -v s="$block_start" '$0 == s {p = 1; next} p && /^}/ {p = 0; next} !p' "$rules" > "$tmp/bare.pro"
echo "R8: $r8 (version $(java -cp "$r8" com.android.tools.r8.R8 --version 2>/dev/null | head -1)); android.jar: $android_jar; ${#jars[@]} runtime jars"
# r8_run <name> <rules>: dex for API 24 and its dexdump in $tmp/<name>.dump; 2 when R8 failed
r8_run() {
  java -XX:ActiveProcessorCount="$threads" -cp "$r8" com.android.tools.r8.R8 --release --min-api 24 --thread-count "$threads" --lib "$android_jar" \
    --pg-conf "$tmp/app.pro" --pg-conf "$2" --output "$tmp/$1.zip" "$tmp/aar/classes.jar" "${jars[@]}" > "$tmp/$1.log" 2>&1 \
    || { echo "FAIL: R8 failed ($1)"; tail -5 "$tmp/$1.log"; return 2; }
  "$dexdump" -d "$tmp/$1.zip" > "$tmp/$1.dump" 2>/dev/null || { echo "FAIL: dexdump failed ($1)"; return 2; }
}
# kept <name>: how many helpers are still defined and called in <name>'s dex, each reported
kept() {
  local n=0 h d c
  for h in $helpers; do
    d=$(grep -c "name *: '$h'" "$tmp/$1.dump"); c=$(grep -c "L${engine//.//};\.$h:" "$tmp/$1.dump")
    echo "  $1: $h defined $d, called from $c site(s)"; [ "$d" -ge 1 ] && [ "$c" -ge 1 ] && n=$((n + 1))
  done
  kept_count=$n
}
nh=$(wc -w <<< "$helpers" | tr -d ' ')
r8_run with-rules "$rules" || { gradle_log; exit 1; }
kept with-rules
[ "$kept_count" = "$nh" ] || { echo "FAIL: with the AAR's rules R8 inlined or removed a helper of the ALTSVC frame learner"; rc=1; }
shape R8 "$tmp/with-rules.dump" || rc=1
r8_run without-block "$tmp/bare.pro" || { gradle_log; exit 1; }
kept without-block
if [ "$kept_count" = "$nh" ]; then echo "FAIL: negative control: without the block R8 inlined no helper, so this check proves nothing"; rc=1
else echo "negative control: without the block R8 inlines a helper, as expected"; fi
# D8: the dex an app gets without minification
if java -XX:ActiveProcessorCount="$threads" -cp "$r8" com.android.tools.r8.D8 --release --min-api 24 --thread-count "$threads" --lib "$android_jar" "${classpath[@]}" \
     --output "$tmp/d8.zip" "$tmp/aar/classes.jar" > "$tmp/d8.log" 2>&1 && "$dexdump" -d "$tmp/d8.zip" > "$tmp/d8.dump" 2>/dev/null; then
  shape D8 "$tmp/d8.dump" || rc=1
else echo "FAIL: D8 or its dexdump failed"; tail -5 "$tmp/d8.log"; rc=1; fi
[ "$rc" = 0 ] || gradle_log
exit $rc
