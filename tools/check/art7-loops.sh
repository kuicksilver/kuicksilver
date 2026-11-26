#!/usr/bin/env bash
# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
# Loops that ART 7.x (API 24/25) can deoptimize into a GC abort ("Tried to mark 0xebadde09"), in the dex an app gets from
# the Android AARs: tools/check/art7-loops.py says what a site is, docs/spec/art7-deopt-loops.md why.
# Usage: art7-loops.sh <kuicksilver-ktor-client AAR> <kuicksilver-ktor-server AAR> [<other Kuicksilver AAR>...]
# The classes are the client's and the server's AARs and every class jar an app links with them; the keep rules are the
# proguard.txt of every AAR given (the others, kuicksilver-quic's at least, for their rules only). The app is a stub
# compiled here with javac (tools/check/art7-app/App.java): it installs an event listener, a logger and an AsyncQlogSink
# on the client and the server, so that R8 keeps the code that calls them. Three dexes, as an app's build makes them:
#   R8 --release (--min-api 24, -dontobfuscate), D8 --release (an app that does not minify), D8 --debug (an app's debug
#   build, and the device tests).
#   release (R8, D8 --release): every site judged in tools/check/art7-loops.allow, or the check fails.
#   debug (D8 --debug): a debug dex copies the locals the debugger may show at each loop's turn, so many loops have the
#     dead copies the crash needs; its sites are listed in tools/check/art7-loops.debug.lock with their counts. A site that
#     is not listed, or whose count changed, fails (judge it: fix it, or list it); so does a line no site needs.
#     KSL_ART7_WRITE_LOCK=1 rewrites the lock.
# The helpers the AARs' rules keep from R8's inlining are listed below (expected=, as r8-inlining.sh lists the learner's):
# each listed block must be in the AARs' rules with exactly its helpers, every helper defined and called in the R8 dex, and
# a block of that kind that is not listed fails. Negative controls: each block R8 9.3 inlines a helper without
# (EngineEvents, AsyncQlogSink) must change R8's output on its own; H3PoolKt's guards a later R8 (R8 9.3 inlines neither
# helper without it), so only its presence is checked; and the debug dex has sites (the scan sees the shape in real dex).
# The filter's own negative controls: art7-loops-test.sh.
# Tools, pinned: android.jar of the compileSdk build-logic sets, dexdump of the build tools AGP uses by default
# (KSL_ART7_BUILD_TOOLS overrides), R8 of gradle/libs.versions.toml (ksR8Jar, or KSL_R8_JAR). Runtime jars:
# :kuicksilver-ktor-client:ksAndroidRuntimeJars and the server's (or the file KSL_RUNTIME_JARS names).
# KSL_R8_REQUIRED=1 fails instead of skipping when a tool is missing. R8 and D8 run with --thread-count KSL_GATE_WORKERS
# (default 2; the JVM and Gradle too). KSL_ART7_KEEP=<dir> keeps the dexes and dumps there.
set -uo pipefail
here="$(cd "$(dirname "$0")" && pwd)"; root="$(cd "$here/../.." && pwd)"
[ $# -ge 2 ] || { echo "usage: art7-loops.sh <client AAR> <server AAR> [<other AAR>...]"; exit 2; }
for a in "$@"; do [ -f "$a" ] || { echo "FAIL: no AAR at $a"; exit 2; }; done
tmp=${KSL_ART7_KEEP:-$(mktemp -d)}; [ -n "${KSL_ART7_KEEP:-}" ] || trap 'rm -rf "$tmp"' EXIT INT TERM HUP; rc=0
threads="${KSL_GATE_WORKERS:-2}"
gradle_log() { if [ -s "$tmp/gradle.log" ]; then echo "Gradle's last messages:"; tail -15 "$tmp/gradle.log" | sed 's/^/  /'; fi; }
skip() { echo "art7-loops skipped: $1"; gradle_log; [ "${KSL_R8_REQUIRED:-0}" = 1 ] && { echo "FAIL: KSL_R8_REQUIRED=1"; exit 1; }; exit 0; }
G=(./gradlew -q --max-workers="$threads")
mkdir -p "$tmp/c" "$tmp/s" "$tmp/rules"
unzip -q -o "$1" classes.jar -d "$tmp/c" 2>/dev/null; unzip -q -o "$2" classes.jar -d "$tmp/s" 2>/dev/null
[ -s "$tmp/c/classes.jar" ] && [ -s "$tmp/s/classes.jar" ] || { echo "FAIL: an AAR lacks classes.jar"; exit 2; }
n=0; for a in "$@"; do n=$((n + 1)); unzip -p "$a" proguard.txt > "$tmp/rules/$n.pro" 2>/dev/null || : > "$tmp/rules/$n.pro"; done

# the tools
compile_sdk=$(sed -n 's/^ *compileSdk = \([0-9][0-9]*\).*/\1/p' "$root/build-logic/src/main/kotlin/kuicksilver.kmp.gradle.kts" | head -1)
agp=$(sed -n 's/^agp = "\([0-9]*\.[0-9]*\)\..*"/\1/p' "$root/gradle/libs.versions.toml")
case "$agp" in 9.3) default_build_tools=36.0.0 ;; *) echo "FAIL: AGP $agp: pin its default build tools here (com.android.builder.core.ToolsRevisionUtils.DEFAULT_BUILD_TOOLS_REVISION)"; exit 2 ;; esac
build_tools="${KSL_ART7_BUILD_TOOLS:-$default_build_tools}"
sdk="${ANDROID_HOME:-$(sed -n 's/^sdk\.dir=//p' "$root/local.properties" 2>/dev/null)}"; sdk="${sdk:-$HOME/Library/Android/sdk}"
android_jar="$sdk/platforms/android-$compile_sdk/android.jar"; dexdump="$sdk/build-tools/$build_tools/dexdump"
[ -n "$compile_sdk" ] && [ -f "$android_jar" ] || skip "no android.jar of compileSdk ${compile_sdk:-?} ($android_jar)"
[ -x "$dexdump" ] || skip "no dexdump of build tools $build_tools ($dexdump)"
r8="${KSL_R8_JAR:-$( (cd "$root" && "${G[@]}" ksR8Jar 2>>"$tmp/gradle.log") | grep '\.jar$' | tail -1)}"
[ -f "$r8" ] || skip "no R8 jar"
if [ -n "${KSL_RUNTIME_JARS:-}" ]; then cp "$KSL_RUNTIME_JARS" "$tmp/jars.txt"
else
  (cd "$root" && "${G[@]}" :kuicksilver-ktor-client:ksAndroidRuntimeJars :kuicksilver-ktor-server:ksAndroidRuntimeJars \
    2>>"$tmp/gradle.log") > "$tmp/jars.txt"
fi
jars=()   # existing jar paths only: Gradle's quiet output also carries the OpenSSL build's verification lines
while IFS= read -r j; do [ -f "$j" ] && jars+=("$j"); done < <(grep '^/.*\.jar$' "$tmp/jars.txt" | awk '!seen[$0]++')
[ "${#jars[@]}" -gt 0 ] || skip "no runtime jars"
command -v javac > /dev/null || skip "no javac"
echo "R8: $r8 (version $(java -cp "$r8" com.android.tools.r8.R8 --version 2>/dev/null | head -1)); android.jar: $android_jar; dexdump: $dexdump; ${#jars[@]} runtime jars"

# the app stub
cp_all=$(IFS=:; echo "$tmp/c/classes.jar:$tmp/s/classes.jar:${jars[*]}:$android_jar")
mkdir -p "$tmp/app"
javac -nowarn -source 17 -target 17 -cp "$cp_all" -d "$tmp/app" "$here/art7-app/App.java" > "$tmp/javac.log" 2>&1 \
  || { echo "FAIL: the app stub does not compile:"; tail -10 "$tmp/javac.log"; exit 1; }
(cd "$tmp/app" && jar cf "$tmp/app.jar" .)
printf '%s\n' '-dontwarn **' '-dontobfuscate' '-keep class io.ktor.client.HttpClientKt { *; }' \
  '-keep class io.ktor.server.engine.EmbeddedServerJvmKt { *; }' '-keep class io.kuicksilver.ktor.server.Kuicksilver { *; }' \
  '-keep class app.App { *; }' > "$tmp/app.pro"
java_() { java -XX:ActiveProcessorCount="$threads" -cp "$r8" "$@"; }
# dex <name> <tool and mode...>: $tmp/<name>.zip and its dexdump $tmp/<name>.dump
dex() {
  local name="$1"; shift
  "$@" --min-api 24 --thread-count "$threads" --lib "$android_jar" --output "$tmp/$name.zip" \
    "$tmp/app.jar" "$tmp/c/classes.jar" "$tmp/s/classes.jar" "${jars[@]}" > "$tmp/$name.log" 2>&1 \
    || { echo "FAIL: $name: the dex build failed"; tail -5 "$tmp/$name.log"; return 1; }
  "$dexdump" -d "$tmp/$name.zip" > "$tmp/$name.dump" 2>/dev/null || { echo "FAIL: dexdump failed ($name)"; return 1; }
}
r8_rules() { local a=(); for f in "$@"; do a+=(--pg-conf "$f"); done; echo "${a[@]}"; }
rules_all=("$tmp"/rules/*.pro)
# shellcheck disable=SC2046   # one --pg-conf per rules file, no spaces in the scratch paths
dex r8 java_ com.android.tools.r8.R8 --release --pg-conf "$tmp/app.pro" $(r8_rules "${rules_all[@]}") || { gradle_log; exit 1; }
dex d8 java_ com.android.tools.r8.D8 --release || exit 1
dex d8debug java_ com.android.tools.r8.D8 --debug || exit 1

# the app stub's two classes of each listener and logger survive R8 (merged into one, R8 could bind their calls), for each
# base type R8 kept: one it removed (the server's listener, whose calls R8 found unreachable) has no calls to guard
merged=0
for pair in "io/kuicksilver/quic/KuicksilverLogger:Logger QuietLogger" "io/kuicksilver/ktor/client/KuicksilverEventListener:Listener CountingListener" \
  "io/kuicksilver/ktor/server/KuicksilverServerEventListener:ServerListener OtherServerListener"; do
  base="${pair%%:*}"
  grep -q "Class descriptor  : 'L$base;'" "$tmp/r8.dump" || { echo "app stub: R8 removed ${base//\//.}, and with it the calls of its classes"; continue; }
  for c in ${pair#*:}; do
    grep -q "Class descriptor  : 'Lapp/App\$$c;'" "$tmp/r8.dump" || { echo "FAIL: R8 merged or removed the app stub's App\$$c"; merged=1; rc=1; }
  done
done
[ "$merged" = 1 ] || echo "app stub: both classes of each listener and logger R8 kept are in its dex"

# the helpers kept from R8's inlining: each block of the AARs' rules this check owns (the learner's is r8-inlining.sh's),
# <class>|<helpers>|<control>. inlined: R8 9.3 inlines a helper without the block, and the block alone must change R8's
# output; later: R8 9.3 inlines none without it, the block guards a later R8 (its presence is checked, not its effect)
expected=(
  "io.kuicksilver.ktor.client.EngineEvents|deliver|inlined"
  "io.kuicksilver.quic.qlog.AsyncQlogSink|perform closeLive|inlined"
  "io.kuicksilver.ktor.client.h3.H3PoolKt|h3FailureFacts h3RequestMark|later"
)
found_blocks=()   # "<rules file>|<class>" of every such block in the AARs
for f in "${rules_all[@]}"; do
  while IFS= read -r c; do [ "$c" = io.kuicksilver.ktor.client.KuicksilverEngine ] || found_blocks+=("$f|$c"); done \
    < <(sed -n 's/^-keepclassmembers,allowobfuscation,allowshrinking class \([^ ]*\) {$/\1/p' "$f")
done
helpers_of() { # <rules file> <class>: the member names its block keeps, sorted
  awk -v s="-keepclassmembers,allowobfuscation,allowshrinking class $2 {" '$0 == s {p = 1; next} p && /^}/ {p = 0} p' "$1" \
    | sed -n 's/.* \([A-Za-z0-9_]*\)(.*/\1/p' | sort | tr '\n' ' ' | sed 's/ $//'
}
# kept <dump> <class> <helpers...>: how many are defined and called, each reported
kept() {
  local d="$1" c="$2" n=0 h def call; shift 2
  for h in "$@"; do
    def=$(grep -c "name *: '$h'" "$d"); call=$(grep -c "L${c//.//};\.$h:" "$d")
    echo "    $h: defined $def, called from $call site(s)"; [ "$def" -ge 1 ] && [ "$call" -ge 1 ] && n=$((n + 1))
  done
  kept_count=$n
}
echo "helpers kept from R8's inlining (${#expected[@]} blocks expected)"
for b in "${found_blocks[@]}"; do
  c="${b#*|}"; known=0
  for e in "${expected[@]}"; do [ "${e%%|*}" = "$c" ] && known=1; done
  [ "$known" = 1 ] || { echo "  FAIL: the block for $c is not listed in tools/check/art7-loops.sh (expected=)"; rc=1; }
done
for e in "${expected[@]}"; do
  c="${e%%|*}"; rest="${e#*|}"; want="${rest%%|*}"; control="${rest#*|}"
  f=""; for b in "${found_blocks[@]}"; do [ "${b#*|}" = "$c" ] && f="${b%%|*}"; done
  if [ -z "$f" ]; then echo "  FAIL: no AAR's rules keep the helpers of $c ($want)"; rc=1; continue; fi
  have=$(helpers_of "$f" "$c"); want_sorted=$(tr ' ' '\n' <<< "$want" | sort | tr '\n' ' ' | sed 's/ $//')
  [ "$have" = "$want_sorted" ] || { echo "  FAIL: the block for $c keeps '$have', not '$want_sorted'"; rc=1; continue; }
  read -r -a hs <<< "$want"
  echo "  $c: ${hs[*]} ($control)"
  kept "$tmp/r8.dump" "$c" "${hs[@]}"
  [ "$kept_count" = "${#hs[@]}" ] || { echo "  FAIL: with the AARs' rules R8 inlined or removed a helper of $c"; rc=1; }
  [ "$control" = inlined ] || { echo "  the block guards a later R8: its effect is not checked"; continue; }
  # negative control: the same R8 run without this block alone
  awk -v s="-keepclassmembers,allowobfuscation,allowshrinking class $c {" '$0 == s {p = 1; next} p && /^}/ {p = 0; next} !p' "$f" > "$tmp/bare.pro"
  others=(); for g in "${rules_all[@]}"; do [ "$g" = "$f" ] || others+=("$g"); done
  # shellcheck disable=SC2046
  dex r8-without java_ com.android.tools.r8.R8 --release --pg-conf "$tmp/app.pro" $(r8_rules "$tmp/bare.pro" "${others[@]}") || exit 1
  kept "$tmp/r8-without.dump" "$c" "${hs[@]}" > /dev/null
  if [ "$kept_count" != "${#hs[@]}" ]; then echo "  negative control: without the block R8 inlines a helper of $c, as expected"
  else echo "  FAIL: negative control: without the block R8 inlines no helper of $c, so this check could not see it go"; rc=1; fi
done

echo "release (R8, D8 --release): every site judged in tools/check/art7-loops.allow"
python3 -I "$here/art7-loops.py" "$tmp/r8.dump:$tmp/r8.zip" "$tmp/d8.dump:$tmp/d8.zip" > "$tmp/release.out"; rrc=$?
sed 's/^/  /' "$tmp/release.out"; [ "$rrc" = 0 ] || rc=1
echo "debug (D8 --debug): every site listed in tools/check/art7-loops.debug.lock"
lock_args=(--known "$here/art7-loops.debug.lock")
[ "${KSL_ART7_WRITE_LOCK:-0}" = 1 ] && lock_args=(--write-known "$here/art7-loops.debug.lock")
python3 -I "$here/art7-loops.py" "${lock_args[@]}" "$tmp/d8debug.dump:$tmp/d8debug.zip" > "$tmp/debug.out"; drc=$?
sed 's/^/  /' "$tmp/debug.out"; [ "$drc" = 0 ] || rc=1
# positive control: the debug dex has the shape, so the scan sees it in real dex
if grep -q '^art7-loops: 0 methods' "$tmp/debug.out"; then
  echo "FAIL: positive control: the debug dex shows no site, so this check proves nothing"; rc=1
else echo "positive control: the debug dex has sites, as expected"; fi
[ "$rc" = 0 ] || gradle_log
exit $rc
