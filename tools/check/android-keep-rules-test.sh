#!/usr/bin/env bash
# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
# Where tools/check/android-keep-rules.sh finds the kotlin-stdlib jar its R8 run reads, in a throwaway copy of the
# repository with a fake ./gradlew, a fixture AAR (the consumer rules of kuicksilver-native, a placeholder classes.jar) and
# an empty Android SDK, so the run stops before R8 and names what it found: Gradle's answer (ksKotlinStdlibJar) first, also
# when a cache holds a newer one; KSL_KOTLIN_STDLIB_JAR over Gradle, a missing one refused; without Gradle the newest
# version in $GRADLE_RO_DEP_CACHE/modules-2 (what CI's matrix jobs read: Gradle never copies it into the user home) or in
# the Gradle user home, never a sources jar; none at all fails with KSL_R8_REQUIRED=1 (the R8 run and its negative
# control are the script's own). Needs python3. Usage: android-keep-rules-test.sh
set -uo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"; real="$(cd "$here/../.." && pwd)"
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT INT TERM HUP
rc=0
root="$tmp/repo"; mkdir -p "$root/tools/check" "$root/kuicksilver-native/src/jni" "$tmp/sdk" "$tmp/aar"
cp "$here/android-keep-rules.sh" "$root/tools/check/"
cp "$real/kuicksilver-native/src/jni/ksl_jni.c" "$root/kuicksilver-native/src/jni/"
cp "$real/kuicksilver-native/consumer-rules.pro" "$tmp/aar/proguard.txt"
echo placeholder > "$tmp/aar/classes.jar"
python3 -I -c 'import sys, zipfile
with zipfile.ZipFile(sys.argv[1], "w") as z:
    for n in ("proguard.txt", "classes.jar"): z.write(sys.argv[2] + "/" + n, n)' "$tmp/fixture.aar" "$tmp/aar"
# the fake wrapper: ksR8Jar prints a path; ksKotlinStdlibJar prints $FAKE_STDLIB, or fails when it is empty
cat > "$root/gradlew" <<'G'
#!/usr/bin/env bash
case "$*" in
  *ksR8Jar*) echo "/fake/r8.jar" ;;
  *ksKotlinStdlibJar*) [ -n "${FAKE_STDLIB:-}" ] || { echo "FAILURE: offline" >&2; exit 1; }; echo "> Task :ksKotlinStdlibJar"; echo "$FAKE_STDLIB" ;;
  *) exit 1 ;;
esac
G
chmod +x "$root/gradlew"
jar() { # jar <modules-2 dir> <version> [suffix]: a kotlin-stdlib jar where Gradle keeps one; prints its path
  local d="$1/files-2.1/org.jetbrains.kotlin/kotlin-stdlib/$2/0123abcd"
  mkdir -p "$d"; echo jar > "$d/kotlin-stdlib-$2${3:-}.jar"; echo "$d/kotlin-stdlib-$2${3:-}.jar"
}
ro="$tmp/ro"; home="$tmp/gh"; empty="$tmp/empty"; mkdir -p "$ro/modules-2" "$home/caches/modules-2" "$empty"
ro_jar=$(jar "$ro/modules-2" 2.4.20); old_jar=$(jar "$home/caches/modules-2" 2.3.0); jar "$ro/modules-2" 2.99.0 -sources > /dev/null
gradle_jar="$tmp/from-gradle/kotlin-stdlib-2.4.20.jar"; mkdir -p "${gradle_jar%/*}"; echo jar > "$gradle_jar"

# run <name> <want exit> <want kotlin-stdlib (a path, or none)> <env...>
run() {
  local name=$1 want_rc=$2 want=$3 out s=0; shift 3
  out=$(env -u KSL_R8_REQUIRED -u KSL_KOTLIN_STDLIB_JAR -u GRADLE_RO_DEP_CACHE -u KSL_R8_JAR \
    ANDROID_HOME="$tmp/sdk" HOME="$empty" GRADLE_USER_HOME="$empty/gh" "$@" bash "$root/tools/check/android-keep-rules.sh" "$tmp/fixture.aar" 2>&1) || s=$?
  if [ "$s" -eq "$want_rc" ] && { grep -qF "kotlin-stdlib=$want" <<< "$out" || { [ "$want_rc" -eq 2 ] && grep -qF "$want" <<< "$out"; }; }; then
    echo "ok $name"
  else
    echo "FAIL $name: exit $s (want $want_rc), want kotlin-stdlib=$want"; sed 's/^/    /' <<< "$out"; rc=1
  fi
}
run "Gradle's answer" 0 "$gradle_jar" FAKE_STDLIB="$gradle_jar"
run "Gradle's answer, also when the caches hold others" 0 "$gradle_jar" FAKE_STDLIB="$gradle_jar" GRADLE_RO_DEP_CACHE="$ro" GRADLE_USER_HOME="$home"
run "KSL_KOTLIN_STDLIB_JAR over Gradle" 0 "$ro_jar" FAKE_STDLIB="$gradle_jar" KSL_KOTLIN_STDLIB_JAR="$ro_jar"
run "negative_aMissingKslKotlinStdlibJarIsRefused" 2 "KSL_KOTLIN_STDLIB_JAR $tmp/none.jar is not a file" KSL_KOTLIN_STDLIB_JAR="$tmp/none.jar"
run "without Gradle: the read-only cache alone (CI's matrix jobs)" 0 "$ro_jar" GRADLE_RO_DEP_CACHE="$ro"
run "without Gradle: the newest of both caches, never a sources jar" 0 "$ro_jar" GRADLE_RO_DEP_CACHE="$ro" GRADLE_USER_HOME="$home"
run "without Gradle: the Gradle user home alone" 0 "$old_jar" GRADLE_USER_HOME="$home"
h2_jar=$(jar "$tmp/h2/.gradle/caches/modules-2" 2.2.0)
run "without Gradle: ~/.gradle when GRADLE_USER_HOME is empty" 0 "$h2_jar" GRADLE_USER_HOME= HOME="$tmp/h2"
run "a path Gradle printed that is not a file is not taken" 0 "$ro_jar" FAKE_STDLIB="$tmp/gone.jar" GRADLE_RO_DEP_CACHE="$ro"
run "negative_nothingFound_skipsWithout" 0 none
run "negative_nothingFound_failsWithKslR8Required" 1 none KSL_R8_REQUIRED=1
[ "$rc" -eq 0 ] && echo "android-keep-rules-test: all cases passed" || echo "android-keep-rules-test: FAILED"
exit $rc
