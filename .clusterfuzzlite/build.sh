#!/bin/bash -eu
# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
#
# ClusterFuzzLite / OSS-Fuzz build of the Jazzer targets of tools/fuzz/campaign.sh (every target of kind jvm in its
# target table, read from there so that the two never drift apart).
# 1. OpenSSL: the pinned release (gradle/openssl.toml) is downloaded, its PGP signature and SHA-256 are checked
#    (tools/openssl/fetch.sh) and it is built statically for linux-x64 (tools/openssl/build.sh). The local CI builds this
#    target inside manylinux2014 through Docker; Docker is not available here, so the base image's compiler is used:
#    the glibc floor of that library does not matter, it only runs in the fuzzing container.
# 2. libksl: tools/build-jni.sh links ksl + JNI + OpenSSL into libksl_<abi>_linux_x86_64.so and writes it, with its
#    SHA-256 manifest, to kuicksilver-native/build/jni/resources (the kuicksilver-native jar picks it up from there).
#    The QUIC and TLS targets load it (KslLoader); the others have it on their classpath and never load it.
# 3. Gradle compiles the jvmTest classes with JDK 21, skipping buildJniHost (which would rebuild OpenSSL through
#    Docker), and prints the test runtime classpath of each module (tools/fuzz/classpath.init.gradle, as the campaigns).
# 4. The classpath is copied into $OUT and one Jazzer launcher is written per target (--target_class and
#    --target_method of its @FuzzTest), named after the campaign id with '.' and '-' replaced by '_'
#    (quic.frameDecode -> quic_frameDecode, ktor-network.inflate -> ktor_network_inflate). Its seed corpus is the
#    committed inputs of that method and tools/fuzz/corpus/<id>/, the inputs the campaigns start from.
# The ksl C harness (campaign id ksl.parsers) is not built here: it is a C libFuzzer target with ASan and UBSan in a
# project whose language is jvm, and it reads its certificates from the source tree at run time; the campaigns run it.

cd "$SRC/kuicksilver"
JOBS="$(nproc)"; export JOBS

# 1-2: OpenSSL and libksl (JNI headers from the JDK in JAVA_HOME)
bash tools/openssl/fetch.sh
# CFLAGS is cleared: OpenSSL's Configure would pick up the sanitizer flags OSS-Fuzz exports, and an ASan-instrumented
# libksl cannot be loaded into the fuzzing JVM. The fuzzers target the Kotlin code; the C code has its own ASan tests.
CC="${CC:-clang}" CFLAGS="" bash tools/openssl/build.sh linux-x64
CC="${CC:-clang}" CFLAGS="" bash tools/build-jni.sh linux-x86_64 kuicksilver-native/build/jni

# The campaign's target table, <id> <kind> <module> <class> <method>: the targets of kind jvm and their modules
table=$(awk '/^targets_table\(\) \{/ { t = 1; next } t && /^EOF$/ { exit } t && NF == 5' tools/fuzz/campaign.sh)
modules=$(awk '$2 == "jvm" { print $3 }' <<< "$table" | sort -u | tr '\n' ' ')
[ -n "$modules" ] || { echo "no jvm target in tools/fuzz/campaign.sh" >&2; exit 1; }

# 3: compile the fuzz targets and resolve their classpath, one FUZZ_CP line per module
tasks=""; for m in $modules; do tasks="$tasks :$m:printFuzzClasspath"; done
# shellcheck disable=SC2086 # the task list is split on purpose
JAVA_HOME=/opt/jdk-21 ./gradlew --no-daemon --no-watch-fs --max-workers="$JOBS" -q -I tools/fuzz/classpath.init.gradle \
  -x :kuicksilver-native:buildJniHost $tasks > /tmp/fuzz-classpath.txt

# 4: the runtime classpath of each module in $OUT. Jazzer itself comes from the base image (jazzer_agent_deploy.jar,
#    $JAZZER_JUNIT_PATH), so the project's own Jazzer jars are left out to avoid two versions on one classpath. An
#    entry shared by several modules (a dependency jar) is copied once.
mkdir -p "$OUT/cp"
cp "$JAZZER_JUNIT_PATH" "$OUT/cp/jazzer_junit.jar"
declare -A copied module_cp
i=0
while IFS= read -r line; do
  case "$line" in "FUZZ_CP "*) ;; *) continue ;; esac
  line=${line#FUZZ_CP }; module=${line%%=*}; cp_str=""
  IFS=: read -r -a entries <<< "${line#*=}"
  for entry in "${entries[@]}"; do
    [ -e "$entry" ] || continue
    case "$(basename "$entry")" in jazzer-*.jar) continue ;; esac
    if [ -z "${copied[$entry]:-}" ]; then
      i=$((i + 1)); copied[$entry]="cp/$i-$(basename "$entry")"
      cp -r "$entry" "$OUT/${copied[$entry]}"
    fi
    cp_str="$cp_str\$this_dir/${copied[$entry]}:"
  done
  module_cp[$module]="$cp_str\$this_dir/cp/jazzer_junit.jar"
done < /tmp/fuzz-classpath.txt
for m in $modules; do [ -n "${module_cp[$m]:-}" ] || { echo "Gradle printed no classpath for $m" >&2; exit 1; }; done

# One launcher per target of kind jvm in the table
n=0
while read -r id kind module cls method; do
  [ "$kind" = jvm ] || continue
  fuzzer=${id//[.-]/_}
  pkg=${cls%.*}
  seeds="$module/src/jvmTest/resources/${pkg//.//}/${cls##*.}Inputs/$method"
  rm -rf /tmp/seeds && mkdir -p /tmp/seeds
  for d in "$seeds" "tools/fuzz/corpus/$id"; do
    if [ -d "$d" ]; then find "$d" -maxdepth 1 -type f -exec cp {} /tmp/seeds/ \;; fi
  done
  if [ -n "$(ls -A /tmp/seeds)" ]; then (cd /tmp/seeds && zip -q -r "$OUT/${fuzzer}_seed_corpus.zip" .); fi
  cat > "$OUT/$fuzzer" <<LAUNCHER
#!/bin/bash
# LLVMFuzzerTestOneInput for fuzzer detection.
this_dir=\$(dirname "\$0")
if [[ "\$@" =~ (^| )-runs=[0-9]+($| ) ]]; then mem_settings='-Xmx1900m:-Xss4m'; else mem_settings='-Xmx2048m:-Xss4m'; fi
LD_LIBRARY_PATH="$JVM_LD_LIBRARY_PATH":\$this_dir \\
\$this_dir/jazzer_driver --agent_path=\$this_dir/jazzer_agent_deploy.jar \\
  --cp=${module_cp[$module]} \\
  --target_class=$cls --target_method=$method \\
  --instrumentation_includes=io.kuicksilver.** \\
  --jvm_args="\$mem_settings:-Djava.awt.headless=true" \\
  \$@
LAUNCHER
  chmod +x "$OUT/$fuzzer"
  n=$((n + 1))
done <<< "$table"
[ "$n" -gt 0 ] || { echo "no jvm target in tools/fuzz/campaign.sh" >&2; exit 1; }
echo "built $n Jazzer targets"
