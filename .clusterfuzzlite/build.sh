#!/bin/bash -eu
# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
#
# ClusterFuzzLite / OSS-Fuzz build for the Jazzer targets of kuicksilver-quic and kuicksilver-http3.
# 1. OpenSSL: the pinned release (gradle/openssl.toml) is downloaded, its PGP signature and SHA-256 are checked
#    (tools/openssl/fetch.sh) and it is built statically for linux-x64 (tools/openssl/build.sh). The local CI builds this
#    target inside manylinux2014 through Docker; Docker is not available here, so the base image's compiler is used:
#    the glibc floor of that library does not matter, it only runs in the fuzzing container.
# 2. libksl: tools/build-jni.sh links ksl + JNI + OpenSSL into libksl_<abi>_linux_x86_64.so and writes it, with its
#    SHA-256 manifest, to kuicksilver-native/build/jni/resources (the kuicksilver-native jar picks it up from there).
# 3. Gradle compiles the jvmTest classes with JDK 21, skipping buildJniHost (which would rebuild OpenSSL through
#    Docker), and prints the test runtime classpath of both modules (an init script, below).
# 4. The classpath is copied into $OUT and one Jazzer launcher is written per @FuzzTest method (--target_class and
#    --target_method), with the committed inputs of that method as its seed corpus.
# Status: prepared, never run; superseded for this project by local campaigns (tools/fuzz/campaign.sh). The target list
# below does not include the targets added since (ConnectionFuzzTest, ZeroRttFuzzTest, kuicksilver-tls, the ksl harness).

cd "$SRC/kuicksilver"
export JOBS="$(nproc)"

# 1-2: OpenSSL and libksl (JNI headers from the JDK in JAVA_HOME)
bash tools/openssl/fetch.sh
# CFLAGS is cleared: OpenSSL's Configure would pick up the sanitizer flags OSS-Fuzz exports, and an ASan-instrumented
# libksl cannot be loaded into the fuzzing JVM. The fuzzers target the Kotlin code; the C code has its own ASan tests.
CC="${CC:-clang}" CFLAGS="" bash tools/openssl/build.sh linux-x64
CC="${CC:-clang}" CFLAGS="" bash tools/build-jni.sh linux-x86_64 kuicksilver-native/build/jni

# 3: compile the fuzz targets and resolve their classpath
cat > /tmp/fuzz-classpath.init.gradle <<'GRADLE'
allprojects {
    if (name == 'kuicksilver-quic' || name == 'kuicksilver-http3') {
        afterEvaluate {
            tasks.register('printFuzzClasspath') {
                def cp = configurations.getByName('jvmTestRuntimeClasspath')
                dependsOn 'jvmTestClasses', 'jvmTestProcessResources', cp   // cp: builds the jars of the project dependencies
                def out = layout.buildDirectory.get().asFile
                def own = files("$out/classes/kotlin/jvm/test", "$out/processedResources/jvm/test")
                doLast { println('FUZZ_CP=' + (own.files + cp.files).join(':')) }
            }
        }
    }
}
GRADLE
CP=$(JAVA_HOME=/opt/jdk-21 ./gradlew --no-daemon --max-workers="$JOBS" -q -I /tmp/fuzz-classpath.init.gradle \
       -x :kuicksilver-native:buildJniHost \
       :kuicksilver-quic:printFuzzClasspath :kuicksilver-http3:printFuzzClasspath \
     | sed -n 's/^FUZZ_CP=//p' | tr ':' '\n' | awk 'NF && !seen[$0]++')

# 4: runtime classpath in $OUT. Jazzer itself comes from the base image (jazzer_agent_deploy.jar, $JAZZER_JUNIT_PATH),
#    so the project's own Jazzer jars are left out to avoid two versions on one classpath.
mkdir -p "$OUT/cp"
RUNTIME_CP=""
i=0
while IFS= read -r entry; do
  [ -e "$entry" ] || continue
  case "$(basename "$entry")" in jazzer-*.jar) continue ;; esac
  i=$((i + 1)); dest="cp/$i-$(basename "$entry")"
  cp -r "$entry" "$OUT/$dest"
  RUNTIME_CP="$RUNTIME_CP\$this_dir/$dest:"
done <<< "$CP"
cp "$JAZZER_JUNIT_PATH" "$OUT/cp/jazzer_junit.jar"
RUNTIME_CP="$RUNTIME_CP\$this_dir/cp/jazzer_junit.jar"

# One launcher per @FuzzTest: <module> <package> <class> <method>
targets="
kuicksilver-quic io.kuicksilver.quic.fuzz FrameDecodeFuzzTest frameDecode
kuicksilver-quic io.kuicksilver.quic.fuzz PacketHeaderFuzzTest packetHeader
kuicksilver-quic io.kuicksilver.quic.fuzz TransportParametersFuzzTest transportParameters
kuicksilver-quic io.kuicksilver.quic.fuzz ReassemblerFuzzTest streamReassembler
kuicksilver-quic io.kuicksilver.quic.fuzz RetryPacketFuzzTest retryPacket
kuicksilver-quic io.kuicksilver.quic.fuzz EndpointRouteFuzzTest endpointRoute
kuicksilver-quic io.kuicksilver.quic.fuzz PacketReceiveFuzzTest packetRecvServer
kuicksilver-quic io.kuicksilver.quic.fuzz PacketReceiveFuzzTest packetRecvClient
kuicksilver-quic io.kuicksilver.quic.fuzz PacketReceiveFuzzTest multiPacket
kuicksilver-quic io.kuicksilver.quic.fuzz PacketReceiveFuzzTest postHandshake
kuicksilver-http3 io.kuicksilver.http3.fuzz H3FrameFuzzTest h3Frames
kuicksilver-http3 io.kuicksilver.http3.fuzz H3FrameFuzzTest capsules
kuicksilver-http3 io.kuicksilver.http3.fuzz QpackDecodeFuzzTest qpackDecode
"
echo "$targets" | while read -r module pkg cls method; do
  [ -n "$module" ] || continue
  fuzzer="${module#kuicksilver-}_${method}"
  seeds="$module/src/jvmTest/resources/${pkg//.//}/${cls}Inputs/$method"
  if [ -d "$seeds" ] && [ -n "$(ls -A "$seeds")" ]; then (cd "$seeds" && zip -q -r "$OUT/${fuzzer}_seed_corpus.zip" .); fi
  cat > "$OUT/$fuzzer" <<LAUNCHER
#!/bin/bash
# LLVMFuzzerTestOneInput for fuzzer detection.
this_dir=\$(dirname "\$0")
if [[ "\$@" =~ (^| )-runs=[0-9]+($| ) ]]; then mem_settings='-Xmx1900m:-Xss900k'; else mem_settings='-Xmx2048m:-Xss1024k'; fi
LD_LIBRARY_PATH="$JVM_LD_LIBRARY_PATH":\$this_dir \\
\$this_dir/jazzer_driver --agent_path=\$this_dir/jazzer_agent_deploy.jar \\
  --cp=$RUNTIME_CP \\
  --target_class=$pkg.$cls --target_method=$method \\
  --instrumentation_includes=io.kuicksilver.** \\
  --jvm_args="\$mem_settings:-Djava.awt.headless=true" \\
  \$@
LAUNCHER
  chmod +x "$OUT/$fuzzer"
done
