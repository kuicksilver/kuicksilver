#!/usr/bin/env bash
# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
# The CONNECT-UDP proxy's ICMP paths on Linux with CAP_NET_RAW, which no macOS run reaches (RFC 9298 sections 3.1 and 6.1):
#   1) the ksl C tests in the Linux build image (tools/c-test.sh), whose icmp section then runs for real: ksl_icmp_open and
#      ksl_icmp_send of an IPv4 and an IPv6 Packet Too Big from the proxy's address (IP_PKTINFO, IPV6_PKTINFO), checked by a
#      second raw socket (type, code, MTU, checksum, quote, source) and by the target's error queue; the kernel's port
#      unreachable for a closed port and forged port and host unreachable messages through ksl_udp_take_unreachable;
#   2) LinuxIcmpCheckTest on a Linux JVM against the manylinux libksl: a proxied target datagram too large for the client is
#      answered with a Packet Too Big the target's kernel takes; a real port unreachable closes the tunnel; a forged one quoting
#      a payload never sent is ignored (RFC 8085 section 5.2) and one quoting a sent payload closes it.
# Both containers get --cap-add=NET_RAW (and, for the C tests, seccomp unconfined, so a user namespace can be tried first). The
# run fails when any of these is skipped. Usage: tools/interop/icmp-linux-check.sh [linux-x86_64|linux-aarch_64]
# The host must have resolved the Gradle dependencies online before (as for tools/ci/docker-jvm.sh).
set -euo pipefail
root="$(cd "$(dirname "$0")/../.." && pwd)"; cd "$root"
cls="${1:-linux-x86_64}"
abi=$(sed -n 's/^#define KSL_ABI_VERSION \([0-9]*\)u/\1/p' kuicksilver-native/src/c/ksl.h)
case "$cls" in
  linux-x86_64) plat=linux/amd64; img=kuicksilver-openssl-linux-x64; target=linux-x64; so=libksl_${abi}_linux_x86_64.so ;;
  linux-aarch_64) plat=linux/arm64; img=kuicksilver-openssl-linux-arm64; target=linux-arm64; so=libksl_${abi}_linux_aarch_64.so ;;
  *) echo "unknown $cls" >&2; exit 2 ;;
esac
out="$root/build/icmp-linux-check"; mkdir -p "$out"

# 1) the C tests, privileged
echo "== ksl C tests in $img (CAP_NET_RAW)"
KSL_DOCKER_OPTS="--cap-add=NET_RAW --security-opt seccomp=unconfined" bash tools/ci/docker-run.sh "$plat" "$img" \
  "CC=/opt/rh/devtoolset-10/root/usr/bin/gcc SAN= bash tools/c-test.sh $target" > "$out/c-test.log" 2>&1 || { cat "$out/c-test.log"; echo "C tests failed"; exit 1; }
for m in 'icmp: OK' 'icmp_linux_unreachable: OK' 'icmp_linux_ptb_v4: OK' 'icmp_linux_ptb_v6: OK' 'udp_recverr_ptb_parsed: OK'; do
  grep -qF "$m" "$out/c-test.log" || { grep -E 'icmp|recverr' "$out/c-test.log"; echo "missing: $m"; exit 1; }
done
echo "C: $(grep -cE ': OK$' "$out/c-test.log") OK lines, the ICMP ones among them"

# 2) the JVM check: libksl.so from the manylinux image (as tools/ci/docker-jvm.sh), then the test class in a Temurin container
echo "== libksl for $cls"
uflag=""; [ "$(uname -s)" = Linux ] && uflag="--user $(id -u):$(id -g)"
# shellcheck disable=SC2086
docker run --rm $uflag -e HOME=/tmp --platform "$plat" -v "$root:/w" -w /w -e CC=/opt/rh/devtoolset-10/root/usr/bin/gcc -e JAVA_HOME=/usr/lib/jvm/java "$img" bash -c \
  "[ -d /usr/lib/jvm/java/include ] || yum -q -y install java-11-openjdk-devel >/dev/null 2>&1 || true; bash tools/build-jni.sh $cls kuicksilver-native/build/jni"
[ -f "kuicksilver-native/build/jni/$cls/$so" ] || { echo "no $so built for $cls"; exit 1; }
gv=$(sed -n 's#^distributionUrl=.*/gradle-\([0-9.]*\)-bin\.zip$#\1#p' gradle/wrapper/gradle-wrapper.properties)
dist=""; for d in "$HOME/.gradle/wrapper/dists/gradle-$gv-bin/"*/"gradle-$gv"; do [ -x "$d/bin/gradle" ] && { dist="$d"; break; }; done
[ -n "$gv" ] && [ -x "$dist/bin/gradle" ] || { echo "no unpacked Gradle $gv under ~/.gradle/wrapper/dists: run ./gradlew --version on the host first" >&2; exit 2; }
[ -d "$HOME/.gradle/caches/modules-2" ] || { echo "no ~/.gradle/caches/modules-2 to mount as the read-only dependency cache" >&2; exit 2; }
echo "== LinuxIcmpCheckTest on a Linux JVM (CAP_NET_RAW, root in the container: raw sockets need it)"
results=kuicksilver-http3/build/test-results/jvmTest
rm -f "$results"/TEST-io.kuicksilver.http3.LinuxIcmpCheckTest.xml
# the same read-only dependency cache and private Gradle home as tools/ci/docker-jvm.sh (see there why)
docker run --rm --platform "$plat" --cap-add=NET_RAW -v "$root:/w" -w /w \
  -v "$HOME/.gradle/caches/modules-2:/ro-dep-cache/modules-2:ro" -e GRADLE_RO_DEP_CACHE=/ro-dep-cache \
  -e GRADLE_USER_HOME=/tmp/gh -v "$root/tools/ci/gradle-init.d:/tmp/gh/init.d:ro" -v "$dist:/opt/gradle:ro" \
  -e GRADLE_OPTS="-Dorg.gradle.workers.max=2" -e KSL_ICMP_LINUX_CHECK=1 \
  eclipse-temurin:21@sha256:3e3c176ffed168beb42c607be9bc1639b466cf00261a0fb04425562c9d0c5c2b bash -c \
  "(command -v cc >/dev/null || { apt-get -qq update >/dev/null && DEBIAN_FRONTEND=noninteractive apt-get -qq install -y --no-install-recommends gcc libc6-dev >/dev/null; }) && /opt/gradle/bin/gradle --offline --no-daemon --no-watch-fs -q --continue --project-cache-dir /tmp/gradle-project -Pkuicksilver.openssl.prebuilt=true -x :kuicksilver-native:buildJniHost :kuicksilver-http3:jvmTest --tests 'io.kuicksilver.http3.LinuxIcmpCheckTest'" \
  > "$out/jvm.log" 2>&1 || { cat "$out/jvm.log"; echo "LinuxIcmpCheckTest failed"; exit 1; }
x="$results/TEST-io.kuicksilver.http3.LinuxIcmpCheckTest.xml"
[ -f "$x" ] || { cat "$out/jvm.log"; echo "no result for LinuxIcmpCheckTest"; exit 1; }
grep -q 'tests="3" skipped="0" failures="0" errors="0"' "$x" || { cat "$x"; echo "LinuxIcmpCheckTest: not 3 passing tests"; exit 1; }
if grep -q 'skipped: run by tools/interop/icmp-linux-check.sh' "$x"; then echo "LinuxIcmpCheckTest skipped its checks (KSL_ICMP_LINUX_CHECK not seen)"; exit 1; fi
echo "icmp-linux-check: OK ($cls)"
