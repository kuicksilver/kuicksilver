#!/usr/bin/env bash
# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
# The module scope of tools/ci/changed-modules.sh on fixed lists of changed paths (--files) against this checkout's
# build files: nothing is built or run. Usage: tools/ci/changed-modules-test.sh
set -uo pipefail
here="$(cd "$(dirname "$0")" && pwd)"; script="$here/changed-modules.sh"
. "$here/matrix.sh"
fails=0; tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
t() { # <name> <expected modules, space-separated> -- <changed paths...>; the modules given are KSL_MODULES
  local name="$1" exp="$2" got; shift 3
  printf '%s\n' "$@" > "$tmp/files"
  # shellcheck disable=SC2086
  got=$(KSL_MATRIX_ALL_MODULES=0 bash "$script" --files "$tmp/files" $KSL_MODULES 2>/dev/null | tr '\n' ' ' | sed 's/ $//')
  if [ "$got" = "$exp" ]; then echo "ok   $name"; else echo "FAIL $name: got '$got', want '$exp'"; fails=$((fails + 1)); fi
}
t docsOnly              ""                                            -- docs/process.md README.md .github/workflows/build.yml tools/ci/local-matrix.sh
t nothingChanged        ""                                            -- ""
t leafModule            "kuicksilver-ktor-client kuicksilver-ktor-server" -- kuicksilver-ktor-client/src/commonMain/kotlin/A.kt
t http2Dependents       "kuicksilver-http2 kuicksilver-ktor-client kuicksilver-ktor-server" -- kuicksilver-http2/build.gradle.kts
t quicDependents        "kuicksilver-quic kuicksilver-testing kuicksilver-interop kuicksilver-http3 kuicksilver-ktor-client kuicksilver-ktor-server" -- kuicksilver-quic/src/jvmTest/kotlin/B.kt
t nativeSelectsAll      "$KSL_MODULES"                                -- kuicksilver-native/src/c/ksl.c
t notGivenModuleAlone   ""                                            -- kuicksilver-soak/src/jvmTest/kotlin/C.kt
t negative_buildLogic   "$KSL_MODULES"                                -- docs/process.md build-logic/src/main/kotlin/kuicksilver.kmp.gradle.kts
t negative_versionCatalog "$KSL_MODULES"                              -- gradle/libs.versions.toml
t negative_guideReadByTests "$KSL_MODULES"                            -- docs/guide/ktor.md
t negative_fuzzCorpus   "$KSL_MODULES"                                -- tools/fuzz/corpus/quic.frames/abc
t negative_moduleLists  "$KSL_MODULES"                                -- tools/ci/matrix.sh
t negative_archScript   "$KSL_MODULES"                                -- tools/check/sans-io.sh
t negative_rootScript   "$KSL_MODULES"                                -- tools/build-jni.sh
t negative_unknownPath  "$KSL_MODULES"                                -- some-new-input.txt
got=$(KSL_MATRIX_ALL_MODULES=1 bash "$script" --files /dev/null kuicksilver-tls kuicksilver-quic 2>/dev/null | tr '\n' ' ' | sed 's/ $//')
if [ "$got" = "kuicksilver-tls kuicksilver-quic" ]; then echo "ok   allModulesOverride"; else echo "FAIL allModulesOverride: got '$got'"; fails=$((fails + 1)); fi
got=$(bash "$script" --base no-such-ref-of-this-repo kuicksilver-tls 2>/dev/null)
if [ "$got" = "kuicksilver-tls" ]; then echo "ok   negative_noMergeBase"; else echo "FAIL negative_noMergeBase: got '$got'"; fails=$((fails + 1)); fi
[ "$fails" = 0 ] && echo "all passed" || { echo "$fails failed"; exit 1; }
