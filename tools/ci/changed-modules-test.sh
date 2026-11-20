#!/usr/bin/env bash
# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
# The module scope of tools/ci/changed-modules.sh: on fixed lists of changed paths (--files) against this checkout's
# build files, then in git mode in a scratch repository with three modules (untracked files, a non-ASCII name, a move,
# a deletion, staged and unstaged changes). Nothing is built or run. Usage: tools/ci/changed-modules-test.sh
set -uo pipefail
here="$(cd "$(dirname "$0")" && pwd)"; script="$here/changed-modules.sh"
. "$here/matrix.sh"
fails=0; tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
t() { # <name> <expected modules, space-separated> -- <changed paths...>; the modules given are KSL_MODULES
  local name="$1" exp="$2" got; shift 3
  printf '%s\n' "$@" > "$tmp/files"
  [ "$name" != noTrailingNewline ] || printf '%s' "$(cat "$tmp/files")" > "$tmp/files"   # the last path without its newline
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
t negative_gradleProperties "$KSL_MODULES"                            -- gradle.properties
t negative_settings     "$KSL_MODULES"                                -- settings.gradle.kts
t negative_rootBuild    "$KSL_MODULES"                                -- build.gradle.kts
t negative_buildSrc     "$KSL_MODULES"                                -- buildSrc/src/main/kotlin/X.kt
t negative_spdxScript   "$KSL_MODULES"                                -- tools/check/spdx.sh
t negative_quicImports  "$KSL_MODULES"                                -- tools/check/quic-imports.sh
t negative_opensslTool  "$KSL_MODULES"                                -- tools/openssl/build.sh
t otherCheckScript      ""                                            -- tools/check/links.sh
t moduleTestResource    "kuicksilver-http2 kuicksilver-ktor-client kuicksilver-ktor-server" -- kuicksilver-http2/src/jvmTest/resources/vectors/h.json
t renameAndDeletePair   "kuicksilver-ktor-network kuicksilver-http2 kuicksilver-ktor-client kuicksilver-ktor-server" -- kuicksilver-http2/src/commonMain/kotlin/Old.kt kuicksilver-ktor-network/src/commonMain/kotlin/Old.kt
t noTrailingNewline     "kuicksilver-ktor-client kuicksilver-ktor-server"                   -- docs/process.md kuicksilver-ktor-server/src/X.kt
for v in yes true 2 ' 1'; do
  rc=0; KSL_MATRIX_ALL_MODULES="$v" bash "$script" --files /dev/null kuicksilver-tls > /dev/null 2>&1 || rc=$?
  if [ "$rc" = 2 ]; then echo "ok   negative_allModulesValue[$v]"; else echo "FAIL negative_allModulesValue[$v]: exit $rc, want 2"; fails=$((fails + 1)); fi
done
got=$(KSL_MATRIX_ALL_MODULES=1 bash "$script" --files /dev/null kuicksilver-tls kuicksilver-quic 2>/dev/null | tr '\n' ' ' | sed 's/ $//')
if [ "$got" = "kuicksilver-tls kuicksilver-quic" ]; then echo "ok   allModulesOverride"; else echo "FAIL allModulesOverride: got '$got'"; fails=$((fails + 1)); fi
got=$(bash "$script" --base no-such-ref-of-this-repo kuicksilver-tls 2>/dev/null)
if [ "$got" = "kuicksilver-tls" ]; then echo "ok   negative_noMergeBase"; else echo "FAIL negative_noMergeBase: got '$got'"; fails=$((fails + 1)); fi
# git mode, in a scratch repository: kuicksilver-b depends on kuicksilver-a, kuicksilver-c on nothing
repo="$tmp/repo"; mkdir -p "$repo/tools/ci" "$repo/kuicksilver-a" "$repo/kuicksilver-b" "$repo/kuicksilver-c"
cp "$script" "$repo/tools/ci/changed-modules.sh"
echo '// none' > "$repo/kuicksilver-a/build.gradle.kts"; echo 'implementation(project(":kuicksilver-a"))' > "$repo/kuicksilver-b/build.gradle.kts"
echo '// none' > "$repo/kuicksilver-c/build.gradle.kts"
echo a > "$repo/kuicksilver-a/A.kt"; echo d > "$repo/kuicksilver-a/D.kt"; echo c > "$repo/kuicksilver-c/C.kt"; echo x > "$repo/README.md"
g() { git -C "$repo" -c user.name=t -c user.email=t@example.invalid -c commit.gpgsign=false -c core.hooksPath=/dev/null "$@"; }
g init -q -b main && g add -A && g commit -qm base || { echo "FAIL: scratch repository"; exit 1; }
gt() { # <name> <expected modules> -- <shell commands that change the scratch repository from main>
  local name="$1" exp="$2" got; shift 3
  g checkout -q -B work main && g reset -q --hard main && g clean -qfdx
  (cd "$repo" && eval "$1") > /dev/null 2>&1 || { echo "FAIL $name: setup"; fails=$((fails + 1)); return; }
  got=$(cd "$repo" && KSL_MATRIX_ALL_MODULES=0 bash tools/ci/changed-modules.sh --base main kuicksilver-a kuicksilver-b kuicksilver-c 2>/dev/null | tr '\n' ' ' | sed 's/ $//')
  if [ "$got" = "$exp" ]; then echo "ok   git_$name"; else echo "FAIL git_$name: got '$got', want '$exp'"; fails=$((fails + 1)); fi
}
c='git -c user.name=t -c user.email=t@example.invalid -c commit.gpgsign=false -c core.hooksPath=/dev/null commit -qam x'
gt nothing              ""                                         -- 'true'
gt untrackedInModule    "kuicksilver-c"                            -- 'echo n > kuicksilver-c/New.kt'
gt untrackedBuildLogic  "kuicksilver-a kuicksilver-b kuicksilver-c" -- 'mkdir build-logic && echo n > build-logic/x.gradle.kts'
gt untrackedGradleDir   "kuicksilver-a kuicksilver-b kuicksilver-c" -- 'mkdir gradle && echo n > gradle/libs.versions.toml'
gt untrackedScratch     ""                                         -- 'mkdir scratch && echo n > scratch/notes.txt && echo n > notes.txt'
gt nonAsciiName         "kuicksilver-c"                            -- 'mkdir -p kuicksilver-c/src && echo n > "kuicksilver-c/src/тест файл.kt" && git add -A && '"$c"
gt movedAcrossModules   "kuicksilver-a kuicksilver-b kuicksilver-c" -- 'git mv kuicksilver-a/A.kt kuicksilver-c/A.kt && '"$c"
gt deleted              "kuicksilver-a kuicksilver-b"              -- 'git rm -q kuicksilver-a/D.kt && '"$c"
gt stagedOnly           "kuicksilver-c"                            -- 'echo s >> kuicksilver-c/C.kt && git add kuicksilver-c/C.kt'
gt unstagedOnly         "kuicksilver-c"                            -- 'echo s >> kuicksilver-c/C.kt'
gt docsCommitted        ""                                         -- 'echo y >> README.md && '"$c"
[ "$fails" = 0 ] && echo "all passed" || { echo "$fails failed"; exit 1; }
