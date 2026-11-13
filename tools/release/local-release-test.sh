#!/usr/bin/env bash
# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
# The branch, origin, Maven Central, CHANGELOG and version refusals of tools/release/local-release.sh (step 1), in a
# throwaway repository with main, maintenance branches, a feature branch and a local bare origin: the script runs as
# committed up to its local-gate check, where a stub line stops it (nothing is built, signed or uploaded). Maven Central is
# a stub (KSL_CENTRAL_PROBE) and a curl that fails on PATH, so no case reaches the network. Each case expects "ok" or
# "refuse", optionally with a pattern its output must contain; a last case runs the version checks on the repository's own
# version files. Usage: local-release-test.sh
set -uo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"; root="$(cd "$here/../.." && pwd)"
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
# Maven Central: 0.2.0 is published, nothing else; KSL_CENTRAL_STATUS forces an answer (000: no answer)
mkdir -p "$tmp/bin"
printf '#!/bin/sh\nif [ -n "${KSL_CENTRAL_STATUS:-}" ]; then echo "$KSL_CENTRAL_STATUS"; exit 0; fi\ncase "$1" in */kuicksilver-bom/0.2.0/kuicksilver-bom-0.2.0.pom) echo 200 ;; *) echo 404 ;; esac\n' > "$tmp/bin/central"
printf '#!/bin/sh\necho "curl called in a test: $*" >&2; exit 7\n' > "$tmp/bin/curl"
chmod +x "$tmp/bin/central" "$tmp/bin/curl"
export KSL_CENTRAL_PROBE="$tmp/bin/central" PATH="$tmp/bin:$PATH"
# the Swift package repository: empty (no version released there yet); swift-tagged.git already has 0.2.1
for r in swift swift-tagged; do git init -q --bare -b main "$tmp/$r.git"; done
( w="$tmp/swift-w"; git init -q -b main "$w" && cd "$w" && git -c user.email=t@example.invalid -c user.name=t commit -q --allow-empty -m x \
  && git tag 0.2.1 && git push -q "$tmp/swift-tagged.git" main 0.2.1 ) || { echo "FAIL: Swift package fixture"; exit 2; }
export KSL_SWIFT_REPO="$tmp/swift.git"
marker='^# the local gate: tools/ci/local-matrix.sh writes'
grep -qE "$marker" "$root/tools/release/local-release.sh" || { echo "FAIL: the local-gate marker line is gone from local-release.sh"; exit 2; }
new_repo() { # <dir>: a repository with what the script reads before the gate, and the script stopped there
  git init -q -b main "$1"; cd "$1" || exit 2
  git config user.email t@example.invalid; git config user.name t; git config commit.gpgsign false; git config core.hooksPath /dev/null
  mkdir -p tools/release tools/check kuicksilver-native/src/c gradle
  cp "$root/tools/check/llvm-tool.sh" tools/check/
  cp "$root/kuicksilver-native/src/c/ksl.h" kuicksilver-native/src/c/; cp "$root/gradle/openssl.toml" gradle/
  mkdir -p tools/release/swift-package licenses; cp "$root/tools/release/swift-package.sh" tools/release/
  cp "$root"/tools/release/swift-package/*.in tools/release/swift-package/; cp "$root/LICENSE" "$root/NOTICE" .
  cp "$root/licenses/LICENSE.openssl.txt" licenses/
  awk -v m="$marker" '$0 ~ m {print "echo \"STOPPED-BEFORE-GATE push_branch=$push_branch problems=$problems\"; exit 0"} {print}' \
    "$root/tools/release/local-release.sh" > tools/release/local-release.sh
  printf 'build/\n' > .gitignore
}
git init -q --bare "$tmp/origin.git"; new_repo "$tmp/repo"

tree_version() { # <X.Y.Z of every -SNAPSHOT fallback> <version the README and the iOS guide name> [<file to leave behind>]
  local s="$1-SNAPSHOT" p="$2" f
  for f in build-logic/src/main/kotlin/kuicksilver.kmp.gradle.kts build-logic/src/main/kotlin/kuicksilver.release.gradle.kts \
      kuicksilver-bom/build.gradle.kts samples/realtime-telemetry/build.gradle.kts samples/ios/shared/build.gradle.kts \
      samples/ios/kuicksilver-swift/build.gradle.kts samples/compose-demo/build.gradle.kts; do
    [ "$f" = "${3:-}" ] && continue
    mkdir -p "$(dirname "$f")"; printf 'version = providers.gradleProperty("kuicksilver.version").getOrElse("%s")\n' "$s" > "$f"
  done
  printf 'version="${1:-%s}"\n' "$s" > tools/check/consumer-smoke.sh
  mkdir -p docs/guide
  printf '> The API can change between any two 0.x releases, and %s is on Maven Central.\n\n    implementation("io.kuicksilver:kuicksilver-ktor-client:%s")\n' "$p" "$p" > README.md
  printf '        implementation("io.kuicksilver:kuicksilver-http3:%s")   // or -quic\n    .package(url: "https://github.com/kuicksilver/kuicksilver-swift", .upToNextMinor(from: "%s")),\n            url: "https://github.com/kuicksilver/kuicksilver/releases/download/v%s/Kuicksilver.xcframework.zip",\n' "$p" "$p" "$p" > docs/guide/ios.md
}
commit() { git add -A; git commit -qm "$1"; }

# base: the 0.2.1 line prepared (the fork point of release/0.2.x); main then moves to 0.3.0
printf '# Changelog\n\n## [0.15.0] - 2028-01-01\n\n## [0.10.0] - 2027-08-01\n\n## [0.9.0] - 2027-07-01\n\n## [0.8.0] - 2027-06-01\n\n## [0.7.0] - 2027-05-01\n\n## [0.6.0] - 2027-04-01\n\n## [0.5.0] - 2027-03-01\n\n## [0.4.0-rc1] - 2027-02-01\n\n## [0.3.1] - 2027-01-15\n\n## [0.3.0] - 2026-12-01\n\n## [0.2.2] - 2026-11-25\n\n## [0.2.2-rc1] - 2026-11-20\n\n## [0.2.1] - 2026-11-03\n\n## [1.2.1] - 2027-01-01\n\n## [0.2.9] - unreleased\n\n## [0.2.8]\n' > CHANGELOG.md
tree_version 0.2.1 0.2.1; commit base
git remote add origin "$tmp/origin.git"; git push -q origin main
git branch release/0.2.x
tree_version 0.3.0 0.3.0; commit "main: prepare 0.3.0"
git checkout -q release/0.2.x; echo c > h; commit branch-only; git checkout -q main
git branch release/0.1.x main
git checkout -q -b feature main; echo z > z; commit feature-only
git checkout -q -b release/0.4.x main; tree_version 0.4.0 0.3.0; commit "0.4 line"   # a prerelease leaves the coordinates alone
git checkout -q -b release/0.5.x main; tree_version 0.5.0 0.3.0; commit "0.5 line, README not moved"
git checkout -q -b release/0.6.x main; tree_version 0.6.0 0.6.0; printf '        implementation("io.kuicksilver:kuicksilver-http3:0.3.0")\n' > docs/guide/ios.md; commit "0.6 line, iOS guide not moved"
git checkout -q -b release/0.7.x main; tree_version 0.7.0 0.7.0; printf 'version = providers.gradleProperty("kuicksilver.version").getOrElse("0.3.0-SNAPSHOT")\n' > kuicksilver-bom/build.gradle.kts; commit "0.7 line, BOM not moved"
git checkout -q -b release/0.8.x main; tree_version 0.8.0 0.8.0 kuicksilver-bom/build.gradle.kts; git rm -q kuicksilver-bom/build.gradle.kts; commit "0.8 line, no BOM fallback"
git checkout -q -b release/0.9.x main; tree_version 0.9.0 0.9.0; printf '> This README describes 0.9.0, the release in preparation.\n' >> README.md; commit "0.9 line, README still says in preparation"
git checkout -q -b release/0.10.x main; tree_version 0.10.0 0.10.0; printf 'Until 0.10.0 is on Maven Central, build it from a checkout.\n' >> README.md; commit "0.10 line, README still has the build-it-yourself note"
git checkout -q -b release/0.15.x main; tree_version 0.15.0 0.15.0; printf '    .package(url: "https://github.com/kuicksilver/kuicksilver-swift", .upToNextMinor(from: "0.3.0")),\n' >> docs/guide/ios.md; commit "0.15 line, SwiftPM line in the iOS guide not moved"
git checkout -q main

pass=0; fail=0
t() { # <label> <ok|refuse>[:<pattern in the output>] <checkout target> <args...>
  local label="$1" exp="${2%%:*}" pat="" tgt="$3"; [ "$2" = "${2#*:}" ] || pat="${2#*:}"; shift 3
  git checkout -q $tgt || { echo "FAIL: checkout $tgt"; exit 2; }
  local out rc got verdict
  out=$(bash tools/release/local-release.sh "$@" 2>&1); rc=$?
  got=$([ $rc = 0 ] && echo ok || echo refuse)
  verdict=FAIL; if [ "$got" = "$exp" ] && { [ -z "$pat" ] || grep -qE -- "$pat" <<< "$out"; }; then verdict=ok; fi
  [ $verdict = ok ] && pass=$((pass+1)) || fail=$((fail+1))
  printf '%-4s %-58s exp=%-6s got=%-6s | %s\n' "$verdict" "$label" "$exp" "$got" \
    "$(grep -E 'REFUSED|WARN|STOPPED|note' <<< "$out" | sed 's/^ *//' | tr '\n' ' ' | cut -c1-230)"
}
M=$(git rev-parse main); B=$(git rev-parse release/0.2.x); BASE=$(git rev-parse main~1); F=$(git rev-parse feature)

# branches
t "main, 0.3.0"                                          ok:push_branch=main            main 0.3.0
t "main, 0.2.1 while release/0.2.x exists"               "refuse:release/0.2.x exists"  main 0.2.1
t "main, 0.3.1 (no release/0.3.x, tree is 0.3.0)"        "refuse:0.3.0-SNAPSHOT"        main 0.3.1
t "release/0.2.x, 0.2.1"                                 ok:push_branch=release/0.2.x   release/0.2.x 0.2.1
t "release/0.2.x, 0.2.2 without the version bump"        "refuse:0.2.1-SNAPSHOT"        release/0.2.x 0.2.2
t "release/0.2.x, 0.2.2-rc1 without the version bump"    "refuse:0.2.1-SNAPSHOT"        release/0.2.x 0.2.2-rc1
t "release/0.4.x, 0.4.0-rc1 (coordinates not checked)"   ok:push_branch=release/0.4.x   release/0.4.x 0.4.0-rc1
t "release/0.2.x, 0.3.0"                                 "refuse:maintenance branch of" release/0.2.x 0.3.0
t "release/0.2.x, 1.2.1"                                 "refuse:maintenance branch of" release/0.2.x 1.2.1
t "release/0.1.x, 0.2.1"                                 "refuse:maintenance branch of" release/0.1.x 0.2.1
t "feature, 0.2.1"                                       "refuse:not main or"           feature 0.2.1
# --release-commit
t "detached main tip, no --release-commit"               refuse                         "--detach $M" 0.3.0
t "--release-commit main tip, 0.3.0"                     ok:push_branch=main            "--detach $M" 0.3.0 --release-commit $M
t "--release-commit release/0.2.x tip, 0.2.1"            ok:push_branch=release/0.2.x   "--detach $B" 0.2.1 --release-commit $B
t "--release-commit release/0.2.x tip, 0.3.0"            refuse                         "--detach $B" 0.3.0 --release-commit $B
t "--release-commit fork point (both), 0.2.1"            ok:push_branch=release/0.2.x   "--detach $BASE" 0.2.1 --release-commit $BASE
t "--release-commit main-only commit, 0.2.1"             "refuse:not on release/0.2.x"  "--detach $M" 0.2.1 --release-commit $M
t "--release-commit not HEAD"                            refuse                         "--detach $B" 0.2.1 --release-commit $M
t "--release-commit on release/0.2.x checkout"           ok                             release/0.2.x 0.2.1 --release-commit $B
t "--release-commit feature-only commit"                 refuse                         "--detach $F" 0.2.1 --release-commit $F
# the tree's version coordinates
t "release/0.5.x, 0.5.0, README names 0.3.0"             "refuse:README.md"             release/0.5.x 0.5.0
t "release/0.6.x, 0.6.0, iOS guide names 0.3.0"          "refuse:docs/guide/ios.md"     release/0.6.x 0.6.0
t "release/0.7.x, 0.7.0, BOM fallback 0.3.0-SNAPSHOT"    "refuse:kuicksilver-bom"       release/0.7.x 0.7.0
t "release/0.8.x, 0.8.0, BOM fallback missing"           "refuse:kuicksilver-bom"       release/0.8.x 0.8.0
t "release/0.9.x, 0.9.0, README 'in preparation'"        "refuse:in preparation"        release/0.9.x 0.9.0
t "release/0.10.x, 0.10.0, README 'Until ... on Central'" "refuse:Until 0.10.0 is on Maven Central" release/0.10.x 0.10.0
# the Swift package (swift-package.sh prepare, before the gate): a tag of the version there means it is released already
KSL_SWIFT_REPO="$tmp/swift-tagged.git" t "Swift package already tagged 0.2.1" "refuse:tag 0.2.1 is already in" release/0.2.x 0.2.1
KSL_SWIFT_REPO="$tmp/no-such.git" t "Swift package repository unreachable" "refuse:Swift package cannot be prepared: cannot clone" release/0.2.x 0.2.1
KSL_SWIFT_REPO="$tmp/no-such.git" t "dry run: Swift package repository unreachable" "ok:WARN.*cannot clone" release/0.2.x 0.2.1 --dry-run
KSL_SWIFT_REPO="$tmp/swift-tagged.git" t "dry run: Swift package already tagged" "ok:WARN.*tag 0.2.1 is already in" release/0.2.x 0.2.1 --dry-run
t "Swift package prepared"                               "ok:prepared: .*no tag 0.2.1 yet" release/0.2.x 0.2.1
# the iOS guide's Swift package line names the version like its other coordinates
t "release/0.15.x, 0.15.0, iOS guide SwiftPM line 0.3.0" "refuse:docs/guide/ios.md names 0.15.0 0.3.0" release/0.15.x 0.15.0
# dry runs: refusals are warnings
t "dry run: release/0.2.x, 0.3.0"                        "ok:WARN.*maintenance branch"  release/0.2.x 0.3.0 --dry-run
t "dry run: feature, 0.2.1"                              ok:WARN                        feature 0.2.1 --dry-run
t "dry run: main, 0.2.1 while release/0.2.x exists"      "ok:WARN.*release/0.2.x exists" main 0.2.1 --dry-run
t "dry run: release/0.2.x, 0.2.2 without the bump"       "ok:WARN.*0.2.1-SNAPSHOT"      release/0.2.x 0.2.2 --dry-run
git push -q origin release/0.2.x
t "release/0.2.x after push: no note"                    ok                             release/0.2.x 0.2.1
t "--release-commit pushed branch tip: no note"          ok                             "--detach $B" 0.2.1 --release-commit $B
# a maintenance branch only on origin counts as well, fetched by the script in release mode
git push -q origin release/0.1.x:release/0.3.x; git update-ref -d refs/remotes/origin/release/0.3.x
t "main, 0.3.0, origin/release/0.3.x exists, not fetched" "refuse:release/0.3.x exists" main 0.3.0
git fetch -q origin
t "main, 0.3.0 while origin/release/0.3.x is fetched"        "refuse:release/0.3.x exists"  main 0.3.0
git push -q origin :release/0.3.x; git fetch -q --prune origin
t "main, 0.3.0 after origin/release/0.3.x is deleted"    ok:push_branch=main            main 0.3.0
# a local branch behind origin would release an older commit
git checkout -q -b ahead release/0.2.x; echo d > d; commit "pushed from elsewhere"; git push -q origin ahead:release/0.2.x
git checkout -q release/0.2.x; git branch -q -D ahead; git update-ref refs/remotes/origin/release/0.2.x "$B"   # not fetched yet
t "release/0.2.x behind origin (not fetched yet)"        "refuse:behind origin by 1 commit" release/0.2.x 0.2.1
t "--release-commit of the older tip: by design"         ok:push_branch=release/0.2.x   "--detach $B" 0.2.1 --release-commit $B
git fetch -q origin
t "dry run: behind origin, fetched (warning only)"      "ok:WARN.*behind origin by 1"  release/0.2.x 0.2.1 --dry-run
git push -q -f origin release/0.2.x; git fetch -q origin
t "release/0.2.x level with origin again"                ok:push_branch=release/0.2.x   release/0.2.x 0.2.1
# Maven Central (release mode only; a dry run may be offline)
t "0.2.0, already on Maven Central"                      "refuse:0.2.0 is already on Maven Central" release/0.2.x 0.2.0
t "dry run: 0.2.0, Central not asked"                    ok                             release/0.2.x 0.2.0 --dry-run
KSL_CENTRAL_STATUS=000 t "Central does not answer"        "refuse:could not ask Maven Central" release/0.2.x 0.2.1
KSL_CENTRAL_STATUS=503 t "Central answers 503"            "refuse:could not ask Maven Central" release/0.2.x 0.2.1
# CHANGELOG
t "CHANGELOG 0.2.9 - unreleased (placeholder)"           "refuse:no release date"       release/0.2.x 0.2.9
t "CHANGELOG [0.2.8] without date"                       "refuse:no release date"       release/0.2.x 0.2.8
t "CHANGELOG without 0.2.7"                              "refuse:has no '## \[0.2.7\]'" release/0.2.x 0.2.7
t "dry run: placeholder date (warning only)"             ok:WARN                        release/0.2.x 0.2.9 --dry-run
git checkout -q main

# tools/release/swift-package.sh against a local package repository; the maintainer's signing, tagging and pushing are
# done here as a plain tag and push (ptag)
sp_pass() { pass=$((pass+1)); printf 'ok   %s\n' "$1"; }
sp_fail() { fail=$((fail+1)); printf 'FAIL %s: %s\n' "$1" "$2"; }
sp() { # <label> <ok|refuse> <pattern|-> <prepare|finish> <args...>: runs swift-package.sh (output in $sp_out, checkout in $tmp/sp)
  local label="$1" exp="$2" pat="$3" rc; shift 3
  sp_out=$(KSL_SWIFT_REPO="${SP_REPO:-$tmp/sp.git}" bash "$root/tools/release/swift-package.sh" "$@" --out "$tmp/sp" 2>&1); rc=$?
  if [ "$([ $rc = 0 ] && echo ok || echo refuse)" != "$exp" ]; then sp_fail "$label" "exit $rc: $(tr '\n' ' ' <<< "$sp_out" | cut -c1-200)"
  elif [ "$pat" != - ] && ! grep -qE -- "$pat" <<< "$sp_out"; then sp_fail "$label" "no '$pat' in: $(tr '\n' ' ' <<< "$sp_out" | cut -c1-200)"
  else return 0; fi; return 1
}
ptag() { # <version> <branch>: what the maintainer does after finish (here unsigned)
  git -C "$tmp/sp" -c user.email=t@example.invalid -c user.name=t tag -a "$1" -m "Kuicksilver $1" && git -C "$tmp/sp" push -q --atomic "$tmp/sp.git" "$2" "refs/tags/$1"
}
git init -q --bare -b main "$tmp/sp.git"
S1=$(printf a | shasum -a 256 | cut -d' ' -f1); S2=$(printf b | shasum -a 256 | cut -d' ' -f1)
pkg_line() { sed -n "s/^ *$1: \"\(.*\)\",\{0,1\}$/\1/p" "$tmp/sp/Package.swift"; }
L="swift package: prepare leaves nothing committed"
if sp "$L" ok "prepared: .*branch main, no tag 0.3.0 yet" prepare 0.3.0; then
  if ! git -C "$tmp/sp" rev-parse -q --verify HEAD >/dev/null && [ -n "$(pkg_line checksum)" ]; then sp_pass "$L"; else sp_fail "$L" "a commit, or no rendered Package.swift"; fi
fi
L="swift package: first version into the empty repository"
if sp "$L" ok "commit [0-9a-f]+ on main, checksum $S1 \(unsigned, no tag yet\)" finish 0.3.0 "$S1" --source-commit 1234567; then
  if [ "$(pkg_line url)" = https://github.com/kuicksilver/kuicksilver/releases/download/v0.3.0/Kuicksilver.xcframework.zip ] && [ "$(pkg_line checksum)" = "$S1" ] \
      && ! git -C "$tmp/sp" rev-parse -q --verify refs/tags/0.3.0 >/dev/null && [ -f "$tmp/sp/LICENSE" ] && [ -f "$tmp/sp/licenses/LICENSE.openssl.txt" ] \
      && grep -q 'upToNextMinor(from: "0.3.0")' "$tmp/sp/README.md" && grep -q 'kuicksilver/kuicksilver@1234567' <<< "$(git -C "$tmp/sp" log -1 --format=%B)" \
      && [ "$(git -C "$tmp/sp" log -1 --format='%an <%ae> %G?')" = "kinchpik <339333647+kinchpik@users.noreply.github.com> N" ] \
      && grep -q 'git commit --amend --no-edit -S22C1F2E4FCE94B28EB2C7DB0492ABD95C8D0EC68' <<< "$sp_out" \
      && grep -q 'git tag -s -u 22C1F2E4FCE94B28EB2C7DB0492ABD95C8D0EC68 0.3.0 -m "Kuicksilver 0.3.0"' <<< "$sp_out" \
      && grep -q "git push --atomic https://github.com/kuicksilver/kuicksilver-swift.git main refs/tags/0.3.0" <<< "$sp_out" \
      && grep -qx "    cd $tmp/sp" <<< "$sp_out" \
      && grep -qx "    $(printf %q "$root")/tools/release/swift-package.sh finish 0.3.0 $S1 --source-commit 1234567" <<< "$sp_out"
  then sp_pass "$L"; else sp_fail "$L" "files, tag, author, signing or push lines wrong"; fi
fi
ptag 0.3.0 main
L="swift package: next version on top of the published one"
if sp "$L" ok "on main" finish 0.3.1 "$S2"; then
  if [ "$(git -C "$tmp/sp" rev-list --count main)" = 2 ] && [ "$(pkg_line checksum)" = "$S2" ]; then sp_pass "$L"; else sp_fail "$L" "history or checksum wrong"; fi
fi
ptag 0.3.1 main
sp "swift package: version already tagged" refuse "tag 0.3.0 is already in" finish 0.3.0 "$S2" && sp_pass "swift package: version already tagged"
sp "swift package: prepare refuses a tagged version" refuse "tag 0.3.1 is already in" prepare 0.3.1 && sp_pass "swift package: prepare refuses a tagged version"
sp "dry run: version already tagged (warning)" ok "WARN.*tag 0.3.0 is already in" finish 0.3.0 "$S2" --dry-run && sp_pass "dry run: version already tagged (warning)"
sp "swift package: older line with nothing below it" refuse "0.2.0 is older than every version" finish 0.2.0 "$S1" \
  && sp_pass "swift package: older line with nothing below it"
# an older line after a newer one: main stays on 0.3.x, 0.2.3 goes on release/0.2.x (a new branch, then on top of it)
git -C "$tmp/sp" checkout -q --orphan old && git -C "$tmp/sp" -c user.email=t@example.invalid -c user.name=t commit -q --allow-empty -m "0.2.2" \
  && git -C "$tmp/sp" tag 0.2.2 && git -C "$tmp/sp" push -q "$tmp/sp.git" refs/tags/0.2.2
L="swift package: older line on release/0.2.x from its newest tag"
if sp "$L" ok "branch release/0.2.x \(an older line than 0.3: main stays on the newest\)" finish 0.2.3 "$S1"; then
  if [ "$(git -C "$tmp/sp" rev-parse HEAD~1)" = "$(git -C "$tmp/sp" rev-parse '0.2.2^{commit}')" ] && grep -q "push --atomic https://github.com/kuicksilver/kuicksilver-swift.git release/0.2.x refs/tags/0.2.3" <<< "$sp_out" \
      && [ "$(git -C "$tmp/sp.git" rev-parse main)" = "$(git -C "$tmp/sp.git" rev-parse '0.3.1^{commit}')" ]
  then sp_pass "$L"; else sp_fail "$L" "base, push line or main wrong"; fi
fi
ptag 0.2.3 release/0.2.x
L="swift package: older line again on top of release/0.2.x"
if sp "$L" ok "on release/0.2.x" finish 0.2.4 "$S2"; then
  [ "$(git -C "$tmp/sp" rev-parse HEAD~1)" = "$(git -C "$tmp/sp" rev-parse '0.2.3^{commit}')" ] && sp_pass "$L" || sp_fail "$L" "not on top of 0.2.3"
fi
sp "swift package: a newer line moves main" ok "on main" finish 1.0.0 "$S1" && sp_pass "swift package: a newer line moves main"
ptag 1.0.0 main
# the first package release of an older line without a tag of its own: from the newest final version below it, not main
L="swift package: first release of an older line from the version below it"
if sp "$L" ok "on release/0.5.x" finish 0.5.0 "$S2"; then
  [ "$(git -C "$tmp/sp" rev-parse HEAD~1)" = "$(git -C "$tmp/sp" rev-parse '0.3.1^{commit}')" ] && sp_pass "$L" || sp_fail "$L" "not based on 0.3.1"
fi
sp "swift package: all-zero checksum" refuse "not the SHA-256" finish 0.3.2 0000000000000000000000000000000000000000000000000000000000000000 && sp_pass "swift package: all-zero checksum"
sp "swift package: short checksum" refuse "not the SHA-256" finish 0.3.2 c9e7447 && sp_pass "swift package: short checksum"
sp "swift package: malformed version" refuse "is not X.Y.Z" finish v0.3.2 "$S1" && sp_pass "swift package: malformed version"
SP_REPO="$tmp/no-such.git" sp "swift package: repository unreachable" refuse "cannot clone" prepare 0.3.2 && sp_pass "swift package: repository unreachable"
L="dry run: repository unreachable (a new one)"
if SP_REPO="$tmp/no-such.git" sp "$L" ok "WARN.*cannot clone" finish 0.3.2 "$S1" --dry-run; then
  [ "$(git -C "$tmp/sp" rev-list --count main)" = 1 ] && sp_pass "$L" || sp_fail "$L" "not a fresh history"
fi
L="swift package: prerelease (exact:)"
if sp "$L" ok "on main" finish 1.1.0-rc1 "$S1"; then
  grep -q 'exact: "1.1.0-rc1"' <<< "$sp_out" && grep -q 'exact: "1.1.0-rc1"' "$tmp/sp/README.md" && ! grep -q upToNextMinor "$tmp/sp/README.md" \
    && [ "$(pkg_line url)" = https://github.com/kuicksilver/kuicksilver/releases/download/v1.1.0-rc1/Kuicksilver.xcframework.zip ] \
    && sp_pass "$L" || sp_fail "$L" "requirement or URL wrong"
fi

# the local-gate check itself (local-release.sh from the marker line to the toolchain check) on fixture records: only a
# full run's passing stamp is a gate; a run of some steps (local-matrix.sh --only/--from) never is, whatever its file says
gate_block=$(awk -v m="$marker" '$0 ~ m {on = 1} /^# toolchains pinned/ {on = 0} on' "$root/tools/release/local-release.sh")
grep -q 'refuse' <<< "$gate_block" || { echo "FAIL: no local-gate check found after the marker line"; exit 2; }
gate_t() { # <label> <ok|refuse>[:<pattern>] <stamp lines...>: the check against build/ci/gate/<head>.stamp holding those lines
  local label="$1" exp="${2%%:*}" pat="" d out got verdict; [ "$2" = "${2#*:}" ] || pat="${2#*:}"; shift 2
  d="$tmp/gate-$pass-$fail"; mkdir -p "$d/build/ci/gate"; printf '%s\n' "$@" > "$d/build/ci/gate/c0ffee.stamp"
  out=$(cd "$d" && head=c0ffee short=c0ffee bash -c 'refuse() { echo "REFUSED: $*"; }; '"$gate_block" 2>&1)
  got=$(grep -q REFUSED <<< "$out" && echo refuse || echo ok)
  verdict=FAIL; if [ "$got" = "$exp" ] && { [ -z "$pat" ] || grep -qE -- "$pat" <<< "$out"; }; then verdict=ok; fi
  [ $verdict = ok ] && pass=$((pass+1)) || fail=$((fail+1))
  printf '%-4s %-58s exp=%-6s got=%-6s | %s\n' "$verdict" "$label" "$exp" "$got" "$(grep REFUSED <<< "$out" | tr '\n' ' ' | cut -c1-230)"
}
full=(commit=c0ffee tree=clean skip_android=0 skip_docker=0 with_interop=1 with_windows=1 steps=72 failed=0)
gate_t "gate: a full run's passing stamp"                     ok                               result=pass selection=all "${full[@]}"
gate_t "negative_gateFailedStamp"                             "refuse:did not pass"            result=fail selection=all "${full[@]}"
gate_t "negative_gatePartialRecordAsStamp"                    "refuse:did not pass"            result=partial-pass selection=only=25 "${full[@]}"
gate_t "negative_gatePassWithSelection"                       "refuse:only some steps"         result=pass selection=from=3 "${full[@]}"
gate_t "negative_gateNoSelectionLine"                         "refuse:only some steps"         result=pass "${full[@]}"
gate_t "negative_gateWithoutWindows"                          "refuse:without --with-windows"  result=pass selection=all "${full[@]/with_windows=1/with_windows=0}"

# the repository's own version files, so a pattern that drifts from their real layout is caught: the tree passes for the
# version of its fallbacks, except that before the release commit the README's status line names the last published
# version ("X.Y.Z is on Maven Central") while its dependency blocks and the iOS guide already name the line's version
new_repo "$tmp/real"
for f in build-logic/src/main/kotlin/kuicksilver.kmp.gradle.kts build-logic/src/main/kotlin/kuicksilver.release.gradle.kts \
    kuicksilver-bom/build.gradle.kts samples/realtime-telemetry/build.gradle.kts samples/ios/shared/build.gradle.kts \
    samples/ios/kuicksilver-swift/build.gradle.kts samples/compose-demo/build.gradle.kts \
    tools/check/consumer-smoke.sh README.md docs/guide/ios.md; do
  mkdir -p "$(dirname "$f")"; cp "$root/$f" "$f" || { echo "FAIL: $f is gone from the repository"; exit 2; }
done
line=$(sed -n 's/.*getOrElse("\([0-9]*\.[0-9]*\.[0-9]*\)-SNAPSHOT").*/\1/p' build-logic/src/main/kotlin/kuicksilver.kmp.gradle.kts)
published=$(sed -n 's/.* \([0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*\) is on Maven Central.*/\1/p' README.md | head -1)
printf '# Changelog\n\n## [%s] - 2026-01-01\n' "$line" > CHANGELOG.md; git add -A; git commit -qm real
# before the release the README names both versions and calls the line's version the release in preparation
want=""; [ "$published" = "$line" ] || want=$(printf 'README.md names %s instead of %s\nREADME.md still calls %s the release in preparation' \
  "$(printf '%s\n%s\n' "$published" "$line" | sort -u | tr '\n' ' ' | sed 's/ $//')" "$line" "$line")
want=$(grep . <<< "$want" | sort)
out=$(bash tools/release/local-release.sh "$line" --dry-run 2>&1)
have=$(grep 'WARN' <<< "$out" | sed -e 's/^ *WARN (a release would refuse): //' -e 's/ (the commit that prepares.*//' -e 's/ ("release in preparation".*//' | sort)
if [ -n "$line" ] && [ -n "$published" ] && [ "$have" = "$want" ]; then verdict=ok; pass=$((pass+1)); else verdict=FAIL; fail=$((fail+1)); fi
printf '%-4s %-58s line=%s published=%s | %s\n' "$verdict" "the repository's own version files" "$line" "$published" "$(tr '\n' ' ' <<< "${have:-no warning}")"
echo "passed $pass, failed $fail"
[ "$fail" = 0 ]
