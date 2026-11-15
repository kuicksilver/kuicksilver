#!/usr/bin/env bash
# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
# Negative controls of the stateful HTTP/3 fuzz target `h3Connection`: copies the tree (tracked and untracked files that
# are not ignored) to build/h3-planted-check/tree, plants one known bug at a time in that copy, and runs the target's
# seeded programs there (H3ConnectionSeededTest, the same H3Run as the Jazzer target). Each plant must make a program
# fail with the expected invariant; a plant the programs let pass means the target no longer reaches that code or no
# longer checks what goes wrong there. The plants:
#   goaway-id      the server's final GOAWAY names its last request instead of the one after it   RequestNotProcessed
#                  for a request the server application saw (RFC 9114 section 5.2)
#   qpack-capacity the decoder applies a dynamic table capacity 32 bytes below the encoder's        a QPACK error or
#                  tables that differ (RFC 9204 section 3.2)
#   credit-hold    the server no longer holds request streams' credit (Rapid Reset)                 more requests held
#                  than streams allowed (RFC 9114 section 10.5)
#   reset-leak     a request the server application resets stays registered                         requests left
# To check that fuzzing finds a plant, not only the seeded programs: plant it in the copy by hand, delete the seed corpus
# there and run KSL_FUZZ_STATE=<dir> build/h3-planted-check/tree/tools/fuzz/campaign.sh run --targets http3.h3Connection
# --slice 2 --goal 0.05 --gap 0.
# Usage: tools/fuzz/h3-planted-check.sh   (Gradle: ~/.kuicksilver-tools/quiet-gradle when present, else ./gradlew
#        --max-workers=2; KSL_GRADLE_ARGS adds arguments, e.g. "--offline -Pkuicksilver.openssl.prebuilt=true")
set -euo pipefail
root="$(cd "$(dirname "$0")/../.." && pwd)"
copy="$root/build/h3-planted-check/tree"
rm -rf "$copy"; mkdir -p "$copy"
(cd "$root" && git ls-files -z --cached --others --exclude-standard) | (cd "$root" && rsync -a --from0 --files-from=- ./ "$copy/")
for f in local.properties samples/compose-demo/local.properties; do [ ! -f "$root/$f" ] || cp "$root/$f" "$copy/$f"; done
[ ! -d "$root/build/openssl" ] || { mkdir -p "$copy/build"; cp -R "$root/build/openssl" "$copy/build/"; }
if [ -x "$HOME/.kuicksilver-tools/quiet-gradle" ]; then g=("$HOME/.kuicksilver-tools/quiet-gradle"); else g=(./gradlew --max-workers=2); fi
results="$copy/kuicksilver-http3/build/test-results/jvmTest/TEST-io.kuicksilver.http3.fuzz.H3ConnectionSeededTest.xml"

bad=0
for plant in goaway-id qpack-capacity credit-hold reset-leak; do
  python3 -I - "$copy" "$root" "$plant" <<'PY'
import sys, os
root, original, plant = sys.argv[1:4]
rt = "kuicksilver-http3/src/commonMain/kotlin/io/kuicksilver/http3/"
plants = {
    "goaway-id": (rt + "runtime/H3Session.shutdown.kt",
                  "    val id = if (maxRequestId < 0) 0 else maxRequestId + 4\n",
                  "    val id = if (maxRequestId < 0) 0 else maxRequestId\n"),
    "qpack-capacity": (rt + "qpack/QpackDecoder.kt",
                       "                table.setCapacity(c)\n",
                       "                table.setCapacity(if (c > 64) c - 32 else c)\n"),
    "credit-hold": (rt + "runtime/H3Session.kt",
                    "        if (isServer) quic.holdPeerStreamCredit()\n",
                    "        if (isServer && plantedOff()) quic.holdPeerStreamCredit()\n"),
    "reset-leak": (rt + "runtime/ServerRequestStream.kt",
                   "        session.scope.launch { done() }\n        applicationDone()\n",
                   "        applicationDone()\n"),
}
for f, _, _ in plants.values():  # every planted file as in the checkout, then this run's plant
    with open(os.path.join(original, f)) as src, open(os.path.join(root, f), "w") as dst:
        dst.write(src.read())
f, anchor, replacement = plants[plant]
p = os.path.join(root, f)
s = open(p).read()
if s.count(anchor) != 1:
    sys.exit(f"h3-planted-check: the anchor of {plant} in {f} is gone or not unique; update the plant")
s = s.replace(anchor, replacement)
if plant == "credit-hold":
    s += "\nprivate fun plantedOff() = false\n"
open(p, "w").write(s)
PY
  rm -f "$results"
  # shellcheck disable=SC2086 # KSL_GRADLE_ARGS is a list of arguments
  (cd "$copy" && "${g[@]}" ${KSL_GRADLE_ARGS:-} :kuicksilver-http3:jvmTest \
    --tests 'io.kuicksilver.http3.fuzz.H3ConnectionSeededTest' > "$copy/../gradle-$plant.log" 2>&1) || true
  [ ! -f "$results" ] || cp "$results" "$copy/../results-$plant.xml"
  python3 -I - "$results" "$plant" <<'PY' || bad=1
import sys, os, html
results, plant = sys.argv[1:3]
want = {
    "goaway-id": "but the server application saw it",
    "qpack-capacity": "QPACK",
    "credit-hold": "the server application holds",
    "reset-leak": "server requests left",
}[plant]
if not os.path.exists(results):
    sys.exit(print(f"FAIL {plant}: no test results; see build/h3-planted-check/gradle-{plant}.log") or 1)
text = html.unescape(open(results).read())
if want in text:
    print(f"ok   {plant}: a seeded program fails with '{want}'")
else:
    sys.exit(print(f"FAIL {plant}: no seeded program failed with '{want}'") or 1)
PY
done
exit $bad
