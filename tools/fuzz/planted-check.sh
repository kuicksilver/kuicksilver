#!/usr/bin/env bash
# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
# Negative controls of the HTTP/1.1 fuzz targets: copies the tree (tracked and untracked files that are not ignored) to
# build/planted-check/tree, plants known bugs in that copy, and runs the targets' regression inputs there
# (`client.h1Response`, `server.h1Request`). Each plant must make its target fail on the committed input written for it
# (tools/fuzz/gen-h1-seeds.py) with the expected message; a plant the target lets pass means the target no longer reaches
# that code or no longer reports what goes wrong there. The plants:
#   client-chunk   a client chunk of 0x1f3 bytes throws IllegalStateException     seed-chunk-1f3 of h1Response
#   client-lf      the line end after a field X-B is a bare LF                      seed-obsfold of h1Response
#   client-limit   a response head may take 64 bytes more than its limit           seed-head-over-limit of h1Response
#   client-length  a Content-Length 5 body gets one byte more                        seed-length of h1Response
#   client-head    the answer to HEAD is read as having a body                       seed-head-request of h1Response
#   server-chunk   a request chunk of 0x1f3 bytes throws IllegalStateException    seed-chunk-1f3 of h1Request
#                  (the pipeline answers it with a 400; the sequential pass must report it)
#   server-hang    a request chunk of 0x2a7 bytes waits 40 s before it is read    seed-chunk-2a7 of h1Request
#                  (the connection ends only after that wait: it is still open at virtual time 0)
#   server-content the 400 to a HEAD request carries content                         seed-refused-head of h1Request
#   server-head    a request head with the method BREW throws IllegalStateException  seed-second-head of h1Request
#                  (the second head of a connection: the pipeline answers it with a 400)
# To check that fuzzing finds a plant, not only the input written for it: delete that seed in the copy and run
# KSL_FUZZ_STATE=<dir> build/planted-check/tree/tools/fuzz/campaign.sh run --targets <id> --slice 5 --goal 0.1 --gap 0.
# Usage: tools/fuzz/planted-check.sh   (Gradle: ~/.kuicksilver-tools/quiet-gradle when present, else ./gradlew
#        --max-workers=2; KSL_GRADLE_ARGS adds arguments, e.g. "--offline -Pkuicksilver.openssl.prebuilt=true")
set -euo pipefail
root="$(cd "$(dirname "$0")/../.." && pwd)"
copy="$root/build/planted-check/tree"
rm -rf "$copy"; mkdir -p "$copy"
(cd "$root" && git ls-files -z --cached --others --exclude-standard) | (cd "$root" && rsync -a --from0 --files-from=- ./ "$copy/")
for f in local.properties samples/compose-demo/local.properties; do [ ! -f "$root/$f" ] || cp "$root/$f" "$copy/$f"; done
[ ! -d "$root/build/openssl" ] || { mkdir -p "$copy/build"; cp -R "$root/build/openssl" "$copy/build/"; }

python3 -I - "$copy" <<'PY'
import sys, os
root = sys.argv[1]
client = "kuicksilver-ktor-client/src/commonMain/kotlin/io/kuicksilver/ktor/client/h1/ChunkedBody.kt"
server = "kuicksilver-ktor-server/src/commonMain/kotlin/io/kuicksilver/ktor/server/h1/ChunkedBody.kt"
head = "kuicksilver-ktor-server/src/commonMain/kotlin/io/kuicksilver/ktor/server/h1/RequestHeadCheck.kt"
size = "            val chunkSize = parseChunkSize(input)\n"
rhead = "kuicksilver-ktor-client/src/commonMain/kotlin/io/kuicksilver/ktor/client/h1/ResponseHead.kt"
exchange = "kuicksilver-ktor-client/src/commonMain/kotlin/io/kuicksilver/ktor/client/h1/H1Exchange.kt"
pipeline = "kuicksilver-ktor-server/src/commonMain/kotlin/io/kuicksilver/ktor/server/h1/ServerPipeline.kt"
plants = [
    (pipeline, "            if (!head) bytes(BAD_REQUEST_BODY)\n", "            bytes(BAD_REQUEST_BODY)\n"),
    (exchange, "                val copied = input.copyTo(out, contentLength)\n",
     "                val copied = input.copyTo(out, contentLength)\n"
     "                if (contentLength == 5L) out.writeFully(byteArrayOf(0x21))\n"),
    (exchange, "                    request.method == HttpMethod.Head || status == HttpStatusCode.NotModified ||",
     "                    status == HttpStatusCode.NotModified ||"),
    (rhead, "        head.write(f)\n        head.write(CRLF)\n",
     "        head.write(f)\n"
     "        if (f.size >= 3 && f[0] == 'X'.code.toByte() && f[1] == '-'.code.toByte() && f[2] == 'B'.code.toByte()) {\n"
     "            head.write(byteArrayOf(LF))\n        } else {\n            head.write(CRLF)\n        }\n"),
    (rhead, "            if (taken == maxBytes) throw responseHeadTooLarge(maxBytes)\n",
     "            if (taken == maxBytes + 64) throw responseHeadTooLarge(maxBytes)\n"),
    (rhead, "            val window = minOf(from.size, (maxBytes - taken).toLong())\n",
     "            val window = minOf(from.size, (maxBytes + 64 - taken).toLong())\n"),
    (client, size, size + '            if (chunkSize == 0x1f3L) throw IllegalStateException("PLANTED-client-chunk")\n'),
    (server, size, size + '            if (chunkSize == 0x1f3L) throw IllegalStateException("PLANTED-server-chunk")\n'
                          '            if (chunkSize == 0x2a7L) kotlinx.coroutines.delay(40_000)\n'),
    (head, "internal suspend fun HeadLimitedInput.checkRequestHead() {\n    val buffer = readBuffer.buffer\n",
     "internal suspend fun HeadLimitedInput.checkRequestHead() {\n    val buffer = readBuffer.buffer\n"
     "    if (awaitContent(5) && buffer.size >= 5 && buffer[0] == 'B'.code.toByte() && buffer[1] == 'R'.code.toByte() &&\n"
     "        buffer[2] == 'E'.code.toByte() && buffer[3] == 'W'.code.toByte() && buffer[4] == ' '.code.toByte()\n"
     '    ) throw IllegalStateException("PLANTED-server-head")\n'),
]
for f, anchor, replacement in plants:
    p = os.path.join(root, f)
    s = open(p).read()
    if s.count(anchor) != 1:
        sys.exit(f"planted-check: the anchor in {f} is gone or not unique; update the plant")
    open(p, "w").write(s.replace(anchor, replacement))
PY

cd "$copy"
if [ -x "$HOME/.kuicksilver-tools/quiet-gradle" ]; then g=("$HOME/.kuicksilver-tools/quiet-gradle"); else g=(./gradlew --max-workers=2); fi
# shellcheck disable=SC2086 # KSL_GRADLE_ARGS is a list of arguments
"${g[@]}" ${KSL_GRADLE_ARGS:-} --continue \
  :kuicksilver-ktor-client:jvmTest --tests 'io.kuicksilver.ktor.client.fuzz.H1ResponseFuzzTest' \
  :kuicksilver-ktor-server:jvmTest --tests 'io.kuicksilver.ktor.server.fuzz.H1RequestFuzzTest' > "$copy/../gradle.log" 2>&1 || true

python3 -I - "$copy" <<'PY'
import sys, os, re, html
root = sys.argv[1]
results = "build/test-results/jvmTest/TEST-io.kuicksilver.ktor.{0}.fuzz.{1}.xml"
expect = [  # plant, module, class, input, text the failure must contain
    ("client-chunk", "kuicksilver-ktor-client", ("client", "H1ResponseFuzzTest"), "seed-chunk-1f3", "PLANTED-client-chunk"),
    ("client-lf", "kuicksilver-ktor-client", ("client", "H1ResponseFuzzTest"), "seed-obsfold", "an LF without CR"),
    ("client-limit", "kuicksilver-ktor-client", ("client", "H1ResponseFuzzTest"), "seed-head-over-limit", "a head that took"),
    ("client-length", "kuicksilver-ktor-client", ("client", "H1ResponseFuzzTest"), "seed-length", "for Content-Length 5"),
    ("client-head", "kuicksilver-ktor-client", ("client", "H1ResponseFuzzTest"), "seed-head-request", "a body for HEAD"),
    ("server-chunk", "kuicksilver-ktor-server", ("server", "H1RequestFuzzTest"), "seed-chunk-1f3", "PLANTED-server-chunk"),
    ("server-content", "kuicksilver-ktor-server", ("server", "H1RequestFuzzTest"), "seed-refused-head", "Connection: close"),
    ("server-hang", "kuicksilver-ktor-server", ("server", "H1RequestFuzzTest"), "seed-chunk-2a7", "still open"),
    ("server-head", "kuicksilver-ktor-server", ("server", "H1RequestFuzzTest"), "seed-second-head", "PLANTED-server-head"),
]
bad = 0
for plant, module, cls, case, text in expect:
    p = os.path.join(root, module, results.format(*cls))
    if not os.path.exists(p):
        print(f"FAIL {plant}: no test results ({p}); see build/planted-check/gradle.log"); bad += 1; continue
    found = None
    for m in re.finditer(r'<testcase name="([^"]*)"[^>]*?(/>|>(.*?)</testcase>)', open(p).read(), re.S):
        if case in m.group(1):
            found = html.unescape(m.group(3) or "")
    if found is None:
        print(f"FAIL {plant}: input {case} did not run"); bad += 1
    elif text not in found:
        print(f"FAIL {plant}: input {case} passed or failed otherwise (want '{text}')"); bad += 1
    else:
        print(f"ok   {plant}: {case} fails with '{text}'")
sys.exit(1 if bad else 0)
PY
