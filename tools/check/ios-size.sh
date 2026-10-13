#!/usr/bin/env bash
# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
# Size budget of Kuicksilver in an iOS app (docs/guide/ios.md, "Size"): builds the sample app for iphoneos arm64 in
# Release (unsigned), reads the linker map (LD_GENERATE_MAP_FILE in samples/ios/Config/Project.xcconfig) and sums the
# linked bytes per origin: OpenSSL, the ksl C shim, Kotlin (Kuicksilver, ktor-io/network, coroutines, stdlib and the
# Kotlin/Native runtime: one object in a release framework), and the app's own Swift. Also prints the stripped
# executable. Usage: tools/check/ios-size.sh [path to an existing link map]
# KUICKSILVER_GRADLE overrides the Gradle command the Xcode build runs.
set -euo pipefail
root="$(cd "$(dirname "$0")/../.." && pwd)"; cd "$root"
out="$root/samples/ios/build/xcode-device"
map="${1:-}"
if [ -z "$map" ]; then
  taskpolicy -b nice -n 19 xcodebuild -quiet -project samples/ios/KuicksilverSample.xcodeproj -scheme KuicksilverSample -configuration Release \
    -sdk iphoneos -destination "generic/platform=iOS" -derivedDataPath "$out" CODE_SIGNING_ALLOWED=NO build
  map=$(find "$out/Build/Intermediates.noindex" -name 'KuicksilverSample-LinkMap-normal-arm64.txt' | head -1)
fi
exe="$out/Build/Products/Release-iphoneos/KuicksilverSample.app/KuicksilverSample"
python3 - "$map" <<'PY'
import re, sys
files, sizes, kotlin, part = {}, {}, {}, None
def package(sym):
    # Kotlin/Native symbol names carry the package (_kfun:io.kuicksilver.quic.X#f, _kclass:..., _kvar:...)
    m = re.match(r"_k(?:fun|class|var|ifacetable|type)?[^:]*:(\S+)", sym)
    name = m.group(1) if m else ""
    for prefix, label in (("io.kuicksilver.", "Kuicksilver"), ("io.ktor.", "ktor-io / ktor-network"),
                          ("kotlinx.coroutines.", "kotlinx-coroutines"), ("kotlinx.io.", "kotlinx-io"),
                          ("kotlinx.atomicfu", "atomicfu"), ("kotlinx.serialization", "kotlinx-serialization"),
                          ("kotlin.", "Kotlin stdlib"), ("kotlinx.cinterop", "Kotlin stdlib"), ("platform.", "platform interop")):
        if name.startswith(prefix): return label
    return "K/N runtime, glue and data"
for line in open(sys.argv[1], encoding="utf-8", errors="replace"):
    if line.startswith("# Object files:"): part = "obj"; continue
    if line.startswith("# Sections:"): part = "sec"; continue
    if line.startswith("# Symbols:"): part = "sym"; continue
    if line.startswith("# Dead Stripped Symbols:"): break
    if part == "obj":
        m = re.match(r"\[\s*(\d+)\]\s+(.*)$", line.rstrip("\n"))
        if m: files[int(m.group(1))] = m.group(2)
    elif part == "sym":
        m = re.match(r"0x[0-9A-Fa-f]+\s+0x([0-9A-Fa-f]+)\s+\[\s*(\d+)\]\s*(.*)$", line)
        if m:
            idx, n = int(m.group(2)), int(m.group(1), 16)
            sizes[idx] = sizes.get(idx, 0) + n
            if "Shared.framework.o" in files.get(idx, ""):
                kotlin[package(m.group(3))] = kotlin.get(package(m.group(3)), 0) + n
def origin(path):
    member = path[path.rfind("(") + 1:-1] if path.endswith(")") else path.rsplit("/", 1)[-1]
    if "Shared.framework" in path:
        if re.match(r"lib(crypto|ssl|default|common)-lib-", member): return "OpenSSL (libssl + libcrypto, prefixed)"
        if member.startswith("ksl_"): return "ksl C shim (libksl)"
        return "Kotlin (Kuicksilver + ktor-io/network + coroutines + stdlib + K/N runtime)"
    if "linker synthesized" in path: return "linker"
    return "app (Swift) and other"
total = {}
for idx, n in sizes.items():
    o = origin(files.get(idx, "?")); total[o] = total.get(o, 0) + n
all_bytes = sum(total.values())
for o, n in sorted(total.items(), key=lambda kv: -kv[1]):
    print(f"{n / 1048576:8.2f} MB  {o}")
k = sum(n for o, n in total.items() if o.startswith(("OpenSSL", "ksl", "Kotlin")))
print(f"{k / 1048576:8.2f} MB  Kuicksilver's contribution (OpenSSL + ksl + Kotlin)")
print(f"{all_bytes / 1048576:8.2f} MB  everything the linker placed")
print("Kotlin, by package:")
for o, n in sorted(kotlin.items(), key=lambda kv: -kv[1]):
    print(f"{n / 1048576:8.2f} MB    {o}")
PY
if [ -f "$exe" ]; then
  tmp=$(mktemp); cp "$exe" "$tmp"; xcrun strip -x "$tmp" 2>/dev/null || true
  echo "executable: $(( $(stat -f %z "$exe") / 1024 )) KiB unstripped, $(( $(stat -f %z "$tmp") / 1024 )) KiB stripped (strip -x)"; rm -f "$tmp"
fi
