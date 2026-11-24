#!/usr/bin/env bash
# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
# Negative controls of tools/check/env-apis.py on a scratch repository: library code without name-service calls passes
# (a `hostname` parameter, a named argument, a comment, a string and samples do not count); Ktor's .hostname
# (also through an implicit receiver, the H1Request case), java.net's hostName and canonicalHostName,
# InetAddress.getLocalHost, the C gethostname / getnameinfo, a call inside a string template, a reference ::getHostName
# a Java source and a use in a test source set (commonTest, jvmTest) each fail; an allowlist entry with its count and reason lets that many uses of one file pass, one more
# fails, and an entry without a count or a reason, with an unknown api or with more than the file has fails.
# Usage: env-apis-test.sh
set -uo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
r="$tmp/repo"; rc=0
m="kuicksilver-x/src/commonMain/kotlin/x"
mkdir -p "$r/tools/check" "$r/$m" "$r/kuicksilver-x/src/jvmMain/java/x" "$r/kuicksilver-x/src/commonTest/kotlin/x" "$r/kuicksilver-x/src/jvmTest/kotlin/x" "$r/samples/s/src/commonMain/kotlin" "$r/kuicksilver-native/src/c"
git -C "$r" init -q
cat > "$r/$m/Ok.kt" <<'EOF'
// a.hostname in a comment
fun connect(hostname: String, port: Int) = Target(hostname = "x", port = port).also { println("$port .hostName") }
class Target(val hostname: String, val port: Int)
EOF
printf 'fun s(a: io.ktor.network.sockets.InetSocketAddress) = a.hostname\n' > "$r/samples/s/src/commonMain/kotlin/S.kt"
git -C "$r" add -A
expect() { # <0|1> <what> <pattern>
  python3 -I "$here/env-apis.py" "$r" > "$tmp/out.txt" 2>&1; local got=$?
  if [ "$got" = "$1" ] && grep -qF -- "$3" "$tmp/out.txt"; then echo "ok: $2"
  else echo "FAIL: $2 (exit $got, want $1 and '$3')"; sed 's/^/  | /' "$tmp/out.txt"; rc=1; fi
}
case_() { # <0|1> <what> <pattern> <path> <content>
  printf '%s\n' "$5" > "$r/$4"; git -C "$r" add -A
  expect "$1" "$2" "$3"
  git -C "$r" rm -q --cached "$4"; rm "$r/$4"
}
expect 0 "parameters, named arguments, comments, strings and samples pass" "0 use(s), 0 allowed, 0 finding(s)"
case_ 1 "negative: Ktor's .hostname" "$m/A.kt:1 | hostname |" "$m/A.kt" 'fun f(a: io.ktor.network.sockets.InetSocketAddress) = a.hostname'
case_ 1 "negative: hostname through an implicit receiver" "$m/A.kt:2 | hostname |" "$m/A.kt" \
'class R(val a: io.ktor.network.sockets.InetSocketAddress) {
    val h: String get() = with(a) { hostname }
}'
case_ 1 "negative: java.net's hostName" "| hostName |" "$m/A.kt" 'fun f(a: java.net.InetAddress) = a.hostName'
case_ 1 "negative: canonicalHostName" "| canonicalHostName |" "$m/A.kt" 'fun f(a: java.net.InetAddress) = a.canonicalHostName'
case_ 1 "negative: InetAddress.getLocalHost" "| getLocalHost |" "$m/A.kt" 'fun f() = java.net.InetAddress.getLocalHost()'
case_ 1 "negative: C gethostname" "| gethostname |" "kuicksilver-native/src/c/a.c" 'int f(char *b) { return gethostname(b, 64); }'
case_ 1 "negative: C getnameinfo" "| getnameinfo |" "kuicksilver-native/src/c/a.c" 'int f(void) { return getnameinfo(0, 0, 0, 0, 0, 0, 0); }'
case_ 1 "negative: a call inside a string template" "$m/A.kt:1 | hostname |" "$m/A.kt" 'fun f(a: io.ktor.network.sockets.InetSocketAddress) = error("peer ${a.hostname} is gone")'
case_ 1 "negative: a reference ::getHostName" "| getHostName( |" "$m/A.kt" 'val f = java.net.InetAddress::getHostName'
case_ 1 "negative: a Java source" "| getHostName( |" "kuicksilver-x/src/jvmMain/java/x/J.java" 'class J { String h(java.net.InetAddress a) { return a.getHostName(); } }'
case_ 1 "negative: a test source set's .hostname (the wildcard bind's reverse lookup)" "kuicksilver-x/src/commonTest/kotlin/x/T.kt:1 | hostname | a name-service call in library or test code" \
  "kuicksilver-x/src/commonTest/kotlin/x/T.kt" 'val f: suspend (io.ktor.network.sockets.InetSocketAddress) -> Boolean = { a -> ":" in a.hostname }'
case_ 1 "negative: a jvmTest getHostName" "| getHostName( |" "kuicksilver-x/src/jvmTest/kotlin/x/J.kt" 'fun f(a: java.net.InetSocketAddress) = a.getHostName()'
printf '%s | hostname | 1 | the address is always built from the literal text, so no lookup runs\n' "$m/A.kt" > "$r/tools/check/env-apis.allow"
case_ 0 "an allowlisted use passes" "1 use(s), 1 allowed, 0 finding(s)" "$m/A.kt" 'fun f(a: io.ktor.network.sockets.InetSocketAddress) = a.hostname'
case_ 1 "negative: a second use in an allowed file" "$m/A.kt:2 | hostname | 2 uses in the file (lines 1, 2), tools/check/env-apis.allow:1 allows 1" "$m/A.kt" \
'fun f(a: io.ktor.network.sockets.InetSocketAddress) = a.hostname
fun g(a: io.ktor.network.sockets.InetSocketAddress) = "peer ${a.hostname}"'
case_ 1 "negative: the allowlist names one api only" "| hostName |" "$m/A.kt" \
'fun f(a: io.ktor.network.sockets.InetSocketAddress, b: java.net.InetAddress) = a.hostname + b.hostName'
expect 1 "negative: an entry matching no use is stale" "| stale | $m/A.kt has 0 hostname use(s), the entry allows 1"
printf '%s | hostname | 1 |\n' "$m/A.kt" > "$r/tools/check/env-apis.allow"
case_ 1 "negative: an entry without a reason" "| allow | the entry needs" "$m/A.kt" 'fun f(a: io.ktor.network.sockets.InetSocketAddress) = a.hostname'
printf '%s | hostname | the address is always built from the literal text\n' "$m/A.kt" > "$r/tools/check/env-apis.allow"
case_ 1 "negative: an entry without a count" "| allow | the entry needs" "$m/A.kt" 'fun f(a: io.ktor.network.sockets.InetSocketAddress) = a.hostname'
printf '%s | resolve | 1 | the address is always built from the literal text\n' "$m/A.kt" > "$r/tools/check/env-apis.allow"
expect 1 "negative: an unknown api" "'resolve' is none of"
[ "$rc" = 0 ] && echo "all passed" || echo "FAILED"
exit "$rc"
