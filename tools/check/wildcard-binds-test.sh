#!/usr/bin/env bash
# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
# Negative controls of tools/check/wildcard-binds.py on a scratch tree. Fail: a connector block without host
# (tlsConnector, sslConnector, plainConnector, Ktor's connector), a tlsConnector call without a block, host = "0.0.0.0"
# and "::", a wildcard InetSocketAddress handed to a bind or an open directly or through a local val, Netty's .bind(0)
# and a bare .bind(), ServerSocket(port) and ServerSocket(port, backlog), DatagramSocket() and DatagramSocket(port), an
# interop server without host, the same in a Java file, in a harness module's main sources and in an androidDeviceTest
# set; Ktor's bind("0.0.0.0", 0), bind(port = 0) and bind { }, a named local = wildcard argument, DatagramSocket(a port
# variable), NIO bind(null) and bind(null, backlog), bind(localAddress = null), DatagramSocket(0, null),
# ServerSocket(0, 50, null), embeddedServer(Netty, port = 0) and embeddedServer(Netty, 0) (also a port variable) without host, bindTcp(selector, "0.0.0.0", 0), a wildcard
# val written over several lines, a file whose only loopback mention is [::1]; an allowlist entry that matches nothing
# (stale), one without a reason. Pass: the same binds on 127.0.0.1 or ::1,
# a host set inside a nested block, embeddedServer(Netty, 0, "127.0.0.1"), embeddedServer(Netty, environment), a null
# that is not the address, a wildcard bind in a file that never talks to loopback, a main source set, binds named
# in comments, KDoc and strings, the function definitions, another function named connector(...), a judged line.
# Usage: wildcard-binds-test.sh
set -uo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
r="$tmp/repo"; rc=0
t="kuicksilver-x/src/jvmTest/kotlin/x"
mkdir -p "$r/tools/check" "$r/$t" "$r/kuicksilver-x/src/commonMain/kotlin/x" "$r/kuicksilver-x/src/androidDeviceTest/kotlin/x" \
  "$r/kuicksilver-bench/src/commonMain/kotlin/x" "$r/kuicksilver-x/src/jvmTest/java/x"

cat > "$r/$t/Bad.kt" <<'EOF'
package x

class Bad {
    val a = embeddedServer(Kuicksilver, configure = { tlsConnector(identity) { port = 0 } }) {}            // BAD-tls-block
    val b = embeddedServer(Kuicksilver, configure = { tlsConnector(identity) }) {}                        // BAD-tls-noblock
    val c = embeddedServer(Kuicksilver, configure = { plainConnector { trustedGateway = true } }) {}      // BAD-plain
    val d = embeddedServer(Kuicksilver, configure = { connector { port = 0 } }) {}                        // BAD-ktor
    val e = embeddedServer(Netty, configure = { sslConnector(ks, "a", { p }, { p }) { port = 0 } }) {}   // BAD-ssl
    val f = tlsServer(connector = { host = "0.0.0.0" }) {}                                               // BAD-host4
    val g = tlsServer(connector = { host = "::" }) {}                                                    // BAD-host6
    suspend fun h() = QuicEndpoint.bind(InetSocketAddress("0.0.0.0", 0))                                 // BAD-quic
    suspend fun i() = DatagramIo.open(InetSocketAddress("::", 0))                                        // BAD-open6
    suspend fun j() {
        val wild = InetSocketAddress(if (v6) "::" else "0.0.0.0", 0)
        Http3Endpoint.bind(wild, config)                                                                  // BAD-val
    }
    fun k() = Bootstrap().group(g).bind(0)                                                                // BAD-netty
    fun l() = aSocket(selector).tcp().bind()                                                              // BAD-bare
    fun m() = java.net.ServerSocket(0)                                                                    // BAD-ss1
    fun n() = java.net.ServerSocket(0, 50)                                                                // BAD-ss2
    fun o() = java.net.DatagramSocket()                                                                   // BAD-ds0
    fun p() = java.net.DatagramSocket(4433)                                                               // BAD-ds1
    fun q() = HqInteropServer.start(identity(), port = 0, www = root, versions = v1)                      // BAD-interop
    suspend fun r() {
        val any = "0.0.0.0"
        QuicEndpoint.bind(InetSocketAddress(any, 0))                                                      // BAD-const
    }
    fun s() = java.nio.channels.ServerSocketChannel.open().bind(java.net.InetSocketAddress(8080))         // BAD-javaport
    fun t() = aSocket(selector).tcp().bind("0.0.0.0", 0)                                                  // BAD-ktor-host
    fun u() = aSocket(selector).udp().bind(port = 0)                                                      // BAD-ktor-port
    fun v() = aSocket(selector).tcp().bind { reuseAddress = true }                                        // BAD-ktor-lambda
    suspend fun w() = QuicEndpoint.bind(local = InetSocketAddress("0.0.0.0", 0), config = c)             // BAD-named
    fun x(listenPort: Int) = java.net.DatagramSocket(listenPort)                                          // BAD-ds-var
    fun y() = java.nio.channels.DatagramChannel.open().bind(null)                                         // BAD-nio-null
    fun z() = embeddedServer(Netty, port = 0) { }                                                         // BAD-embedded
    fun bt() = bindTcp(selector, "0.0.0.0", 0)                                                            // BAD-bindtcp
    fun ln() = aSocket(selector).udp().bind(localAddress = null)                                          // BAD-named-null
    fun nb() = java.nio.channels.ServerSocketChannel.open().bind(null, 50)                                // BAD-null-backlog
    fun dn() = java.net.DatagramSocket(0, null)                                                           // BAD-ds-null
    fun sn() = java.net.ServerSocket(0, 50, null)                                                         // BAD-ss-null
    fun ep() = embeddedServer(Netty, 0) { }                                                               // BAD-embedded-pos
    fun ev(serverPort: Int) = embeddedServer(Netty, serverPort, module = { })                             // BAD-embedded-var
    suspend fun ml() {
        val far =
            InetSocketAddress(
                "::",
                0,
            )
        QuicEndpoint.bind(far)                                                                            // BAD-multiline
    }
    fun stale() = "the stale entry below names a line that is not here"
    val target = "https://127.0.0.1:443/"
}
EOF
cat > "$r/kuicksilver-x/src/jvmTest/java/x/BadJava.java" <<'EOF'
package x;
class BadJava {
    java.net.ServerSocket s = new java.net.ServerSocket(0); // BAD-java
    String to = "127.0.0.1";
}
EOF
cat > "$r/kuicksilver-x/src/androidDeviceTest/kotlin/x/BadDevice.kt" <<'EOF'
package x
suspend fun device() = QuicEndpoint.bind(InetSocketAddress("0.0.0.0", 0)) // BAD-device
val peer = "localhost"
EOF
cat > "$r/kuicksilver-bench/src/commonMain/kotlin/x/BadBench.kt" <<'EOF'
package x
suspend fun bench() = QuicEndpoint.bind(InetSocketAddress("0.0.0.0", 0)) // BAD-bench
val lo = InetSocketAddress("127.0.0.1", 0)
EOF
cat > "$r/$t/OnlyBracketed.kt" <<'EOF'
package x
suspend fun bracketed() = QuicEndpoint.bind(InetSocketAddress("0.0.0.0", 0)) // BAD-bracketed
val url = "https://[::1]:4433/"
EOF
cat > "$r/$t/Good.kt" <<'EOF'
package x

/**
 * KDoc naming tlsConnector(identity) { port = 0 } and QuicEndpoint.bind(InetSocketAddress("0.0.0.0", 0)) does not count.
 */
class Good {
    // a comment: tlsConnector(identity) { port = 0 }, ServerSocket(0), .bind(0)
    val a = embeddedServer(Kuicksilver, configure = { tlsConnector(identity) { port = 0; host = "127.0.0.1" } }) {}
    val b = embeddedServer(Kuicksilver, configure = { tlsConnector(identity) {
        port = 0
        host = "::1"
        trust = TrustConfig.AnchoredCa(listOf(ca))
    } }) {}
    val c = embeddedServer(Kuicksilver, configure = { connector { host = "127.0.0.1"; port = 0 } }) {}
    val d = embeddedServer(Kuicksilver, configure = { plainConnector { if (x) { port = 1 }; host = "127.0.0.1" } }) {}
    suspend fun e() = QuicEndpoint.bind(InetSocketAddress("127.0.0.1", 0))
    suspend fun f() = DatagramIo.open(InetSocketAddress("::1", 0))
    fun g() = Bootstrap().bind(InetSocketAddress("127.0.0.1", 0))
    fun h() = java.net.ServerSocket(0, 50, java.net.InetAddress.getLoopbackAddress())
    fun i() = java.net.DatagramSocket(java.net.InetSocketAddress("127.0.0.1", 0))
    fun j() = HqInteropServer.start(identity(), port = 0, host = "127.0.0.1", www = root, versions = v1)
    val message = "use tlsConnector(identity) or a plain connector, not .bind(0)"
    fun tlsConnector(identity: Any) = Unit
    fun Configuration.plainConnector(block: () -> Unit) = Unit
    fun connector(name: String) = name
    val judged = QuicEndpoint.bind(InetSocketAddress("0.0.0.0", 4433)) // judged in the allowlist
    fun k() = aSocket(selector).tcp().bind("127.0.0.1", 0)
    fun l() = bindTcp(selector, "127.0.0.1", 0)
    fun m() = embeddedServer(Netty, port = 0, host = "127.0.0.1") { }
    fun m2() = embeddedServer(Kuicksilver, configure = { connector { host = "127.0.0.1"; port = 0 } }) { }
    fun m3() = embeddedServer(Netty, 0, "127.0.0.1") { }
    fun m4() = embeddedServer(Netty, 0, host = "::1") { }
    fun m5() = embeddedServer(Netty, environment)
    fun o1() = aSocket(selector).udp().bind(localAddress = InetSocketAddress("127.0.0.1", 0))
    fun o2() = java.nio.channels.ServerSocketChannel.open().bind(java.net.InetSocketAddress("127.0.0.1", 0), 0)
    fun o3() = java.net.DatagramSocket(0, java.net.InetAddress.getLoopbackAddress())
    fun o4() = Bootstrap().bind(InetSocketAddress("127.0.0.1", 0)).addListener(null)
    val address = java.net.InetSocketAddress("127.0.0.1", 0)
    fun n() = java.net.DatagramSocket(address)
    suspend fun before(local: InetSocketAddress) = QuicEndpoint.bind(local) // a parameter, not the val below
    suspend fun after() {
        val local = InetSocketAddress("0.0.0.0", 0)
        println(local)
    }
}
EOF
cat > "$r/$t/NoLoopback.kt" <<'EOF'
package x
// a wildcard server whose clients are elsewhere (a container): this file never talks to loopback
val s = tlsServer(connector = { host = "0.0.0.0" }) {}
suspend fun far() = QuicEndpoint.bind(InetSocketAddress("0.0.0.0", 0))
EOF
cat > "$r/kuicksilver-x/src/commonMain/kotlin/x/Main.kt" <<'EOF'
package x
public var host: String = "0.0.0.0"
suspend fun serve() = QuicEndpoint.bind(InetSocketAddress("0.0.0.0", 443))
val lo = "127.0.0.1"
EOF
cat > "$r/tools/check/wildcard-binds.allow" <<EOF
# header
$t/Good.kt | val judged = QuicEndpoint.bind(InetSocketAddress("0.0.0.0", 4433)) // judged in the allowlist | an example the gate must pass
$t/Bad.kt | fun gone() = QuicEndpoint.bind(InetSocketAddress("0.0.0.0", 0)) | a stale entry the gate reports
$t/Bad.kt | val x = 1 | short
EOF

out=$(python3 -I "$here/wildcard-binds.py" "$r"); status=$?
expect() { # a finding on the line carrying the marker
  local file=$1 marker=$2 line
  line=$(grep -n -- "$marker" "$r/$file" | head -1 | cut -d: -f1)
  if ! grep -q -- "^$file:$line: " <<< "$out"; then echo "FAIL: no finding for $marker ($file:$line)"; rc=1; fi
}
for m in BAD-tls-block BAD-tls-noblock BAD-plain BAD-ktor BAD-ssl BAD-host4 BAD-host6 BAD-quic BAD-open6 BAD-netty BAD-bare \
  BAD-ss1 BAD-ss2 BAD-ds0 BAD-ds1 BAD-interop BAD-const BAD-javaport BAD-ktor-host BAD-ktor-port BAD-ktor-lambda BAD-named \
  BAD-ds-var BAD-nio-null BAD-embedded BAD-bindtcp BAD-multiline BAD-named-null BAD-null-backlog BAD-ds-null BAD-ss-null \
  BAD-embedded-pos BAD-embedded-var; do expect "$t/Bad.kt" "$m"; done
line=$(grep -n "Http3Endpoint.bind(wild" "$r/$t/Bad.kt" | cut -d: -f1)
grep -q "^$t/Bad.kt:$line: " <<< "$out" || { echo "FAIL: no finding for a wildcard through a local val"; rc=1; }
expect "kuicksilver-x/src/jvmTest/java/x/BadJava.java" BAD-java
expect "kuicksilver-x/src/androidDeviceTest/kotlin/x/BadDevice.kt" BAD-device
expect "kuicksilver-bench/src/commonMain/kotlin/x/BadBench.kt" BAD-bench
expect "$t/OnlyBracketed.kt" BAD-bracketed
grep -q "wildcard-binds.allow:3: stale" <<< "$out" || { echo "FAIL: the stale allowlist entry is not reported"; rc=1; }
grep -q "wildcard-binds.allow:4: want" <<< "$out" || { echo "FAIL: an entry without a reason is not reported"; rc=1; }
for f in Good.kt NoLoopback.kt; do
  if grep -q "^$t/$f:" <<< "$out"; then echo "FAIL: findings in $f:"; grep "^$t/$f:" <<< "$out"; rc=1; fi
done
if grep -q "^kuicksilver-x/src/commonMain/" <<< "$out"; then echo "FAIL: a main source set was checked"; rc=1; fi
bad=$(grep -c -- "BAD-" "$r/$t/Bad.kt"); want=$((bad + 4 + 2)) # Bad.kt (its val case marked too), Java, device, bench; two allowlist problems
got=$(grep -c "^kuicksilver-\|wildcard-binds.allow:" <<< "$out")
[ "$got" -eq "$want" ] || { echo "FAIL: $got findings, want $want:"; echo "$out"; rc=1; }
[ "$status" -eq 1 ] || { echo "FAIL: exit $status with findings, want 1"; rc=1; }

# a clean tree passes
rm -f "$r/$t/Bad.kt" "$r/$t/OnlyBracketed.kt" "$r/kuicksilver-x/src/jvmTest/java/x/BadJava.java" "$r/kuicksilver-x/src/androidDeviceTest/kotlin/x/BadDevice.kt" \
  "$r/kuicksilver-bench/src/commonMain/kotlin/x/BadBench.kt"
sed -i.bak '3,4d' "$r/tools/check/wildcard-binds.allow"
out=$(python3 -I "$here/wildcard-binds.py" "$r"); status=$?
[ "$status" -eq 0 ] || { echo "FAIL: a clean tree fails (exit $status):"; echo "$out"; rc=1; }

[ "$rc" -eq 0 ] && echo "wildcard-binds-test: all passed"
exit $rc
