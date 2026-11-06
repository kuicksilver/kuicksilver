#!/usr/bin/env bash
# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
# Generates the weak-chain test PKI (100-year validity) for the security-level checks on a peer's chain (OpenSSL security
# level 2: keys of at least 112 security bits, no certificate signature under 112 bits but a self-signed anchor's), as DER
# files in kuicksilver-native/src/c/test/testdata/weak/ for the C tests and as WeakCerts.kt for the kuicksilver-tls tests.
# Kept apart from gen-testcerts.sh so that the main test PKI is not regenerated. As there, only leaf keys are written (a
# server presents them); CA keys stay in the temporary directory. Requires an OpenSSL 3.x CLI that still signs with MD5 and
# SHA-1 and makes RSA-1024, P-192 and P-224 keys (Homebrew openssl@3 does). Usage: gen-weak-certs.sh [cross]: without an
# argument every certificate is made anew; with `cross` only the cross-certificate group (the path a platform builds, T.5b)
# is, and the other DER files are kept as they are.
set -euo pipefail
only="${1:-}"; case "$only" in ""|cross) ;; *) echo "usage: gen-weak-certs.sh [cross]"; exit 2 ;; esac
root="$(cd "$(dirname "$0")/../.." && pwd)"
der="$root/kuicksilver-native/src/c/test/testdata/weak"; kt="$root/kuicksilver-tls/src/commonTest/kotlin/io/kuicksilver/tls/WeakCerts.kt"
O="${OPENSSL:-$(command -v openssl)}"; "$O" version | grep -q '^OpenSSL 3' || { echo "need an OpenSSL 3.x CLI (set OPENSSL)"; exit 2; }
work=$(mktemp -d); trap 'rm -rf "$work"' EXIT INT TERM HUP; cd "$work"; mkdir -p "$der"
if [ -z "$only" ]; then rm -f "$der"/*.der; else rm -f "$der"/cross-*.der "$der"/leaf-via-cross-*.der; fi
DAYS=36500
key() { # name spec: rsa:<bits> | ec:<curve>
  case "$2" in
    rsa:*) "$O" genpkey -algorithm RSA -pkeyopt "rsa_keygen_bits:${2#rsa:}" -out "$1.key" 2>/dev/null ;;
    ec:*) "$O" genpkey -algorithm EC -pkeyopt "ec_paramgen_curve:${2#ec:}" -pkeyopt ec_param_enc:named_curve -out "$1.key" 2>/dev/null ;;
  esac
}
root_ca() { # name keyspec digest
  key "$1" "$2"
  "$O" req -x509 -new -key "$1.key" -out "$1.pem" -days $DAYS -"$3" -subj "/CN=Kuicksilver Weak Test $1" \
    -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign" 2>/dev/null
  "$O" x509 -in "$1.pem" -outform DER -out "$der/$1.der"
}
issue() { # name issuer keyspec digest kind(ca|server|client) [subject: self-issued, without key identifiers] [days]
  local name=$1 issuer=$2 spec=$3 md=$4 kind=$5 subject=${6:-} days=${7:-$DAYS}
  key "$name" "$spec"
  "$O" req -new -key "$name.key" -out "$name.csr" -subj "${subject:-/CN=$name}" 2>/dev/null
  case "$kind" in
    ca) printf 'basicConstraints=critical,CA:TRUE,pathlen:0\nkeyUsage=critical,keyCertSign\n' > "$name.ext" ;;
    server) printf 'basicConstraints=CA:FALSE\nkeyUsage=digitalSignature\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:server.test\n' > "$name.ext" ;;
    client) printf 'basicConstraints=CA:FALSE\nkeyUsage=digitalSignature\nextendedKeyUsage=clientAuth\nsubjectAltName=DNS:client.test\n' > "$name.ext" ;;
  esac
  # subject = issuer and no SKID/AKID: OpenSSL flags it self-signed (EXFLAG_SS, v3_purp.c) without checking the signature
  if [ -n "$subject" ]; then printf 'subjectKeyIdentifier=none\nauthorityKeyIdentifier=none\n' >> "$name.ext"; fi
  "$O" x509 -req -in "$name.csr" -CA "$issuer.pem" -CAkey "$issuer.key" -CAcreateserial -"$md" -days "$days" -out "$name.pem" -extfile "$name.ext" 2>/dev/null
  "$O" x509 -in "$name.pem" -outform DER -out "$der/$name.der"
  if [ "$kind" != ca ]; then "$O" pkcs8 -topk8 -nocrypt -in "$name.key" -outform DER -out "$der/$name.key.der"; fi
}
self_leaf() { # name keyspec digest: a self-signed server certificate, as a Tofu peer presents
  key "$1" "$2"
  "$O" req -x509 -new -key "$1.key" -out "$1.pem" -days $DAYS -"$3" -subj "/CN=server.test" -addext "basicConstraints=critical,CA:FALSE" \
    -addext "keyUsage=digitalSignature" -addext "extendedKeyUsage=serverAuth" -addext "subjectAltName=DNS:server.test" 2>/dev/null
  "$O" x509 -in "$1.pem" -outform DER -out "$der/$1.der"; "$O" pkcs8 -topk8 -nocrypt -in "$1.key" -outform DER -out "$der/$1.key.der"
}
decoy() { # name keyspec subject: genuinely self-signed, the subject of a real intermediate, no key identifiers, so that
  # X509_check_issued takes it for that intermediate's issuer match although it signed nothing in the chain
  key "$1" "$2"
  "$O" req -x509 -new -key "$1.key" -out "$1.pem" -days $DAYS -sha256 -subj "$3" -addext "basicConstraints=critical,CA:TRUE" \
    -addext "keyUsage=critical,keyCertSign" -addext "subjectKeyIdentifier=none" -addext "authorityKeyIdentifier=none" 2>/dev/null
  "$O" x509 -in "$1.pem" -outform DER -out "$der/$1.der"
}
cross_cert() { # name subject-of key-of issuer digest: a CA certificate for another CA's name and key (a cross-certificate)
  "$O" req -new -key "$3.key" -out "$1.csr" -subj "$2" 2>/dev/null
  printf 'basicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign\n' > "$1.ext"
  "$O" x509 -req -in "$1.csr" -CA "$4.pem" -CAkey "$4.key" -CAcreateserial -"$5" -days $DAYS -out "$1.pem" -extfile "$1.ext" 2>/dev/null
  "$O" x509 -in "$1.pem" -outform DER -out "$der/$1.der"
}
if [ -z "$only" ]; then
root_ca weak-root ec:P-256 sha256          # the anchor of most chains below
root_ca rsa-root rsa:2048 sha256           # RSA, for an MD5 signature (no ECDSA with MD5 exists)
root_ca sha1-root ec:P-256 sha1            # a self-signed anchor signed with SHA-1: its own signature is never checked
root_ca rsa1024-root rsa:1024 sha256       # an anchor whose key is too small
issue leaf-rsa1024 weak-root rsa:1024 sha256 server         # leaf key 80 bits
issue leaf-rsa2048 weak-root rsa:2048 sha256 server         # leaf key 112 bits: the floor, accepted
issue leaf-p256 weak-root ec:P-256 sha256 server            # 128 bits, accepted
issue leaf-sha1 weak-root ec:P-256 sha1 server              # leaf signed with SHA-1
issue leaf-md5 rsa-root rsa:2048 md5 server                 # leaf signed with MD5 (RFC 9846 section 4.5.1.3: MUST be refused)
issue mid-rsa1024 weak-root rsa:1024 sha256 ca
issue leaf-via-rsa1024 mid-rsa1024 ec:P-256 sha256 server   # intermediate key 80 bits
issue mid-p192 weak-root ec:P-192 sha256 ca
issue leaf-via-p192 mid-p192 ec:P-256 sha256 server         # intermediate key 96 bits (P-192)
issue mid-p224 weak-root ec:P-224 sha256 ca
issue leaf-via-p224 mid-p224 ec:P-256 sha256 server         # intermediate key 112 bits (P-224): accepted
issue mid-sha1 weak-root ec:P-256 sha1 ca
issue leaf-via-sha1 mid-sha1 ec:P-256 sha256 server         # intermediate signed with SHA-1
issue leaf-under-sha1-root sha1-root ec:P-256 sha256 server # presented with its SHA-1 self-signed root: accepted
issue leaf-under-rsa1024-root rsa1024-root ec:P-256 sha256 server  # presented with its 1024-bit root: refused
issue client-rsa1024 weak-root rsa:1024 sha256 client       # a client certificate with a key too small
# self-issued but not self-signed (EXFLAG_SS set, signature by the CA): their weak signatures must still be checked
issue leaf-self-issued-md5 rsa-root rsa:2048 md5 server "/CN=Kuicksilver Weak Test rsa-root"
issue mid-self-issued-sha1 weak-root ec:P-256 sha1 ca "/CN=Kuicksilver Weak Test weak-root"
issue leaf-via-self-issued-sha1 mid-self-issued-sha1 ec:P-256 sha256 server
decoy decoy-sha1 ec:P-256 "/CN=mid-sha1"                    # sent between leaf-via-sha1 and mid-sha1
decoy decoy-rsa1024 rsa:2048 "/CN=mid-rsa1024"              # sent between leaf-via-rsa1024 and mid-rsa1024
self_leaf self-signed-rsa1024 rsa:1024 sha256               # Tofu: a key too small, refused at first contact
self_leaf self-signed-sha1 ec:P-256 sha1                    # Tofu: SHA-1 on its own self-signature, accepted
fi
# T.5b: the path a platform builds. L <- I <- R, R a trust anchor, and an extra certificate X sent with them: R's name and key
# signed with SHA-1 by another root. X verifies I's signature, so a walk over the presented chain reaches it; a platform that
# anchors at R never puts it on its path. The leaf is made twice, for 100 years and for 800 days: SecTrust refuses a server
# certificate valid longer than 825 days under any anchor (gen-apple-trust-certs.sh); the Apple test evaluates at a fixed date.
root_ca cross-root ec:P-256 sha256                                       # R: the anchor
root_ca cross-other-root ec:P-256 sha256                                 # signs X; never trusted
issue cross-mid cross-root ec:P-256 sha256 ca                            # I
issue leaf-via-cross-mid cross-mid ec:P-256 sha256 server                # L
issue leaf-via-cross-mid-800d cross-mid ec:P-256 sha256 server "" 800    # L for SecTrust
cross_cert cross-root-by-sha1 "/CN=Kuicksilver Weak Test cross-root" cross-root cross-other-root sha1   # X
nb=$("$O" x509 -in leaf-via-cross-mid-800d.pem -noout -startdate | cut -d= -f2)
cross_verify_at=$(( $(date -j -u -f '%b %e %T %Y %Z' "$nb" +%s 2>/dev/null || date -u -d "$nb" +%s) + 86400 ))
mkdir -p "$(dirname "$kt")"
{
  printf '// Copyright 2026 The Kuicksilver Authors\n// SPDX-License-Identifier: Apache-2.0\n// generated by tools/certs/gen-weak-certs.sh — do not edit\n@file:Suppress("ktlint", "MaxLineLength")\n\npackage io.kuicksilver.tls\n\nimport kotlin.io.encoding.Base64\n\n'
  printf '/** Weak-chain test PKI (100-year validity): keys and signatures below and at OpenSSL security level 2. */\ninternal object WeakCerts {\n    private fun b64(s: String): ByteArray = Base64.decode(s)\n'
  for f in "$der"/*.der; do n=$(basename "$f" .der | perl -pe 's/\.key$/Key/; s/-([a-z0-9])/\u$1/g'); printf '    val %s: ByteArray by lazy { b64("%s") }\n' "$n" "$(base64 < "$f" | tr -d '\n')"; done
  printf '\n    /** Seconds since 1970 inside the validity of [leafViaCrossMid800d] (a day after its start), for SecTrust. */\n'
  printf '    const val crossVerifyAt: Long = %sL\n}\n' "$cross_verify_at"
} > "$kt"
echo "generated $(find "$der" -name "*.der" | wc -l | tr -d ' ') DER files and $kt"
