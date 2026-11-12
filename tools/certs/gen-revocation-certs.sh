#!/usr/bin/env bash
# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
# Generates the revocation test PKI (100-year validity) with its OCSP responses (RFC 6960, made by `openssl ocsp` from a CA
# index) and CRLs (RFC 5280, `openssl ca -gencrl`), as DER files in kuicksilver-native/src/c/test/testdata/revocation/ for
# the C tests and as RevocationCerts.kt for the kuicksilver-tls tests. Kept apart from gen-testcerts.sh so that the main test
# PKI is not regenerated. Only leaf keys are written (a server or client presents them); CA and responder keys stay in the
# temporary directory. Requires an OpenSSL 3.x CLI (Homebrew openssl@3 does). Usage: gen-revocation-certs.sh
#
# The PKI: rv-root <- rv-mid <- the leaves; rv-mid signs its own OCSP responses and CRLs, rv-responder is a delegated
# responder (id-kp-OCSPSigning) rv-mid issued, rv-responder-root one rv-root issued (not authorized for rv-mid's
# certificates, RFC 6960 section 4.2.2.2), rv-responder-noeku one rv-mid issued without the OCSPSigning purpose.
# The "stale" response expires one minute after it is made (stale to ksl six minutes after: five minutes of clock skew), the "stale" CRL expired in 2020; "nonext" has no nextUpdate.
set -euo pipefail
root="$(cd "$(dirname "$0")/../.." && pwd)"
der="$root/kuicksilver-native/src/c/test/testdata/revocation"
kt="$root/kuicksilver-tls/src/commonTest/kotlin/io/kuicksilver/tls/RevocationCerts.kt"
O="${OPENSSL:-$(command -v openssl)}"; "$O" version | grep -q '^OpenSSL 3' || { echo "need an OpenSSL 3.x CLI (set OPENSSL)"; exit 2; }
work=$(mktemp -d); trap 'rm -rf "$work"' EXIT INT TERM HUP; cd "$work"; mkdir -p "$der"; rm -f "$der"/*.der
DAYS=36500
key() { "$O" ecparam -name prime256v1 -genkey -noout -out "$1.key"; }
ca_root() { # name
  key "$1"
  "$O" req -x509 -new -key "$1.key" -out "$1.pem" -days $DAYS -sha256 -subj "/CN=Kuicksilver Revocation Test $1" \
    -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" 2>/dev/null
  "$O" x509 -in "$1.pem" -outform DER -out "$der/$1.der"
}
issue() { # name issuer kind(ca|server|client|ocsp|ocsp-noeku) [extra extension line]
  local name=$1 issuer=$2 kind=$3 extra=${4:-}
  key "$name"
  "$O" req -new -key "$name.key" -out "$name.csr" -subj "/CN=$name" 2>/dev/null
  case "$kind" in
    ca) printf 'basicConstraints=critical,CA:TRUE,pathlen:0\nkeyUsage=critical,keyCertSign,cRLSign\n' > "$name.ext" ;;
    server) printf 'basicConstraints=CA:FALSE\nkeyUsage=digitalSignature\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:server.test\n' > "$name.ext" ;;
    client) printf 'basicConstraints=CA:FALSE\nkeyUsage=digitalSignature\nextendedKeyUsage=clientAuth\nsubjectAltName=DNS:client.test\n' > "$name.ext" ;;
    ocsp) printf 'basicConstraints=CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=OCSPSigning\n' > "$name.ext" ;;
    ocsp-noeku) printf 'basicConstraints=CA:FALSE\nkeyUsage=critical,digitalSignature\n' > "$name.ext" ;;
  esac
  if [ -n "$extra" ]; then printf '%s\n' "$extra" >> "$name.ext"; fi
  "$O" x509 -req -in "$name.csr" -CA "$issuer.pem" -CAkey "$issuer.key" -CAcreateserial -sha256 -days $DAYS \
    -out "$name.pem" -extfile "$name.ext" 2>/dev/null
  "$O" x509 -in "$name.pem" -outform DER -out "$der/$name.der"
  case "$kind" in server|client) "$O" pkcs8 -topk8 -nocrypt -in "$name.key" -outform DER -out "$der/$name.key.der" ;; esac
}
serial() { "$O" x509 -in "$1.pem" -noout -serial | cut -d= -f2; }
subject() { "$O" x509 -in "$1.pem" -noout -subject -nameopt compat | sed 's/^subject=//'; }
ca_root rv-root
issue rv-mid rv-root ca
issue rv-leaf rv-mid server                                  # good
issue rv-leaf-revoked rv-mid server                          # revoked (OCSP and CRL)
issue rv-leaf-unlisted rv-mid server                         # not in the index: OCSP "unknown"
issue rv-leaf-must-staple rv-mid server "tlsfeature=status_request"  # RFC 7633 must-staple, good
issue rv-client rv-mid client                                # good
issue rv-client-revoked rv-mid client                        # revoked on the CRL
issue rv-responder rv-mid ocsp
issue rv-responder-root rv-root ocsp
issue rv-responder-noeku rv-mid ocsp-noeku
# the CA database of rv-mid (index.txt: status, expiry, revocation time, serial, file, subject)
row() { printf '%s\t491231235959Z\t%s\t%s\tunknown\t%s\n' "$1" "$2" "$(serial "$3")" "$(subject "$3")"; }
{ row V "" rv-leaf; row R "251101000000Z,keyCompromise" rv-leaf-revoked; row V "" rv-leaf-must-staple; row V "" rv-client
  row R "251101000000Z,keyCompromise" rv-client-revoked; row V "" rv-responder; row V "" rv-responder-noeku; } > index.txt
ocsp() { # out cert signer [validity args...]: the response rv-mid's index gives for cert, signed by signer
  local out=$1 cert=$2 signer=$3; shift 3
  "$O" ocsp -issuer rv-mid.pem -cert "$cert.pem" -no_nonce -reqout "$out.req" 2>/dev/null
  "$O" ocsp -index index.txt -CA rv-mid.pem -rsigner "$signer.pem" -rkey "$signer.key" -reqin "$out.req" -respout "$der/$out.der" "$@" 2>/dev/null
}
ocsp ocsp-good rv-leaf rv-mid -ndays $DAYS
ocsp ocsp-good-delegated rv-leaf rv-responder -ndays $DAYS
ocsp ocsp-revoked rv-leaf-revoked rv-mid -ndays $DAYS
ocsp ocsp-unknown rv-leaf-unlisted rv-mid -ndays $DAYS
ocsp ocsp-must-staple rv-leaf-must-staple rv-mid -ndays $DAYS
ocsp ocsp-stale rv-leaf rv-mid -nmin 1
ocsp ocsp-nonext rv-leaf rv-mid
ocsp ocsp-unauthorized rv-leaf rv-responder-root -ndays $DAYS
ocsp ocsp-noeku rv-leaf rv-responder-noeku -ndays $DAYS
# CRLs of rv-mid: current (100 years) and stale (2020); a CRL of rv-root that revokes nothing
cat > ca.cnf <<EOF
[ ca ]
default_ca = mid
[ mid ]
database = index.txt
default_md = sha256
crlnumber = crlnumber
EOF
echo 01 > crlnumber
"$O" ca -config ca.cnf -gencrl -keyfile rv-mid.key -cert rv-mid.pem -crldays $DAYS -out mid.crl 2>/dev/null
"$O" crl -in mid.crl -outform DER -out "$der/crl-mid.der"
"$O" ca -config ca.cnf -gencrl -keyfile rv-mid.key -cert rv-mid.pem -crl_lastupdate 20200101000000Z -crl_nextupdate 20200102000000Z -out mid-stale.crl 2>/dev/null
"$O" crl -in mid-stale.crl -outform DER -out "$der/crl-mid-stale.der"
: > index-root.txt; sed 's/index.txt/index-root.txt/' ca.cnf > ca-root.cnf
"$O" ca -config ca-root.cnf -gencrl -keyfile rv-root.key -cert rv-root.pem -crldays $DAYS -out root.crl 2>/dev/null
"$O" crl -in root.crl -outform DER -out "$der/crl-root.der"
mkdir -p "$(dirname "$kt")"
{
  printf '// Copyright 2026 The Kuicksilver Authors\n// SPDX-License-Identifier: Apache-2.0\n// generated by tools/certs/gen-revocation-certs.sh — do not edit\n@file:Suppress("ktlint", "MaxLineLength")\n\npackage io.kuicksilver.tls\n\nimport kotlin.io.encoding.Base64\n\n'
  printf '/** Revocation test PKI (100-year validity) with its OCSP responses and CRLs. */\ninternal object RevocationCerts {\n    private fun b64(s: String): ByteArray = Base64.decode(s)\n'
  for f in "$der"/*.der; do n=$(basename "$f" .der | perl -pe 's/\.key$/Key/; s/-([a-z0-9])/\u$1/g'); printf '    val %s: ByteArray by lazy { b64("%s") }\n' "$n" "$(base64 < "$f" | tr -d '\n')"; done
  printf '}\n'
} > "$kt"
echo "generated $(find "$der" -name "*.der" | wc -l | tr -d ' ') DER files and $kt"
