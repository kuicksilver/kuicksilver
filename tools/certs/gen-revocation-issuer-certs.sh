#!/usr/bin/env bash
# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
# The issuer fixtures of the revocation test PKI (gen-revocation-certs.sh), for the staple check on the pause path (ksl_ocsp.c
# issuer_among): which certificate a stapled OCSP response is checked against when the platform's or an application's verifier
# decided trust. Made from rv-mid and rv-leaf-must-staple, so they are written next to the PKI's other DER files:
#   rv-imp-mid              an impostor of rv-mid: its name (/CN=rv-mid) and subject key identifier, so X509_check_issued takes it
#                           for the leaves' issuer, but another key: only the leaves' signatures tell it from rv-mid
#   ocsp-imp-must-staple    a "good" response for rv-leaf-must-staple whose certID names the impostor's key, signed by the impostor
#   rv-selfname-ca          a CA named /CN=rv-selfname
#   rv-selfname-leaf        a leaf it issued under its own name /CN=rv-selfname, without key identifiers and keyUsage, so
#                           X509_check_issued takes the leaf for its own issuer; its real issuer is the CA
#   rv-self                 a self-signed server certificate (the same key above and below)
# and the OCSPResponses that say nothing of a certificate (RFC 6960 section 4.2.1: no responseBytes), which a client takes for no
# staple:
#   ocsp-try-later          responseStatus tryLater (3), as Apache's mod_ssl staples while its responder is unreachable
#   ocsp-internal-error     responseStatus internalError (2)
# Called by gen-revocation-certs.sh with its work directory (rv-mid.pem, rv-leaf-must-staple.pem, the CA keys are not needed);
# alone it takes rv-mid and rv-leaf-must-staple from the committed DER files and leaves the rest of the PKI as it is.
# Usage: gen-revocation-issuer-certs.sh [work directory]   (OPENSSL: an OpenSSL 3.x or later CLI)
set -euo pipefail
root="$(cd "$(dirname "$0")/../.." && pwd)"
der="$root/kuicksilver-native/src/c/test/testdata/revocation"
O="${OPENSSL:-$(command -v openssl)}"; "$O" version | grep -Eq '^OpenSSL [3-9]' || { echo "need an OpenSSL 3.x CLI (set OPENSSL)"; exit 2; }
DAYS=36500
if [ $# -ge 1 ]; then cd "$1"; else
  work=$(mktemp -d); trap 'rm -rf "$work"' EXIT INT TERM HUP; cd "$work"
  for n in rv-mid rv-leaf-must-staple; do "$O" x509 -inform DER -in "$der/$n.der" -out "$n.pem"; done
fi
"$O" ecparam -name prime256v1 -genkey -noout -out rv-imp-mid.key
ski=$("$O" x509 -in rv-mid.pem -noout -ext subjectKeyIdentifier | tail -1 | tr -d ' ')
"$O" req -x509 -new -key rv-imp-mid.key -out rv-imp-mid.pem -days $DAYS -sha256 -subj "/CN=rv-mid" \
  -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" \
  -addext "subjectKeyIdentifier=$ski" 2>/dev/null
"$O" x509 -in rv-imp-mid.pem -outform DER -out "$der/rv-imp-mid.der"
printf 'V\t491231235959Z\t\t%s\tunknown\t/CN=rv-leaf-must-staple\n' "$("$O" x509 -in rv-leaf-must-staple.pem -noout -serial | cut -d= -f2)" > index-imp.txt
"$O" ocsp -issuer rv-imp-mid.pem -cert rv-leaf-must-staple.pem -no_nonce -reqout imp.req 2>/dev/null
"$O" ocsp -index index-imp.txt -CA rv-imp-mid.pem -rsigner rv-imp-mid.pem -rkey rv-imp-mid.key -reqin imp.req \
  -respout "$der/ocsp-imp-must-staple.der" -ndays $DAYS 2>/dev/null
"$O" ecparam -name prime256v1 -genkey -noout -out rv-selfname-ca.key
"$O" req -x509 -new -key rv-selfname-ca.key -out rv-selfname-ca.pem -days $DAYS -sha256 -subj "/CN=rv-selfname" \
  -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" 2>/dev/null
"$O" x509 -in rv-selfname-ca.pem -outform DER -out "$der/rv-selfname-ca.der"
"$O" ecparam -name prime256v1 -genkey -noout -out rv-selfname-leaf.key
"$O" req -new -key rv-selfname-leaf.key -out rv-selfname-leaf.csr -subj "/CN=rv-selfname" 2>/dev/null
printf 'basicConstraints=CA:FALSE\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:server.test\nsubjectKeyIdentifier=none\nauthorityKeyIdentifier=none\n' > selfname.ext
"$O" x509 -req -in rv-selfname-leaf.csr -CA rv-selfname-ca.pem -CAkey rv-selfname-ca.key -CAcreateserial -sha256 -days $DAYS \
  -out rv-selfname-leaf.pem -extfile selfname.ext 2>/dev/null
"$O" x509 -in rv-selfname-leaf.pem -outform DER -out "$der/rv-selfname-leaf.der"
"$O" ecparam -name prime256v1 -genkey -noout -out rv-self.key
"$O" req -x509 -new -key rv-self.key -out rv-self.pem -days $DAYS -sha256 -subj "/CN=rv-self" \
  -addext "basicConstraints=CA:FALSE" -addext "subjectAltName=DNS:server.test" 2>/dev/null
"$O" x509 -in rv-self.pem -outform DER -out "$der/rv-self.der"
printf '\x30\x03\x0a\x01\x03' > "$der/ocsp-try-later.der"
printf '\x30\x03\x0a\x01\x02' > "$der/ocsp-internal-error.der"
[ $# -ge 1 ] || bash "$root/tools/certs/gen-revocation-kt.sh"
