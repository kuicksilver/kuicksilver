/* Copyright 2026 The Kuicksilver Authors
 * SPDX-License-Identifier: Apache-2.0 */
/* Makes a signed OCSP response (RFC 6960) with given thisUpdate and nextUpdate, which `openssl ocsp` cannot set: the
 * "good" response for <leaf> issued by <issuer>, signed by <signer> with <signer key>, as DER. gen-revocation-certs.sh
 * builds it against the bundled OpenSSL (build/openssl/<host>) for a response that is stale when it is made.
 * Usage: ocsp-backdate <leaf.pem> <issuer.pem> <signer.pem> <signer.key> <thisUpdate> <nextUpdate> <out.der>
 *        (times as GeneralizedTime, e.g. 20200101000000Z) */
#include <stdio.h>
#include <openssl/err.h>
#include <openssl/ocsp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

static X509 *cert(const char *path) {
    FILE *f = fopen(path, "r");
    X509 *x = f ? PEM_read_X509(f, NULL, NULL, NULL) : NULL;
    if (f)
        fclose(f);
    return x;
}

int main(int argc, char **argv) {
    if (argc != 8) {
        fprintf(stderr, "usage: %s leaf.pem issuer.pem signer.pem signer.key thisUpdate nextUpdate out.der\n", argv[0]);
        return 2;
    }
    X509 *leaf = cert(argv[1]), *issuer = cert(argv[2]), *signer = cert(argv[3]);
    FILE *kf = fopen(argv[4], "r");
    EVP_PKEY *key = kf ? PEM_read_PrivateKey(kf, NULL, NULL, NULL) : NULL;
    if (kf)
        fclose(kf);
    ASN1_GENERALIZEDTIME *thisupd = ASN1_GENERALIZEDTIME_new(), *nextupd = ASN1_GENERALIZEDTIME_new();
    OCSP_BASICRESP *bs = OCSP_BASICRESP_new();
    OCSP_CERTID *id = leaf && issuer ? OCSP_cert_to_id(EVP_sha1(), leaf, issuer) : NULL;
    OCSP_RESPONSE *resp = NULL;
    unsigned char *der = NULL;
    int len = -1, rc = 1;
    if (signer && key && thisupd && nextupd && bs && id && ASN1_GENERALIZEDTIME_set_string(thisupd, argv[5]) == 1 &&
        ASN1_GENERALIZEDTIME_set_string(nextupd, argv[6]) == 1 &&
        OCSP_basic_add1_status(bs, id, V_OCSP_CERTSTATUS_GOOD, 0, NULL, thisupd, nextupd) != NULL &&
        OCSP_basic_sign(bs, signer, key, EVP_sha256(), NULL, 0) == 1 &&
        (resp = OCSP_response_create(OCSP_RESPONSE_STATUS_SUCCESSFUL, bs)) != NULL &&
        (len = i2d_OCSP_RESPONSE(resp, &der)) > 0) {
        FILE *out = fopen(argv[7], "wb");
        rc = out && fwrite(der, 1, (size_t)len, out) == (size_t)len ? 0 : 1;
        if (out && fclose(out) != 0)
            rc = 1;
        if (out && rc)
            remove(argv[7]); /* no partial file */
    }
    if (rc) {
        ERR_print_errors_fp(stderr);
        fprintf(stderr, "ocsp-backdate: failed\n");
    }
    OPENSSL_free(der);
    OCSP_RESPONSE_free(resp);
    OCSP_CERTID_free(id);
    OCSP_BASICRESP_free(bs);
    ASN1_GENERALIZEDTIME_free(thisupd);
    ASN1_GENERALIZEDTIME_free(nextupd);
    EVP_PKEY_free(key);
    X509_free(leaf);
    X509_free(issuer);
    X509_free(signer);
    return rc;
}
