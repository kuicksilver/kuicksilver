# ADR-0019. OpenSSL 4.x and Encrypted Client Hello

Date: 2026-11-18. Status: accepted (owner decision 2026-11-18); the move to OpenSSL 4.1.0 is implemented (below, Implementation). Supersedes in part
[ADR-0002](0002-openssl-first-backend.md): its pin of the OpenSSL 3.5 LTS branch. The rest of ADR-0002 (OpenSSL as the
first backend, linked statically; the transport behind the `QuicCrypto` interface; BoringSSL as a possible fallback)
stands.

## Context

The owner took TLS Encrypted Client Hello (RFC 9849, with the `ech` parameter of HTTPS records, RFC 9848) into 0.3.0:
the peers that browsers and mobile platforms use ship it (Chrome over BoringSSL, Go's `crypto/tls` and through it
quic-go, Android's platform TLS), and without it the server name of every connection is visible on the path.

- **OpenSSL 3.5 has no ECH.** The pinned 3.5.9 has HPKE but no ECH API (no `ech.h`). ECH arrived in OpenSSL 4.0.0
  (2026-04-14) and is in 4.1.0: `SSL_set1_ech_config_list`, the `OSSL_ECHSTORE_*` functions, `SSL_CTX_set1_echstore`,
  `SSL_ech_get1_status`, `SSL_ech_get1_retry_config`, `SSL_OP_ECH_GREASE`. OpenSSL supports shared mode only, not split
  mode.
- **Support windows** (OpenSSL's release strategy): 3.5 LTS until 2030-04-08; 4.0 until 2027-05-14; 4.1 until
  2027-11-23; the next LTS, 4.2, is planned for April 2027.
- **What a move costs**, from an earlier build of `ksl` against 4.1.0 and the ECH spike of 2026-11-18 (a one-off
  experiment outside the repository, run on a copy of `ksl`):
  - The QUIC TLS interface `ksl` uses (`SSL_set_quic_tls_cbs` and its callbacks) is the same in 4.x, byte for byte in
    the headers.
  - `tools/openssl/build.sh` fails on 4.x: OpenSSL 4 creates `crypto/buildinf.h` read-only (mode 0444), and the script
    rewrites that file. The hosted `openssl-next` job, which builds 4.x weekly beside the pin
    (`gradle/openssl-next.toml`), most likely fails for the same reason.
  - `tools/openssl/configure-flags.txt` names four options 4.x removed (Configure only warns), and must not add
    `no-ech`.
  - `ksl` does not compile against 4.x with `no-deprecated`: `ksl_ocsp.c` uses `X509_STORE_get0_objects` and
    `X509_cmp_time`. Their replacement `X509_STORE_get1_objects` takes the store's lock itself, so the lock `ksl` takes
    around the call has to go, or it deadlocks.
  - The `ksl` C tests: 103 of 105 sections pass on 4.1.0 (all 105 on 3.5.9). Two revocation negatives fail:
    `revocation_stapling negative_client_mismatch` (the client sees no staple and the handshake passes, over QUIC, TLS
    1.3 and TLS 1.2) and `revocation_crls negative_crl_issuer_outside_path` (the handshake passes where
    CRL_SIGNATURE_FAILURE is expected). These are security regressions; their cause is not known yet.
  - Size on macOS arm64 (the JNI library, our flags): +9.6 % from 4.1.0 itself, +0.7 % more with the ECH API linked;
    `libcrypto.a` +7.1 %, `libssl.a` +15.3 %.
- **What the spike showed about ECH through `ksl`'s callbacks**: accepted ECH, key rotation, GREASE and rejection with
  retry configurations all work, apart from two OpenSSL 4.1.0 bugs and one gap in `ksl`:
  - **Bug A.** A client custom extension whose `add_cb` returns 0 ("do not send") makes the ECH ClientHello fail
    (`custom_ext_add: bad extension`, then an internal error). Every client context of `ksl` registers such an
    extension (`KSL_ABORT_EXT_TYPE` in `ksl_ctx.c`, used by `ksl_tcp_abort`), so every ECH handshake of `ksl` fails at
    once today. `ksl` can avoid it: register that extension only where it is needed, or abort another way.
  - **Bug B.** After a HelloRetryRequest, ECH fails with an internal error on the second ClientHello when the client
    sends any custom extension of its own. QUIC always sends one, the transport parameters, so every ECH handshake over
    QUIC that meets a HelloRetryRequest fails, and `ksl` cannot work around it. A patch of about 30 lines in two
    OpenSSL files (`ech-hrr-custom-ext.patch` of the spike) makes all 49 checks of the spike pass, HelloRetryRequest
    included. OpenSSL's own QUIC ECH test has no HelloRetryRequest.
  - **The name on rejection.** When the server rejects ECH, OpenSSL switches the name its verifier checks to the
    `public_name` of the ECH configuration, but `ksl_verify.c` checks the leaf against the inner name again and fails
    the handshake with `bad_certificate` instead of `ech_required`. `ksl_verify.c` must take the name OpenSSL checks on
    an ECH session, and the paused path of the platform verifiers (ADR-0012: Android, Apple, Windows) must hand that
    name to Kotlin, or they check the inner name too.

## Decision

- **Kuicksilver moves from OpenSSL 3.5 LTS to 4.1.x for 0.3.0, and to 4.2 LTS once it is released.** The pin in
  `gradle/openssl.toml` keeps its form: version, tarball SHA-256, signing key fingerprint; every target is built from
  the signature-checked tarball as before.
- **ECH in 0.3.0**: a client that takes the ECH configuration list from the origin's HTTPS record or from the application,
  retries once with the server's retry configurations, and sends GREASE ECH by default where it has none; a server in
  shared mode with key rotation and retry configurations. No split mode.
- **Bug A is worked around in `ksl`**: no client custom extension that declines to be sent on an ECH session; the bug is
  reported to OpenSSL as well.
- **Two carried OpenSSL patches, as an exception** (owner decisions 2026-11-18: bug B, then bug C). Until now the
  bundled OpenSSL has been the upstream release tarball exactly, checked by its signature and SHA-256 and nothing else.
  The build carries two minimal patches, applied in this order:
  1. `openssl-4.1.0-ech-hrr-custom-ext.patch` (bug B: ECH after a HelloRetryRequest with a client's own custom
     extension, which every QUIC client has). Upstream code: the `ssl/statem/extensions.c` hunk of OpenSSL commit
     openssl/openssl@981f976bb0 (pull request #33246, issue #33231), merged to master, openssl-4.1 and openssl-4.0 on 2026-11-13;
     dropped with 4.1.1, the first release that has it;
  2. `openssl-4.1.0-ech-hrr-rejection.patch` (bug C: a rejection after a HelloRetryRequest ends with `illegal_parameter`
     instead of the rejection path of RFC 9849 section 6.1.6). Upstream code until it merges: the
     `ssl/statem/statem_clnt.c` hunk of OpenSSL pull request #33233 (open, in review; the patch header records the PR
     head commit it was taken from); dropped with the first release that merges it.
  The rules for both:
  - both bugs are known upstream (B: issue #33231, fixed; C: pull request #33233), so nothing is filed; the patches carry
    upstream's code verbatim (source hunks only, the build has no tests), and each is dropped on its own condition
    above;
  - the patches live in the repository and are pinned by their SHA-256 next to the tarball's pin (`patch`,
    `patch_sha256`, then `patch_2`, `patch_2_sha256`); `tools/openssl/build.sh` applies them in that order to the
    verified tarball (`apply-patch.pl`, exactly, both or neither) and refuses a patch whose hash differs, and a second
    patch without a first;
  - the patches and their hashes are listed in the build's provenance (`provenance.txt`, the release provenance and the
    SBOM) and are part of the build cache's key and of `configure-target.txt`;
  - the reproducibility checks (the double build, `tools/verify/verify-release.sh`) rebuild with the same patches;
  - no further patch is carried without a new decision.
- **On rejection the certificate is checked against the `public_name`**, in `ksl_verify.c` and on the paused path of the
  platform verifiers alike.
  The implementation comes with the move to 4.1.x, not with this ADR.

## Consequences

- **A non-LTS window.** From 0.3.0 until 4.2 LTS ships, the bundled OpenSSL is a release with a short support window
  (4.1 until 2027-11-23). The move to 4.2 is a planned patch release; until then the commitments of SECURITY.md for
  OpenSSL advisories apply to 4.1.x unchanged.
- **The move is not a version bump.** Before the pin changes: `build.sh` removes the read-only `crypto/buildinf.h`
  before rewriting it (which also fixes the `openssl-next` job), `configure-flags.txt` drops the removed options,
  `ksl_ocsp.c` moves to the non-deprecated calls without its own store lock, the bug A workaround and the
  `public_name` check land, and the two failing revocation negatives are root-caused and fixed. Until they pass,
  the switch does not happen: they guard revocation checks this project made a security property (threat model 3.6a).
- **Binary size** grows (about 10 % for the JNI library in the measurement above); the size gates of the AAR, the iOS
  framework and the JNI libraries are measured again and their limits changed only by decision.
- **Reproducibility**: a new pin (tarball, signature, SHA-256), a reviewed `configure-flags.txt`, and new baselines for
  the double build and for `tools/verify/verify-release.sh`; releases before 0.3.0 keep verifying against their own pin.
- **Documents and checks that name 3.5** change with the move: SECURITY.md (OpenSSL), docs/stability.md, the README,
  the troubleshooting text of `KslException.Version`, and the system-OpenSSL build mode on Linux, which today refuses
  4.x and will then need 4.x for ECH.
- **A patched OpenSSL until upstream fixes the bug.** A user who verifies a release no longer gets the upstream tarball
  alone: the published OpenSSL is that tarball plus two patches whose hashes are pinned and listed in the provenance, and
  `verify-release.sh` applies them before comparing. The patches are reviewed like our own code, and every OpenSSL update
  checks whether each is still needed.

## Alternatives rejected

- **Two builds, 3.5 by default and 4.1 for ECH.** Every native target built twice, two reproducibility baselines, and a
  feature that silently depends on which artifact a user picked.
- **Backporting ECH to 3.5.** About 4000 lines in `ssl/ech` plus state-machine changes, carried as our own patch for
  years: far beyond the one bug fix of about 30 lines that this ADR allows, temporarily.
- **BoringSSL or AWS-LC.** Mature ECH, but the QUIC glue of `ksl` would be rewritten (`SSL_set_quic_method` instead of
  `SSL_set_quic_tls_cbs`) together with the ticket, 0-RTT and verification-pause code; BoringSSL has no versions. Not for
  0.3.0; ADR-0002's fallback stays a possibility.
- **Waiting for 4.2 LTS.** No non-LTS window, but no ECH in 0.3.0, against the owner's decision.
- **Shipping 4.1.x unpatched and documenting the failure after a HelloRetryRequest.** ECH over QUIC would fail whenever
  a server answers with a HelloRetryRequest (another key exchange group), and retrying without ECH would reveal the
  server name; the owner chose the patch.

## Implementation

### The move to 4.1.0 (2026-11-18)

- **Pin.** `gradle/openssl.toml` names 4.1.0: the tarball's SHA-256 is the one of the release's own `.sha256` file, and its
  signature verifies with the vendored release key (`tools/openssl/openssl-release-key.asc`), made by the signing subkey
  `C46ED3F2CBEFDA1FDAADA44264ED7B1DCCE71CB2` of the pinned primary `B146647E45A7B33947AB226B2A2C87D161692D40`.
- **Build.** `build.sh` removes the read-only `crypto/buildinf.h` before rewriting it; `configure-flags.txt` no longer names
  `no-engine`, `no-atexit`, `no-ssl3` and `no-ssl3-method` (removed in 4.0: engines, `OPENSSL_atexit` and SSLv3 are gone),
  and does not name `no-ech`.
- **`ksl`.** `ksl_ocsp.c` takes the CRLs of the store with `X509_STORE_get1_objects`, which takes the store's lock itself,
  so the lock `ksl` held around the call is gone (holding it would deadlock); a snapshot that cannot be made counts as
  "listed", so the delegated responder in question is refused (fail closed). A responder certificate's validity is read
  with `ASN1_TIME_cmp_time_t`; a time that does not parse refuses the responder (`X509_cmp_time` answered 0 for it, which
  passed).
- **The two revocation negatives.** Both are changes in OpenSSL, not in `ksl`'s client checks:
  - `negative_client_mismatch`: since 3.6 an OpenSSL server staples a response only when one of its single responses
    names the certificate it sends by serial number and issuer name hash (`ssl/statem/statem_srvr.c`,
    `ossl_get_ocsp_response`, the TLS 1.3 multi-stapling support), so the test server, which forced another
    certificate's response, sent none and the client had nothing to refuse. The test now forces a response for the
    leaf's serial and issuer name under another issuer key (`ocsp-other-issuer-key`, from the regenerated revocation
    PKI): the OpenSSL server staples it and the client refuses it, as before, because it compares the whole certID (RFC
    6960 section 3.2, 1). A response for another serial is asserted not to be stapled at all.
  - `negative_crl_issuer_outside_path`: OpenSSL 4 checks the CRLs of a partial chain only below its trust anchor
    (`crypto/x509/x509_vfy.c`, `revocation_check_end`: `num_untrusted - 1` under `X509_V_FLAG_PARTIAL_CHAIN`), where 3.5
    checked the anchor too under `X509_V_FLAG_CRL_CHECK_ALL`. So an `AnchoredCa` whose root is an intermediate was no
    longer checked against its issuer's configured CRL: neither the documented fail-closed case (the CRL's issuer is
    not among the roots) nor an intermediate that the root's CRL revokes (`negative_crl_anchor_revoked`, new). `ksl`
    now checks such an anchor itself (`ksl_ocsp.c`, `anchor_status`): when a configured CRL names the anchor's issuer, the
    anchor is verified on its own as the target of a path without `PARTIAL_CHAIN` against the same store, time and
    security level with `X509_V_FLAG_CRL_CHECK`, and a CRL error of that check fails the handshake; a path that does not
    build leaves the CRL unverifiable (`X509_V_ERR_CRL_SIGNATURE_FAILURE`, decrypt_error, as before).
- **Size** (macOS arm64, the JNI library of the JVM artifact, `-Os`, stripped as released): 2,544,072 bytes on 3.5.9,
  2,809,416 on 4.1.0 (+265,344, +10.4 %); `libcrypto.a` 5,170,512 → 5,539,528 (+7.1 %), `libssl.a` 804,048 → 926,824
  (+15.3 %). The size gates are measured again on the matrix; their limits change only by decision.

### The carried patch for bug B

- **The patch.** `tools/openssl/patches/openssl-4.1.0-ech-hrr-custom-ext.patch`, one hunk in
  `ssl/statem/extensions.c` (`tls_construct_extensions`): the SENT and RECEIVED flags of the custom extensions are reset
  at the start of every inner ClientHello (`ch_depth == 1`), the second one after a HelloRetryRequest included, where
  4.1.0 resets them only without ECH. Since 2026-11-18 it is upstream's hunk of commit openssl/openssl@981f976bb0 verbatim (it replaced
  the bug-B half of the spike's patch, which differed only in its comment; both compile to the same `extensions.o`);
  bug A is not patched (below). Its text starts with a description naming the commit, the bug and the fix.
- **Pinned and applied.** `gradle/openssl.toml` names the file (`patch`) and its SHA-256 (`patch_sha256`).
  `tools/openssl/build.sh` refuses a patch whose hash differs before it looks at anything else, copies the verified
  tree and applies the patch with `tools/openssl/apply-patch.pl` (Perl, which every build image has; no fuzz, no
  offset, every hunk at the line it names, nothing written unless every hunk matches). The hash is part of the build
  cache key, of the target line (`patch-sha256=<first 16 hex digits>` in `configure-target.txt` and `--print-target`)
  and of `provenance.txt`, which `-Pkuicksilver.openssl.prebuilt` compares; the release provenance
  (`tools/release/provenance.py`) lists the file and its hash, the SBOM's OpenSSL component carries the property
  `kuicksilver:openssl:patch`. The double build and `verify-release.sh` run the same `build.sh`, so they apply it too.
  `tools/openssl/apply-patch-test.sh` (CI lint) keeps the applier exact and the hash check in place.
- **Leaving.** Renovate's note for an OpenSSL update says to check the release for the fix: the patch, its two pin
  lines and the file go with 4.1.1 (`patch_2` then becomes `patch`). `gradle/openssl-next.toml` carries the same lines while it
  names a release without the fix, so the `openssl-next` job tests what would ship.
- **Upstream.** Bug B is OpenSSL issue #33231, fixed by openssl/openssl@981f976bb0; bug A is issue #33487 with pull request #33532 in
  review. Nothing is filed from here.

### ECH in `ksl` (2026-11-18)

- **API** (additive under ABI 7, numbered from 15 so that the other 0.3.0 additions keep the numbers below):
  `KSL_OPT_ECH_GREASE` (15), `KSL_SET_ECH_CONFIG_LIST` (15), `KSL_GET_ECH_STATUS` (15), `KSL_GET_ECH_RETRY_CONFIGS` (16),
  `KSL_GET_VERIFY_NAME` (17), `ksl_ech_config_list_check` and `ksl_ctx_set_ech_keys` (`kuicksilver-native/src/c/ksl.h`,
  `ksl_ech.c`).
- **Bug A, worked around in `ksl`.** `ksl_tcp_abort`'s ClientHello extension is registered only on a client context that
  allows TLS 1.2 (`KSL_OPT_MIN_VERSION KSL_TLS1_2`), the only one where a renegotiation can happen; such a context takes
  no ECH configuration (`KSL_E_NOT_SUPPORTED`). ECH never needs TLS 1.2, and GREASE ECH is not affected (OpenSSL does not
  build an inner ClientHello for it). Kuicksilver contexts are TLS 1.3 only unless `TlsVersions.Tls12And13` is chosen
  for TCP.
- **The ECHConfigList is checked entry by entry.** OpenSSL refuses a whole list for one ECHConfig it cannot use (another
  version is skipped, but an unsupported KEM, suite or mandatory extension, or a bad `public_name`, fails the list),
  where RFC 9849 ignores that ECHConfig alone; `ksl_ech_config_list_check` hands each entry to OpenSSL as a list of one
  and keeps those it takes. It is the one ECH parser of `ksl` (fuzz mode `0xfc`).
- **The name on rejection.** `ksl_match_leaf` takes the name OpenSSL verifies (`X509_VERIFY_PARAM` host, which OpenSSL
  replaces by the `public_name` on rejection), and `KSL_GET_VERIFY_NAME` hands it to the paused path.
- **Rotation.** The keys are an `OSSL_ECHSTORE` held by the context and replaced whole under a lock, also on a frozen
  context; every session takes its own copy when it is made (`SSL_set1_echstore`), so `SSL_CTX_set1_echstore`, which
  swaps the context's store without a lock, is never used.
- **System OpenSSL.** ECH is compiled only with the bundled OpenSSL 4 (`KSL_HAS_ECH`): the system-OpenSSL build mode keeps
  its range of 3.5 to 3.x, which has no ECH, and a system 4.x would lack the carried patch. Such a build reports ECH
  unavailable.
- **Bug C (found 2026-11-18; the second carried patch, owner decision 2026-11-18).** After a HelloRetryRequest, OpenSSL
  4.1.0's client takes any `encrypted_client_hello` extension in the HelloRetryRequest for an acceptance
  (`statem_clnt.c`: `hrrsignal_p != NULL`), and a server that rejects ECH may send one with eight random bytes (RFC 9849
  section 7.1; OpenSSL's own server does: `extensions_srvr.c`, `tls_construct_stoc_ech`). The client then ended the
  handshake with `illegal_parameter` at the ServerHello instead of authenticating the `public_name` and sending
  `ech_required` with the retry configurations, so a client whose configuration was out of date could not recover when
  the server also asked for another key share. The same path ran the fallback to the `public_name` twice, the second time
  overwriting (and leaking) the saved inner name. `openssl-4.1.0-ech-hrr-rejection.patch` carries the
  `statem_clnt.c` hunk of OpenSSL pull request #33233 (since 2026-11-18; it replaced our own fix of the same branch):
  after a HelloRetryRequest the client keeps that message's verdict and aborts with `illegal_parameter` whenever the
  ServerHello's confirmation disagrees with it, in either direction (RFC 9849 section 6.1.4: acceptance "is determined
  by the server's initial message"; our fix covered only an accepting HelloRetryRequest followed by a rejecting
  ServerHello), and falls back to the `public_name` only at the first message. `test_ech.c` (`ech_rejected_after_hrr`,
  QUIC and TCP, and the retry) fails without it. While the pull request is open, every OpenSSL update re-checks it
  against the patch.

### ECH in the Ktor engines (2026-11-18)

- **Where a client's configuration comes from.** Per connection: the `ech` of the HTTPS record whose endpoint it goes to
  (RFC 9848), else `ech.configLists` of the host, else GREASE. A record's value is framing-checked by the SVCB codec (a
  malformed one drops the RRset, RFC 9460 section 2.2) and parsed by `EchConfigList` at connect time; one without a usable
  ECHConfig sends GREASE (RFC 9849 section 6.1).
- **One retry, per endpoint.** `EchRoute` holds the offer of a request's connections to one endpoint, shared by the QUIC
  and TCP sides of the race: a rejection sets the retry's offer (the retry configurations, or none: "securely disabled"),
  a sibling's rejection with the same offer takes it instead of a second retry, and a rejected retry is the failure
  (section 6.1.6). The retry reuses the request's resolution (no new lookup, as the section requires). Retry
  configurations are not stored (section 6.1.8 is a MAY; storing them would be a tracking vector to scope).
- **SVCB-reliant and the wait.** With ECH from the records the resolution is waited for like a protected one (RFC 9848
  section 5.3); when every ServiceMode endpoint has `ech` (section 5.1) neither the origin nor the AliasMode endpoint
  nor an Alt-Svc alternative without its own `ech` is tried.
- **0-RTT.** The early data rides under the inner ClientHello's PSK; OpenSSL copies `early_data` to the outer one and adds
  a GREASE PSK there (section 6.1, rules 6 and 7). A rejected handshake shows after `connectEarly` returned: the request,
  which the server ignored, is sent once more, and the connection's rejection sets the route's retry.
- **Pins and TOFU.** The `public_name`'s certificate is authenticated by the base trust; pins are the origin's (RFC 7469)
  and do not apply to it, since that connection only reports the rejection. TOFU takes no first contact from a rejection.
- **Proxies.** Inside a CONNECT or SOCKS5 tunnel the origin's ECH applies (`configLists` or GREASE; no HTTPS records
  through a proxy, RFC 9460 section 3.2). The hop to the proxy is plain TCP: there is no ClientHello to it, so neither ECH
  nor GREASE arises there; a TLS connection to a proxy, if one is added, gets GREASE like any server without a
  configuration (section 6.2.1) and never the origin's configuration.
- **Server.** `echKeys` on the TLS connector (TCP and HTTP/3) and `kuicksilver.tls.echKeys`; the `sniSelector` sees the
  `public_name` during a rejection and its certificate is the one the client checks.
- **No client certificate on a rejection.** OpenSSL 4.1 sends `ech_required` once the server's Finished is verified, before
  the client's flight, so no Certificate message leaves (RFC 9849 section 6.1.7 asks for an empty one if the client goes on;
  BoringSSL goes on and sends it); the C test `ech_rejection_sends_no_client_certificate` pins it.

