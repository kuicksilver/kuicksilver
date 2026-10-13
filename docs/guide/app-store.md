<!--
Copyright 2026 The Kuicksilver Authors
SPDX-License-Identifier: Apache-2.0
-->

# Publishing an app that uses Kuicksilver (App Store, Mac App Store, notarized macOS)

This page walks through what Apple and the U.S. export rules ask of an app that embeds Kuicksilver, and ends with
templates you can copy and fill in. The iOS build itself (frameworks, privacy manifest, size, device checks) is in
[ios.md](ios.md).

> **Not legal advice.** Export classification and the answers you give Apple are the app owner's decision and
> responsibility. This page summarises the sources as of 2026-10-13 and links them; check them, and ask counsel when
> the stakes are real. The project cannot classify your app for you.

Sources used: Apple, [Complying with encryption export regulations](https://developer.apple.com/documentation/security/complying-with-encryption-export-regulations),
[Overview of export compliance](https://developer.apple.com/help/app-store-connect/manage-app-information/overview-of-export-compliance/),
[Export compliance documentation for encryption](https://developer.apple.com/help/app-store-connect/reference/app-information/export-compliance-documentation-for-encryption/),
[`ITSAppUsesNonExemptEncryption`](https://developer.apple.com/documentation/bundleresources/information-property-list/itsappusesnonexemptencryption),
the App Store Connect API [`AppEncryptionDeclaration` attributes](https://developer.apple.com/documentation/appstoreconnectapi/appencryptiondeclaration/attributes-data.dictionary)
(the same questions the web form asks), [required reason API](https://developer.apple.com/documentation/bundleresources/describing-use-of-required-reason-api);
the EAR as published in the eCFR: [15 CFR 740.17](https://www.ecfr.gov/current/title-15/subtitle-B/chapter-VII/subchapter-C/part-740/section-740.17)
(License Exception ENC) and [Supplement No. 8 to Part 742](https://www.ecfr.gov/current/title-15/part-742)
(self-classification report); BIS, [encryption controls](https://www.bis.gov/learn-support/encryption-controls).

## 1. Export compliance

**Why Kuicksilver counts as non-exempt encryption.** Apple treats encryption that is part of its operating systems
(HTTPS through `URLSession`, for example) as typically exempt from export documentation, and other encryption as not.
Kuicksilver ships its own TLS 1.3 (OpenSSL 3.5, statically linked) to secure QUIC, so an app that links it "implements
standard encryption algorithms instead of, or in addition to, using or accessing the encryption in Apple's operating
systems". Only standard, published algorithms are used (no proprietary cryptography).

**`ITSAppUsesNonExemptEncryption`.** Without this Info.plist key, App Store Connect asks the encryption questions for
every build you upload (TestFlight builds show "Missing Compliance" until answered). With Kuicksilver linked, set it to
`true`. `false` means "no encryption, or only exempt encryption", which is not the case for a Kuicksilver app even if
you only use it as a client. If App Store Connect issues a code after reviewing uploaded documentation, add it as
`ITSEncryptionExportComplianceCode`.

**What App Store Connect asks.** The questionnaire records, in order (the field names are those of the API):

1. Does the app use, contain or incorporate cryptography? (`usesEncryption`)
2. Is it exempt based on its use of encryption and availability? (`exempt`)
3. Does it implement proprietary encryption algorithms? (`containsProprietaryCryptography`)
4. Does it implement standard encryption algorithms instead of, or in addition to, the encryption in Apple's operating
   systems? (`containsThirdPartyCryptography`)
5. Will it be distributed on the App Store in France? (`availableOnFrenchStore`)

Apple's documentation table then says what to upload: encryption limited to the operating system needs nothing; an
"industry standard algorithm, not provided within the Apple operating system" needs the **French encryption
declaration**, and only if you distribute in France; proprietary algorithms additionally need a CCATS from BIS (not
the case with Kuicksilver). The French declaration is filed with ANSSI; App Store Connect takes the resulting document
under App Information > App Encryption Documentation, and Apple says it reviews it in about two business days.

**The usual U.S. path.** An app that uses standard cryptography to secure its own communication and is sold or given
away to the general public is normally a "mass market" item: it is exported under License Exception ENC,
15 CFR 740.17(b)(1), and after self-classification is classified **5D992.c** (mass-market software), "removed from EI
and NS controls". The annual **self-classification report** (740.17(e)(3), format in Supplement No. 8 to Part 742)
applies to mass-market *components* and certain "executable software" and to items that stay in 5x002; a finished
mass-market app is outside it, but the recordkeeping of part 762 applies (keep your classification reasoning). If you
ship a *component* (for example an SDK built on Kuicksilver for other developers), the report can apply to you: see the
template below. ENC never covers the embargoed destinations of Country Groups E:1/E:2.

**Mac App Store** uses the same App Store Connect questions and Info.plist keys. **Notarized apps outside the store**
see no questionnaire, but the EAR applies to the export the same way.

## 2. Why the app uses its own cryptography

App Review or a compliance contact may ask why the app does not use Apple's encryption. The answer is technical and
short: QUIC needs a TLS 1.3 stack with an interface that Apple's TLS APIs do not offer. The texts in
[Templates](#3-why-non-apple-encryption) are ready to paste.

## 3. Privacy manifest

Ship [`kuicksilver-native/apple/PrivacyInfo.xcprivacy`](../../kuicksilver-native/apple/PrivacyInfo.xcprivacy) or
merge its entries into your app's manifest ([ios.md, Privacy manifest](ios.md#privacy-manifest) explains the audit):
no tracking, no collected data, and one required-reason category, file timestamp APIs with reason `C617.1` (OpenSSL's
file loaders and the key-log file check call `stat`/`fstat`/`lstat` on files inside the app container). Apple requires
manifests on iOS, iPadOS, tvOS, visionOS and watchOS; a macOS app may carry the same file. Re-run
`tools/check/ios-private-api.py` on your Release binary when you upgrade: it prints the required-reason APIs it finds.

## 4. Info.plist and entitlements

| Key | When | Value |
|---|---|---|
| `ITSAppUsesNonExemptEncryption` | always with Kuicksilver | `true` |
| `ITSEncryptionExportComplianceCode` | only if App Store Connect gave you a code | the code |
| `NSLocalNetworkUsageDescription` | the app talks to LAN devices (a server on the phone, LAN peers, discovery); iOS 14+, macOS 15+ | why, in the user's words |
| `NSBonjourServices` | the app advertises or browses Bonjour services | e.g. `_myservice._udp` |
| `com.apple.security.network.client` (macOS App Sandbox) | any client: QUIC, HTTP/3, TLS | `true` |
| `com.apple.security.network.server` (macOS App Sandbox) | the app accepts connections: a QUIC endpoint with `server`, the Ktor server engine | `true` |

- iOS apps have no network entitlements; App Transport Security does not apply to Kuicksilver's own sockets.
- **Hardened runtime and notarization** (macOS): no exception entitlements are needed. Kotlin/Native compiles ahead of
  time and allocates ordinary read-write memory; OpenSSL is built without dynamic engines or modules. Checked on
  2026-10-13 by signing a Kotlin/Native test binary of `kuicksilver-tls` with `codesign --options runtime` and no
  entitlements and running its handshake tests (11 passed). Do not add `com.apple.security.cs.allow-jit`,
  `allow-unsigned-executable-memory` or `disable-library-validation` for Kuicksilver.
- With the App Sandbox, test the signed, sandboxed build: a missing `network.server` shows up only when a peer
  connects.

## 5. Do you need your own crypto at all?

If the app only needs an HTTP client, Ktor's **Darwin engine** runs on `URLSession`, which negotiates HTTP/3 by itself
when the server advertises it (iOS 15 and macOS 12 or later) and uses the operating system's encryption: no
non-exempt encryption, no French declaration, no OpenSSL in the binary. Choose Kuicksilver when you need what
`URLSession` does not give you:

- a raw QUIC API: your own protocol over streams, QUIC datagrams (RFC 9221), stream priorities, connection migration
  under your control;
- a server (HTTP/3, QUIC, or TLS over TCP) inside the app;
- control over 0-RTT (opt-in, replay-safe methods only), TLS policy (pins, a private CA, TOFU) and transport settings;
- the same protocol stack and behaviour on Android, the JVM, Linux and Windows.

## 6. App Review

- **IPv6-only networks.** Apple reviews apps on an IPv6-only network with NAT64/DNS64 and rejects apps that fail
  there. Bind `::`, connect by host name, never ship IPv4 literals. Test it with macOS Internet Sharing's NAT64 option
  ([ios.md, Device checklist](ios.md#device-checklist), item 5).
- **QUIC uses UDP**, usually to port 443. Networks that block UDP fall back to nothing unless your app has a TCP path;
  say in the review notes what the reviewer should see if UDP is blocked.
- **Checklist before you submit:**
  - [ ] `ITSAppUsesNonExemptEncryption = true`; the questionnaire answered once; French declaration uploaded if you
        distribute in France.
  - [ ] Privacy manifest included; `ios-private-api.py` on the Release binary reports no non-public symbols and no
        required-reason API missing from the manifest.
  - [ ] `tools/check/ios-symbols.sh` passes (no symbol clash with another OpenSSL/BoringSSL in the app).
  - [ ] Size impact measured (`tools/check/ios-size.sh`: about 3.3 MB for OpenSSL + Kuicksilver, about 5.4 MB with
        the Kotlin runtime in an app that has no other Kotlin).
  - [ ] Tested on a device, Wi-Fi and cellular, and on NAT64.
  - [ ] `NSLocalNetworkUsageDescription`/`NSBonjourServices` present if and only if the app uses the LAN.
  - [ ] Review notes filled in (template below), with a test server the reviewer can reach without an account.

## Templates

How to use them: copy a block, replace every `<PLACEHOLDER>`, delete the lines that do not apply. They describe a
typical app that uses Kuicksilver for its network traffic with standard algorithms only; where your app differs (a
server, an SDK for other developers, extra cryptography of your own) the notes say what changes. Not legal advice:
the answers are yours to give.

### 1. App Store Connect encryption questions

| Question | Typical Kuicksilver app | When the answer differs |
|---|---|---|
| Does your app use, contain or incorporate cryptography? | **Yes** | never "No" while Kuicksilver is linked |
| Is it exempt (based on its use of encryption and availability)? | **No** | Apple's exemptions cover encryption limited to the OS; Kuicksilver brings its own |
| Does it implement any proprietary encryption algorithms? | **No** (TLS 1.3 and QUIC are IETF standards; OpenSSL implements published algorithms) | "Yes" only if *your* code adds unpublished cryptography: then a CCATS from BIS is needed |
| Does it implement standard encryption algorithms instead of, or in addition to, the encryption in Apple's operating systems? | **Yes** | same answer for a client, a server mode or both |
| Will it be available on the App Store in France? | **Yes / No** (your choice) | "Yes": upload the French encryption declaration (ANSSI) |

### 2. Info.plist

```xml
<!-- Export compliance: Kuicksilver embeds OpenSSL (TLS 1.3 for QUIC). See docs/guide/app-store.md. -->
<key>ITSAppUsesNonExemptEncryption</key>
<true/>
<!-- Only after App Store Connect approved uploaded documentation and showed a code: -->
<key>ITSEncryptionExportComplianceCode</key>
<string><CODE FROM APP STORE CONNECT></string>

<!-- Only if the app talks to devices on the local network: -->
<key>NSLocalNetworkUsageDescription</key>
<string><APP NAME> connects to <WHAT, e.g. "your camera / other phones running <APP NAME>"> on your local network to <WHY>.</string>
<!-- Only if the app advertises or browses Bonjour services: -->
<key>NSBonjourServices</key>
<array>
    <string>_<SERVICE>._udp</string>
</array>
```

macOS App Sandbox (`<APP NAME>.entitlements`):

```xml
<key>com.apple.security.app-sandbox</key>
<true/>
<key>com.apple.security.network.client</key>
<true/>
<!-- Only if the app accepts connections (QUIC/HTTP/3 server): -->
<key>com.apple.security.network.server</key>
<true/>
```

### 3. Why non-Apple encryption

Long version (paste and adjust):

> <APP NAME> by <COMPANY> uses QUIC (IETF RFC 9000 and RFC 9001) and HTTP/3 to <WHAT THE APP USES QUIC FOR>. QUIC
> builds its security on TLS 1.3 in a way that requires direct access to the TLS handshake: the QUIC implementation
> must receive the handshake messages for each encryption level separately, install the traffic secrets for each
> level itself, and carry QUIC transport parameters inside the TLS handshake. Apple's TLS interfaces (Security and
> Network frameworks) do not expose these steps to a third-party QUIC implementation, so the app includes the
> Kuicksilver library, which uses OpenSSL 3.5 as its TLS 1.3 implementation. Only standard, published algorithms
> are used: AES-GCM and ChaCha20-Poly1305 for encryption, X25519 and the X25519/ML-KEM hybrid for key exchange, ECDSA
> and RSA signature verification, and HKDF with SHA-2. The cryptography is used only to authenticate the
> servers the app connects to and to encrypt the app's own network traffic; it is not offered to users or other apps
> as a general-purpose encryption function. Server certificates are verified with Apple's trust evaluation (SecTrust)
> and the system trust store. The app contains no proprietary or non-standard cryptography.

One line:

> <APP NAME> implements QUIC/HTTP-3, which needs a TLS 1.3 stack Apple's APIs do not expose, so it embeds OpenSSL
> (standard algorithms only) solely to authenticate servers and encrypt its own network traffic.

If the app also runs a server, add: "The app can also accept connections from <WHO> on the local network, secured the
same way."

### 4. App Review notes

```text
Network features: <APP NAME> uses QUIC and HTTP/3 (UDP, port <443>) to <WHAT THE APP DOES OVER THE NETWORK>.
How to test: <STEPS, e.g. "open the Live tab; data from https://<TEST SERVER> appears within a few seconds">.
No account is needed. <OR: Demo account: <USER> / <PASSWORD>.>
Test server: https://<TEST SERVER>:<PORT> is public and accepts the review device.
If UDP is blocked on the review network, <WHAT THE REVIEWER SEES, e.g. "the app falls back to HTTPS over TCP" or
"the status line shows 'QUIC unavailable on this network'">.
IPv6: the app connects by host name and works on IPv6-only (NAT64) networks; tested on <DATE>.
Local network: <ONLY IF USED: "the Share tab serves a page to nearby devices; iOS asks for local network access the
first time">.
Encryption: standard TLS 1.3 via the embedded Kuicksilver/OpenSSL library to secure the app's own traffic;
ITSAppUsesNonExemptEncryption is set.
```

### 5. Annual self-classification report (only if it applies)

A finished mass-market app is normally outside 740.17(e)(3) (see section 1); the report is for mass-market
components and certain executable software classified 5A992/5D992, and for items that stay in 5A002/5D002 after
self-classification, exported under 740.17(b)(1). **Verify with your counsel whether it applies to you.** Format:
Supplement No. 8 to Part 742, a `.csv` file whose first line is exactly the twelve headers below, one row per product,
no empty cells, company columns repeated on every row.

```csv
PRODUCT NAME,MODEL NUMBER,MANUFACTURER,ECCN,AUTHORIZATION TYPE,ITEM TYPE,SUBMITTER NAME,TELEPHONE NUMBER,E-MAIL ADDRESS,MAILING ADDRESS,NON-U.S. COMPONENTS,NON-U.S. MANUFACTURING LOCATIONS
<PRODUCT NAME>,<VERSION OR N/A>,SELF,5D992,MMKT,Mobility and mobile applications n.e.s.,<COMPANY>,<PHONE>,<EMAIL>,<ADDRESS>,<YES/NO>,<CITY COUNTRY OR NONE>
```

`AUTHORIZATION TYPE` is `MMKT` for mass market or `ENC`; `ITEM TYPE` comes from the list in the supplement (for an
SDK, "Other (please specify)" with a short description may fit better). Send it for each calendar year by
**February 1** of the next year, by email to `crypt-supp8@bis.doc.gov` **and** `enc@nsa.gov`, subject
"self-classification report", stating the period covered and a contact. A product is reported once; in a year with no
new products, an email saying nothing has changed is sent instead.

### 6. Privacy manifest

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <!-- Kuicksilver does no tracking and contacts no tracking domains. Set these for YOUR app's own behaviour. -->
    <key>NSPrivacyTracking</key>
    <false/>
    <key>NSPrivacyTrackingDomains</key>
    <array/>
    <!-- Kuicksilver collects no data. Add the data types your app collects. -->
    <key>NSPrivacyCollectedDataTypes</key>
    <array/>
    <key>NSPrivacyAccessedAPITypes</key>
    <array>
        <!-- Kuicksilver: OpenSSL's file loaders and the key-log file check call stat/fstat/lstat on files inside the
             app container (type, owner, link count; never sent anywhere). -->
        <dict>
            <key>NSPrivacyAccessedAPIType</key>
            <string>NSPrivacyAccessedAPICategoryFileTimestamp</string>
            <key>NSPrivacyAccessedAPITypeReasons</key>
            <array>
                <string>C617.1</string>
            </array>
        </dict>
        <!-- Add your app's own categories here (for example NSPrivacyAccessedAPICategoryUserDefaults, CA92.1). -->
    </array>
</dict>
</plist>
```
