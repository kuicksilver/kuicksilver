#!/usr/bin/env python3
# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
"""The Maven repository of a GitHub prerelease (tools/release/local-release.sh --github-prerelease, docs/release.md,
"Prereleases on GitHub only").

pack: every file of the io.kuicksilver publication of <version> in the local repository local-release.sh made
(build/release/m2), with the .md5, .sha1, .sha256 and .sha512 of each artifact (none for the .asc, as on Maven Central)
and a maven-metadata.xml per artifact naming the one version (Gradle's maven-metadata-local.xml is left out), zipped
under one top directory kuicksilver-<version>-maven-repository/ with a README.md that says how to consume it; the same
README next to the zip as kuicksilver-<version>-maven-repository.md. Refuses a version that is not a prerelease, an
artifact without its POM or Gradle module metadata, and with --signed any file without its .asc. The zip is
deterministic: sorted entries, every timestamp --time (the release commit's), fixed permissions.
sums: a SHA256SUMS file (sha256sum format, file names only) of the given assets; refuses a missing one.

Usage: github-repository.py pack --version V --m2 DIR --out-dir DIR --time EPOCH [--signed]
       github-repository.py sums --out FILE ASSET...
Stdlib only, Python 3.9 or newer.
"""
import argparse
import datetime
import hashlib
import os
import re
import sys
import zipfile

GROUP = "io.kuicksilver"
REPO = "https://github.com/kuicksilver/kuicksilver"
KEY = "22C1F2E4FCE94B28EB2C7DB0492ABD95C8D0EC68"
PRERELEASE = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+-(alpha|beta|rc)\.?[0-9]+$")
CHECKSUMS = ("md5", "sha1", "sha256", "sha512")


def digest(algo, data):
    return hashlib.new(algo, data).hexdigest()


def metadata(artifact, version, stamp):
    return (f'<?xml version="1.0" encoding="UTF-8"?>\n<metadata>\n  <groupId>{GROUP}</groupId>\n'
            f"  <artifactId>{artifact}</artifactId>\n  <versioning>\n    <latest>{version}</latest>\n"
            f"    <release>{version}</release>\n    <versions>\n      <version>{version}</version>\n    </versions>\n"
            f"    <lastUpdated>{stamp}</lastUpdated>\n  </versioning>\n</metadata>\n").encode()


def readme(version, signed):
    top = f"kuicksilver-{version}-maven-repository"
    url = f"{REPO}/releases/download/v{version}"
    verify = (f"""Every asset has a detached signature (`.asc`) by the release key `{KEY}`
(`tools/release/kuicksilver-release-key.asc` in the repository), and so has every file inside the repository:

```
gpg --verify {top}.zip.asc {top}.zip
```

""" if signed else "")
    return f"""# Kuicksilver {version}: Maven repository

Kuicksilver {version} is a prerelease. It is not on Maven Central: it is published only as this GitHub prerelease,
as a Maven repository in one zip (`{top}.zip`). The final version goes to Maven Central.

## Download and check

```
gh release download v{version} -R kuicksilver/kuicksilver -p 'kuicksilver-{version}*'
shasum -a 256 -c kuicksilver-{version}-SHA256SUMS
```

or by URL: `{url}/{top}.zip` and `{url}/kuicksilver-{version}-SHA256SUMS`.

{verify}## Use it from Gradle

```
unzip {top}.zip
```

`settings.gradle.kts`: the unzipped directory as a repository, the only one for `io.kuicksilver` (a relative path:
`url = uri(settingsDir.resolve("{top}"))`):

```kotlin
dependencyResolutionManagement {{
    repositories {{
        exclusiveContent {{
            forRepository {{
                maven {{
                    name = "kuicksilverPrerelease"
                    url = uri("file:///path/to/{top}")
                }}
            }}
            filter {{ includeGroup("{GROUP}") }}
        }}
        google()
        mavenCentral()
    }}
}}
```

`build.gradle.kts` (in a Kotlin Multiplatform project, in `commonMain.dependencies`):

```kotlin
dependencies {{
    implementation(platform("{GROUP}:kuicksilver-bom:{version}"))
    implementation("{GROUP}:kuicksilver-ktor-client")
}}
```

Maven: the same directory as a `<repository>` with `<url>file:///path/to/{top}</url>`.

## SwiftPM

The Swift package names this version exactly (SwiftPM never picks a prerelease for a version range):

```swift
.package(url: "https://github.com/kuicksilver/kuicksilver-swift", exact: "{version}")
```

Its binary target is `Kuicksilver.xcframework.zip` of this release, whose SHA-256 is in
`kuicksilver-{version}-SHA256SUMS`.
"""


def pack(o):
    if not PRERELEASE.match(o.version):
        sys.exit(f"REFUSED: {o.version} is not a prerelease (X.Y.Z-alphaN|betaN|rcN): a final version goes to Maven Central")
    base = os.path.join(o.m2, *GROUP.split("."))
    files = {}  # path inside the repository -> bytes
    problems = []
    artifacts = sorted(a for a in (os.listdir(base) if os.path.isdir(base) else [])
                       if os.path.isdir(os.path.join(base, a, o.version)))
    if not artifacts:
        sys.exit(f"REFUSED: no {GROUP} publication of {o.version} in {o.m2}")
    stamp = datetime.datetime.fromtimestamp(o.time, datetime.timezone.utc)
    for a in artifacts:
        d = os.path.join(base, a, o.version)
        names = sorted(n for n in os.listdir(d) if os.path.isfile(os.path.join(d, n)) and not n.startswith("maven-metadata")
                       and not n.endswith(tuple("." + c for c in CHECKSUMS)))
        for need, what in ((f"{a}-{o.version}.pom", "no POM"), (f"{a}-{o.version}.module", "no Gradle module metadata")):
            if need not in names:
                problems.append(f"{a} {o.version}: {what} ({need})")
        for n in names:
            data = open(os.path.join(d, n), "rb").read()
            rel = "/".join(GROUP.split(".") + [a, o.version, n])
            files[rel] = data
            if n.endswith(".asc"):
                continue
            if o.signed and n + ".asc" not in names:
                problems.append(f"{a} {o.version}: no signature {n}.asc")
            for c in CHECKSUMS:
                files[f"{rel}.{c}"] = digest(c, data).encode()
        meta = metadata(a, o.version, stamp.strftime("%Y%m%d%H%M%S"))
        rel = "/".join(GROUP.split(".") + [a, "maven-metadata.xml"])
        files[rel] = meta
        for c in CHECKSUMS:
            files[f"{rel}.{c}"] = digest(c, meta).encode()
    if problems:
        sys.exit("REFUSED:\n  " + "\n  ".join(problems))
    top = f"kuicksilver-{o.version}-maven-repository"
    doc = readme(o.version, o.signed).encode()
    files["README.md"] = doc
    os.makedirs(o.out_dir, exist_ok=True)
    zpath = os.path.join(o.out_dir, top + ".zip")
    tmp = zpath + ".tmp"
    when = stamp.timetuple()[:6]
    with zipfile.ZipFile(tmp, "w", zipfile.ZIP_DEFLATED) as z:
        for rel in sorted(files):
            info = zipfile.ZipInfo(f"{top}/{rel}", date_time=when)
            info.external_attr = 0o100644 << 16
            info.compress_type = zipfile.ZIP_DEFLATED
            info.create_system = 3
            z.writestr(info, files[rel])
    os.replace(tmp, zpath)
    with open(os.path.join(o.out_dir, top + ".md"), "wb") as f:
        f.write(doc)
    arts = sum(1 for r in files if r.count("/") >= 3 and not r.endswith((".asc",) + tuple("." + c for c in CHECKSUMS))
               and not r.endswith("maven-metadata.xml"))
    print(f"{zpath}: {len(artifacts)} artifacts, {arts} files with checksums, {len(files)} entries, "
          f"{os.path.getsize(zpath)} bytes, sha256 {digest('sha256', open(zpath, 'rb').read())}")


def sums(o):
    missing = [p for p in o.assets if not os.path.isfile(p)]
    if missing:
        sys.exit("\n".join(f"{p}: no such asset" for p in missing))
    names = [os.path.basename(p) for p in o.assets]
    if len(set(names)) != len(names):
        sys.exit("two assets with the same file name")
    lines = "".join(f"{digest('sha256', open(p, 'rb').read())}  {n}\n" for p, n in zip(o.assets, names))
    with open(o.out, "w") as f:
        f.write(lines)
    sys.stdout.write(lines)


def main():
    a = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = a.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("pack")
    p.add_argument("--version", required=True)
    p.add_argument("--m2", required=True)
    p.add_argument("--out-dir", required=True)
    p.add_argument("--time", type=int, required=True)
    p.add_argument("--signed", action="store_true")
    s = sub.add_parser("sums")
    s.add_argument("--out", required=True)
    s.add_argument("assets", nargs="+")
    o = a.parse_args()
    pack(o) if o.cmd == "pack" else sums(o)


if __name__ == "__main__":
    main()
