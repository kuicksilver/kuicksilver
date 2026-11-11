#!/usr/bin/env bash
# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
# Negative controls of tools/verify/verify-release.sh on fixtures, without network. A fixture is a Maven repository of a
# made-up version (a BOM naming kuicksilver-native, whose Gradle module file names a jar, an AAR and a cinterop klib
# carrying stand-in native libraries), its GitHub release files (the provenance whose subjects are those files: from
# 0.3.0 an in-toto bundle with one DSSE envelope, before it a plain statement; an SBOM zip; from 0.3.0 a stand-in
# Kuicksilver.xcframework.zip whose checksum the tag's Package.swift names), a directory of "rebuilt" libraries (--rebuilt) and a throwaway git repository with the signed tag
# (KSL_VERIFY_REPO), all signed with a throwaway key handed to the script through KSL_VERIFY_KEY/KSL_VERIFY_FPR. Each case
# copies the fixture, breaks one thing and expects an exit code and the lines the report must (and must not) contain.
# The offline cases read the copy with --offline; the online cases go through a curl stub that serves the copy as
# Maven Central and GitHub (directory listings included) and can answer 404 or not at all, so no case reaches the network.
# Usage: verify-release-test.sh
set -uo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
script="$here/verify-release.sh"
tmp=$(mktemp -d /tmp/ksl-vrt.XXXXXX)   # short path: macOS limits gpg-agent socket paths
trap 'for h in "$tmp"/gpg-*; do gpgconf --homedir "$h" --kill all >/dev/null 2>&1 || true; done; rm -rf "$tmp"' EXIT
sha1() { (sha1sum "$1" 2>/dev/null || shasum -a 1 "$1") | cut -d' ' -f1; }

# curl: https://central.invalid/maven2/<path> is $STUB_CENTRAL/<path> (a directory gives an HTML listing),
# https://github.invalid/dl/v<version>/<file> is $STUB_GITHUB/<file>; a URL matching $STUB_NOANSWER gets no answer (000,
# exit 7), one matching $STUB_404 a 404; $STUB_LISTING_EXTRA is added to every listing; anything else is a test bug and gets no answer
mkdir -p "$tmp/bin"
cat > "$tmp/bin/curl" <<'PY'
#!/usr/bin/env python3
import os, re, shutil, sys
args, out, fmt, url = sys.argv[1:], None, "", None
i = 0
while i < len(args):
    a = args[i]
    if a in ("-o", "-w", "--retry", "--connect-timeout", "--max-time"):
        if a == "-o": out = args[i + 1]
        if a == "-w": fmt = args[i + 1]
        i += 2; continue
    if not a.startswith("-"): url = a
    i += 1
def answer(code, body=None, path=None):
    if out and path: shutil.copyfile(path, out)
    elif out and body is not None: open(out, "w").write(body)
    elif out and code != "000": open(out, "w").write("not found\n")
    sys.stdout.write(fmt.replace("%{http_code}", code))
    sys.exit(7 if code == "000" else 0)
if os.environ.get("STUB_NOANSWER") and re.search(os.environ["STUB_NOANSWER"], url): answer("000")
if os.environ.get("STUB_404") and re.search(os.environ["STUB_404"], url): answer("404")
for prefix, base, flat in (("https://central.invalid/maven2/", os.environ.get("STUB_CENTRAL"), False),
                           ("https://github.invalid/dl/", os.environ.get("STUB_GITHUB"), True)):
    if base and url.startswith(prefix):
        rel = url[len(prefix):]
        p = os.path.join(base, os.path.basename(rel) if flat else rel)
        if rel.endswith("/") and os.path.isdir(p):
            extra = [os.environ["STUB_LISTING_EXTRA"]] if os.environ.get("STUB_LISTING_EXTRA") else []
            answer("200", '<a href="../">../</a>\n' + "".join(f'<a href="{f}">{f}</a>\n' for f in sorted(os.listdir(p)) + extra))
        if os.path.isfile(p): answer("200", path=p)
        answer("404")
sys.stderr.write(f"curl stub: unexpected {url}\n"); answer("000")
PY
chmod +x "$tmp/bin/curl"; export PATH="$tmp/bin:$PATH"

key() { # <name>: a throwaway signing key in $tmp/gpg-<name>; prints its fingerprint
  local h="$tmp/gpg-$1"; mkdir -p "$h"; chmod 700 "$h"
  gpg --homedir "$h" --batch --pinentry-mode loopback --passphrase '' --quick-gen-key "$1 <$1@example.invalid>" ed25519 sign never >/dev/null 2>&1
  gpg --homedir "$h" --batch --with-colons --list-keys 2>/dev/null | awk -F: '$1 == "fpr" {print $10; exit}'
}
sign() { # <key name> <file>: <file>.asc
  rm -f "$2.asc"; gpg --homedir "$tmp/gpg-$1" --batch --pinentry-mode loopback --passphrase '' --armor --detach-sign -o "$2.asc" "$2"
}
fpr=$(key test); other=$(key other)
[ -n "$fpr" ] && [ -n "$other" ] || { echo "FAIL: could not make the test keys"; exit 2; }
gpg --homedir "$tmp/gpg-test" --batch --armor --export "$fpr" > "$tmp/test-key.asc"

# the git repository with the tags: v9.9.9 signed by the test key, v9.9.8 by the other key
git init -q "$tmp/git"; git -C "$tmp/git" config user.email t@example.invalid; git -C "$tmp/git" config user.name t
git -C "$tmp/git" config commit.gpgsign false; git -C "$tmp/git" config core.hooksPath /dev/null
echo x > "$tmp/git/f"
printf 'xcframework stand-in\n' > "$tmp/xcframework.zip"
xcf_sum=$( (sha256sum "$tmp/xcframework.zip" 2>/dev/null || shasum -a 256 "$tmp/xcframework.zip") | cut -d' ' -f1)
printf '        .binaryTarget(\n            name: "Kuicksilver",\n            url: "https://github.com/kuicksilver/kuicksilver/releases/download/v9.9.9/Kuicksilver.xcframework.zip",\n            checksum: "%s"\n        ),\n' "$xcf_sum" > "$tmp/git/Package.swift"
git -C "$tmp/git" add f Package.swift; git -C "$tmp/git" commit -qm x
commit=$(git -C "$tmp/git" rev-parse HEAD)
GNUPGHOME="$tmp/gpg-test" git -C "$tmp/git" -c gpg.format=openpgp -c gpg.program=gpg -c user.signingkey="$fpr" tag -s v9.9.9 -m t
GNUPGHOME="$tmp/gpg-other" git -C "$tmp/git" -c gpg.format=openpgp -c gpg.program=gpg -c user.signingkey="$other" tag -s v9.9.8 -m t

# the rebuilt libraries, and the published archives that carry the same bytes
rb="$tmp/rebuilt"; mkdir -p "$rb/jni/osx-aarch_64" "$rb/android/arm64-v8a" "$rb/klib/macos_arm64"
printf 'dylib for osx-aarch_64\n' > "$rb/jni/osx-aarch_64/libksl_7_osx_aarch_64.dylib"
printf 'so for arm64-v8a\n' > "$rb/android/arm64-v8a/libksl.so"
for a in libksl.a libssl.a libcrypto.a; do printf 'archive %s\n' "$a" > "$rb/klib/macos_arm64/$a"; done
x="$tmp/x"; mkdir -p "$x/META-INF/native" "$x/jni/arm64-v8a" "$x/default/targets/macos_arm64/included"
cp "$rb/jni/osx-aarch_64/libksl_7_osx_aarch_64.dylib" "$x/META-INF/native/"
cp "$rb/android/arm64-v8a/libksl.so" "$x/jni/arm64-v8a/"
cp "$rb/klib/macos_arm64"/*.a "$x/default/targets/macos_arm64/included/"
printf '{"cyclonedx":"stand-in"}\n' > "$x/bom.cdx.json"

envelope() { # <statement.json> <out.intoto.jsonl> [<key name>]: the in-toto bundle as the release writes it
  # (tools/release/dsse.py, an armored signature over the PAE), after an unrecognised line the verifier must ignore
  python3 "$here/../release/dsse.py" payload "$1" "$2.payload" "$2.pae" >/dev/null || return 1
  gpg --homedir "$tmp/gpg-${3:-test}" --batch --pinentry-mode loopback --passphrase '' --armor --detach-sign -o "$2.pae.asc" "$2.pae"
  python3 "$here/../release/dsse.py" envelope "$2.payload" "$2.env" --sig "$2.pae.asc" --keyid test >/dev/null || return 1
  { echo '{"note":"an unrecognised line, ignored"}'; cat "$2.env"; } > "$2"
  rm -f "$2.pae" "$2.pae.asc" "$2.payload" "$2.env"
}
statement() { # <in-toto bundle>: its Statement, pretty, on stdout
  python3 -c 'import base64,json,sys
for l in open(sys.argv[1]):
    o = json.loads(l)
    if "payload" in o: print(json.dumps(json.loads(base64.b64decode(o["payload"])), indent=1))' "$1"
}
restate() { # <bundle> <python on s, the Statement>: changes the Statement and signs the envelope and the file again
  statement "$1" > "$1.st"; python3 -c "import json,sys; s=json.load(open(sys.argv[1])); $2; json.dump(s,open(sys.argv[1],'w'))" "$1.st"
  envelope "$1.st" "$1"; rm -f "$1.st"; sign test "$1"
}
ver_ge() { [ "$(printf '%s\n%s\n' "$1" "$2" | sort -V | head -1)" = "$2" ]; }
fixture() { # <version> <dir> <source commit of the provenance>
  local v="$1" fx="$2" m="$2/io/kuicksilver" f
  mk() { mkdir -p "$m/$1/$v"; printf '%s' "$m/$1/$v/$1-$v$2"; }
  mkdir -p "$fx/github"
  (cd "$x" && zip -qr "$(mk kuicksilver-native-jvm .jar)" META-INF)
  (cd "$x" && zip -qr "$(mk kuicksilver-native-android .aar)" jni)
  (cd "$x" && zip -qr "$(mk kuicksilver-native-macosarm64 -cinterop-ksl.klib)" default)
  printf '<project><dependencyManagement><dependencies><dependency><groupId>io.kuicksilver</groupId><artifactId>kuicksilver-native</artifactId><version>%s</version></dependency></dependencies></dependencyManagement></project>\n' "$v" > "$(mk kuicksilver-bom .pom)"
  printf '{"variants":[{"name":"a","available-at":{"url":"../../kuicksilver-native-jvm/%s/kuicksilver-native-jvm-%s.module"}},{"name":"b","available-at":{"url":"../../kuicksilver-native-android/%s/kuicksilver-native-android-%s.module"}},{"name":"c","available-at":{"url":"../../kuicksilver-native-macosarm64/%s/kuicksilver-native-macosarm64-%s.module"}}]}\n' "$v" "$v" "$v" "$v" "$v" "$v" > "$(mk kuicksilver-native .module)"
  (cd "$x" && zip -q "$fx/github/kuicksilver-$v-sbom.zip" bom.cdx.json)
  ver_ge "$v" 0.3.0 && cp "$tmp/xcframework.zip" "$fx/github/Kuicksilver.xcframework.zip"
  python3 - "$fx" "$v" "$3" > "$fx/statement.json" <<'PY'
import hashlib, json, os, sys
fx, v, commit = sys.argv[1:4]
subj = []
for d, _, fs in os.walk(os.path.join(fx, "io")):
    for f in sorted(fs):
        p = os.path.join(d, f); subj.append({"name": os.path.relpath(p, fx), "digest": {"sha256": hashlib.sha256(open(p, "rb").read()).hexdigest()}})
z = os.path.join(fx, "github", f"kuicksilver-{v}-sbom.zip")
subj.append({"name": os.path.basename(z), "digest": {"sha256": hashlib.sha256(open(z, "rb").read()).hexdigest()}})
z = os.path.join(fx, "github", "Kuicksilver.xcframework.zip")
if os.path.isfile(z): subj.append({"name": os.path.basename(z), "digest": {"sha256": hashlib.sha256(open(z, "rb").read()).hexdigest()}})
src = {"uri": "git+https://github.com/kuicksilver/kuicksilver", "digest": {"gitCommit": commit}}
print(json.dumps({"_type": "https://in-toto.io/Statement/v1", "subject": sorted(subj, key=lambda s: s["name"]),
                  "predicateType": "https://slsa.dev/provenance/v1",
                  "predicate": {"buildDefinition": {"externalParameters": {"source": src, "version": v}}}}, indent=1))
PY
  if ver_ge "$v" 0.3.0; then envelope "$fx/statement.json" "$fx/github/kuicksilver-$v.intoto.jsonl"
  else mv "$fx/statement.json" "$fx/github/kuicksilver-$v.intoto.json"; fi
  rm -f "$fx/statement.json"
  for f in $(cd "$fx" && find io -type f); do sign test "$fx/$f"; sha1 "$fx/$f" > "$fx/$f.sha1"; done
  for f in "$fx/github"/*; do sign test "$f"; done
}
fixture 9.9.9 "$tmp/fx-9.9.9" "$commit"
fixture 9.9.8 "$tmp/fx-9.9.8" "$commit"
fixture 0.2.5 "$tmp/fx-0.2.5" "$commit"   # 0.2.x: a plain statement, kuicksilver-<v>.intoto.json, no xcframework
fixture 0.1.9 "$tmp/fx-0.1.9" "$commit"; rm -r "$tmp/fx-0.1.9/github"   # before 0.2.1: no SBOM or provenance

pass=0; fail=0
t() { # [V=<version>] [ONLINE=1] [PINNED=1] [NOREBUILT=1] t <name> <expected exit> <setup, run in the case's copy> [+<must match> | -<must not>]... -- [args]
  local name="$1" want="$2" setup="$3" v="${V:-9.9.9}"; shift 3
  local c="$tmp/case"; rm -rf "$c"; mkdir -p "$c"; cp -R "$tmp/fx-$v" "$c/repo"; cp -R "$rb" "$c/rebuilt"
  local pats=(); while [ $# -gt 0 ] && [ "$1" != -- ]; do pats+=("$1"); shift; done; [ "${1:-}" = -- ] && shift
  (cd "$c" && eval "$setup") || { echo "FAIL $name: setup failed"; fail=$((fail+1)); return; }
  local env=(KSL_VERIFY_KEY="$tmp/test-key.asc" KSL_VERIFY_FPR="$fpr" KSL_VERIFY_REPO="$tmp/git")
  [ "${PINNED:-0}" = 1 ] && env=(-u KSL_VERIFY_KEY -u KSL_VERIFY_FPR KSL_VERIFY_REPO="$tmp/git")
  local mode=(--offline "$c/repo")
  [ "${ONLINE:-0}" = 1 ] && { mode=(); env+=(KSL_VERIFY_CENTRAL=https://central.invalid/maven2 KSL_VERIFY_GITHUB=https://github.invalid/dl
                                            STUB_CENTRAL="$c/repo" STUB_GITHUB="$c/repo/github"); }
  local out rc why="" given=(--rebuilt "$c/rebuilt"); [ "${NOREBUILT:-0}" = 1 ] && given=()
  out=$(cd "$c" && env "${env[@]}" bash "$script" "$v" ${mode[@]+"${mode[@]}"} \
    ${given[@]+"${given[@]}"} --targets macos-arm64,android-arm64 --work "$c/work" "$@" 2>&1); rc=$?
  [ "$rc" = "$want" ] || why="exit $rc, want $want"
  for p in ${pats[@]+"${pats[@]}"}; do
    case "$p" in
      +*) grep -Eq -- "${p#+}" <<< "$out" || why="${why:+$why; }no line matching '${p#+}'" ;;
      -*) ! grep -Eq -- "${p#-}" <<< "$out" || why="${why:+$why; }a line matching '${p#-}'" ;;
    esac
  done
  # shellcheck disable=SC2001
  if [ -z "$why" ]; then printf 'ok   %s\n' "$name"; pass=$((pass+1))
  else printf 'FAIL %s: %s\n' "$name" "$why"; sed 's/^/     | /' <<< "$out"; fail=$((fail+1)); fi
}
jar="repo/io/kuicksilver/kuicksilver-native-jvm/9.9.9/kuicksilver-native-jvm-9.9.9.jar"
aar="repo/io/kuicksilver/kuicksilver-native-android/9.9.9/kuicksilver-native-android-9.9.9.aar"
bom="repo/io/kuicksilver/kuicksilver-bom/9.9.9/kuicksilver-bom-9.9.9.pom"
mod="repo/io/kuicksilver/kuicksilver-native/9.9.9/kuicksilver-native-9.9.9.module"
prov="repo/github/kuicksilver-9.9.9.intoto.jsonl"; xcf="repo/github/Kuicksilver.xcframework.zip"
flip() { python3 -c 'import sys; p=sys.argv[1]; b=bytearray(open(p,"rb").read()); b[len(b)//2]^=1; open(p,"wb").write(b)' "$1"; }
resign() { sign test "$1"; sha1 "$1" > "$1.sha1"; }

# offline
t "good release"                       0 ':' \
  '+^OK +tag +v9.9.9 +\(commit [0-9a-f]{40}, signed by' \
  '+^OK +signature +io/kuicksilver/kuicksilver-native-jvm/9.9.9/kuicksilver-native-jvm-9.9.9.jar' \
  '+^OK +signature +github/kuicksilver-9.9.9.intoto.jsonl$' '+^OK +signature +github/kuicksilver-9.9.9.intoto.jsonl \(DSSE envelope\)' \
  '+^OK +signature +github/Kuicksilver.xcframework.zip' '+^OK +provenance +Kuicksilver.xcframework.zip' \
  '+^OK +swiftpm +github/Kuicksilver.xcframework.zip +\(the checksum Package.swift of v9.9.9 names\)' \
  '+^OK +provenance +io/kuicksilver/kuicksilver-native-android/9.9.9/' \
  '+^OK +provenance +source commit [0-9a-f]{12} +\(the commit of tag v9.9.9\)' \
  '+^OK +rebuild +jni/osx-aarch_64/libksl_7_osx_aarch_64.dylib' '+^OK +rebuild +android/arm64-v8a/libksl.so' \
  '+^OK +rebuild +klib/macos_arm64/libcrypto.a' '+^SKIPPED +rebuild +jni/linux-x86_64' \
  '-^(DIFF|FAIL)' '+0 DIFF, [0-9]+ SKIPPED, 0 FAIL$'
t "tampered byte in the published jar" 1 "flip $jar" \
  '+^FAIL +signature +.*kuicksilver-native-jvm-9.9.9.jar +\(not a good signature' \
  '+^DIFF +provenance +.*kuicksilver-native-jvm-9.9.9.jar' '+^OK +rebuild +android/arm64-v8a'
# a published library that is not what the sources build, in a jar signed with the right key (a stolen key, a dirty build)
t "published library differs, signed"  1 "mkdir -p y/META-INF/native; printf 'other dylib\\\\n' > y/META-INF/native/libksl_7_osx_aarch_64.dylib
    rm $jar; (cd y && zip -qr ../$jar META-INF); resign $jar" \
  '+^OK +signature +.*kuicksilver-native-jvm-9.9.9.jar' '+^DIFF +rebuild +jni/osx-aarch_64/libksl_7_osx_aarch_64.dylib' \
  '+^DIFF +provenance +.*kuicksilver-native-jvm-9.9.9.jar'
t "rebuilt library differs by a byte"  1 'flip rebuilt/android/arm64-v8a/libksl.so' \
  '+^DIFF +rebuild +android/arm64-v8a/libksl.so +\(rebuilt [0-9a-f]{16}, published [0-9a-f]{16}' '+^OK +signature' '-^FAIL'
t "signature by another key"           1 "rm $aar.asc; gpg --homedir $tmp/gpg-other --batch --armor --detach-sign -o $aar.asc $aar" \
  '+^FAIL +signature +.*kuicksilver-native-android-9.9.9.aar +\(not a good signature' '+^OK +rebuild +android/arm64-v8a'
t "provenance signed by another key"   1 "rm $prov.asc; gpg --homedir $tmp/gpg-other --batch --armor --detach-sign -o $prov.asc $prov" \
  '+^FAIL +signature +github/kuicksilver-9.9.9.intoto.jsonl' '+^SKIPPED +provenance +subjects of .* +\(its signature is not good' \
  '-^OK +provenance' '-DSSE envelope'
t "envelope signed by another key"     1 "statement $prov > st.json; envelope st.json $prov other; sign test $prov" \
  '+^OK +signature +github/kuicksilver-9.9.9.intoto.jsonl$' \
  '+^FAIL +signature +github/kuicksilver-9.9.9.intoto.jsonl \(DSSE envelope\) +\(no good signature' \
  '+^SKIPPED +provenance +subjects of' '-^OK +provenance'
t "envelope without a signature"       1 "python3 -c 'import json,sys; p=sys.argv[1]; ls=[json.loads(l) for l in open(p)]; ls[-1][\"signatures\"]=[]; open(p,\"w\").write(\"\".join(json.dumps(l)+chr(10) for l in ls))' $prov; sign test $prov" \
  '+^FAIL +signature +github/kuicksilver-9.9.9.intoto.jsonl \(DSSE envelope\) +\(the envelope carries no signature' '-^OK +provenance'
t "bundle with two provenance envelopes" 1 "tail -1 $prov >> $prov; sign test $prov" \
  '+^FAIL +provenance +github/kuicksilver-9.9.9.intoto.jsonl +\(not an in-toto bundle of the provenance: 2 DSSE' '-^OK +provenance'
t "bundle that is one pretty-printed statement" 1 "statement $prov > $prov.st; mv $prov.st $prov; sign test $prov" \
  '+^FAIL +provenance +github/kuicksilver-9.9.9.intoto.jsonl +\(not an in-toto bundle of the provenance: line [0-9]+ is not JSON' '+^SKIPPED +provenance +subjects of .* +\(it is not a provenance bundle' '-^OK +provenance'
t "xcframework differs from Package.swift" 1 "printf 'other\\\\n' > $xcf; sign test $xcf" \
  '+^OK +signature +github/Kuicksilver.xcframework.zip' '+^DIFF +provenance +Kuicksilver.xcframework.zip' \
  '+^DIFF +swiftpm +github/Kuicksilver.xcframework.zip +\(sha256 [0-9a-f]{16}, Package.swift of v9.9.9 names'
t "xcframework missing"                1 "rm $xcf $xcf.asc" \
  '+^FAIL +provenance +github/Kuicksilver.xcframework.zip +\(not on the GitHub release v9.9.9\)' '-swiftpm'
V=0.2.5 t "0.2.x: the plain statement, no xcframework" 0 ':' \
  '+^OK +signature +github/kuicksilver-0.2.5.intoto.json$' '+^OK +provenance +kuicksilver-0.2.5-sbom.zip' '-xcframework' '-DSSE' '-^(DIFF|FAIL)' -- --no-rebuild
t "missing signature"                  1 "rm $jar.asc" '+^FAIL +signature +.*kuicksilver-native-jvm-9.9.9.jar +\(no \.asc\)'
t "missing artifact"                   1 "rm $aar $aar.asc $aar.sha1" \
  '+^FAIL +provenance +.*kuicksilver-native-android-9.9.9.aar +\(a subject of the provenance, missing here' \
  '+^FAIL +rebuild +android/arm64-v8a/libksl.so +\(kuicksilver-native-android-9.9.9.aar is not among'
t "published file not in the provenance" 1 "cp $jar ${jar%.jar}-extra.jar; cp $jar.asc ${jar%.jar}-extra.jar.asc" \
  '+^FAIL +provenance +.*-extra.jar +\(published, but not a subject'
t "wrong .sha1"                        1 "echo 0000000000000000000000000000000000000000 > $aar.sha1" '+^DIFF +sha1 +.*\.aar'
t "missing rebuilt library"            1 'rm rebuilt/klib/macos_arm64/libssl.a' '+^FAIL +rebuild +klib/macos_arm64/libssl.a +\(the rebuild produced no'
t "0.2.1 or later without GitHub release files" 1 'rm -r repo/github' \
  '+^FAIL +provenance +github/kuicksilver-9.9.9.intoto.jsonl +\(not on the GitHub release v9.9.9\)' \
  '+^FAIL +provenance +github/kuicksilver-9.9.9-sbom.zip' '-^SKIPPED +provenance'
V=0.1.9 t "before 0.2.1: no GitHub release files is not a failure" 0 ':' \
  '+^SKIPPED +provenance +kuicksilver-0.1.9.intoto.json +\(not on the GitHub release v0.1.9 \(releases before 0.2.1' \
  '+^SKIPPED +tag +v0.1.9 +\(not in this clone' '-^(DIFF|FAIL)'
t "provenance names another commit than the verified tag" 1 \
  "restate $prov 's[\"predicate\"][\"buildDefinition\"][\"externalParameters\"][\"source\"][\"digest\"][\"gitCommit\"]=\"1\"*40'" \
  '+^DIFF +provenance +source commit 111111111111 +\(tag v9.9.9 is [0-9a-f]{12}\)'
t "provenance subject with a traversal name" 1 \
  "restate $prov 's[\"subject\"].append({\"name\":\"../../../etc/passwd\",\"digest\":{\"sha256\":\"0\"}})'" \
  "+^FAIL +provenance +'../../../etc/passwd' +\\(not a plain relative path"
V=9.9.8 t "tag signed by another key"  1 ':' '+^FAIL +tag +v9.9.8 +\(commit [0-9a-f]{40}, not a good signature' \
  '+^SKIPPED +provenance +source commit .* +\(no verified tag v9.9.8' '-^OK +tag'
V=9.9.8 NOREBUILT=1 t "tag signed by another key: nothing is rebuilt from it" 1 ':' \
  '+^FAIL +rebuild +native libraries +\(no verified tag v9.9.8 to build from' '-^OK +openssl' '-building'
t "--no-rebuild"                       0 ':' '+^SKIPPED +rebuild +native libraries +\(--no-rebuild\)' '-^OK +rebuild' '+^OK +tag' -- --no-rebuild
# without the override the pinned release key is used: a fixture signed by any other key must fail every signature
PINNED=1 t "the pinned key, not the fixture's" 1 ':' '+^FAIL +signature +io/kuicksilver/kuicksilver-bom/' '-^OK +signature' '+^FAIL +tag +v9.9.9'

# online, through the curl stub
ONLINE=1 t "online: good release"       0 ':' '+5 files of 5 publications' '+^OK +signature +io/kuicksilver/kuicksilver-native-macosarm64/' \
  '+^OK +provenance +source commit' '+^OK +rebuild +klib/macos_arm64/libssl.a' '-^(DIFF|FAIL)'
ONLINE=1 STUB_NOANSWER='kuicksilver-native-android-9\.9\.9\.aar$' t "online: a listed file does not download" 1 ':' \
  '+^FAIL +central +io/kuicksilver/kuicksilver-native-android/9.9.9/kuicksilver-native-android-9.9.9.aar +\(listed on Central, but the download failed' \
  '+^FAIL +provenance +.*kuicksilver-native-android-9.9.9.aar +\(a subject of the provenance, missing here'
ONLINE=1 STUB_404='kuicksilver-native-jvm-9\.9\.9\.jar\.sha1$' t "online: no .sha1 on Central" 1 ':' \
  '+^FAIL +sha1 +.*kuicksilver-native-jvm-9.9.9.jar +\(good signature, but no \.sha1'
ONLINE=1 STUB_NOANSWER='^https://github\.invalid/' t "online: GitHub does not answer" 1 ':' \
  '+^FAIL +provenance +github/kuicksilver-9.9.9.intoto.jsonl +\(no answer from' '-^SKIPPED +provenance'
ONLINE=1 STUB_404='^https://github\.invalid/' t "online: 0.2.1 or later, GitHub answers 404" 1 ':' \
  '+^FAIL +provenance +github/kuicksilver-9.9.9.intoto.jsonl +\(not on the GitHub release'
ONLINE=1 t "online: traversal artifact id in the BOM" 1 \
  "sed -i.bak 's#<artifactId>kuicksilver-native</artifactId>#<artifactId>kuicksilver-native/../../../x</artifactId>#' $bom; rm $bom.bak; resign $bom" \
  "+^FAIL +central +BOM artifactId 'kuicksilver-native/../../../x' +\\(not a plain artifact id"
ONLINE=1 t "online: traversal URL in a module file" 1 \
  "sed -i.bak 's#../../kuicksilver-native-jvm/#../../../../etc/#' $mod; rm $mod.bak; resign $mod" \
  "+^FAIL +central +.*kuicksilver-native-9.9.9.module +\\(available-at '../../../../etc/" '+4 files of 4 publications' '-^OK .*etc/'
ONLINE=1 STUB_LISTING_EXTRA='../../../../x/evil.jar' t "online: traversal name in a directory listing" 1 ':' \
  '+^FAIL +central +io/kuicksilver/kuicksilver-native-jvm/9.9.9/../../../../x/evil.jar +\(not a plain file name' '-^OK .*evil'
echo "passed $pass, failed $fail"
[ "$fail" = 0 ]
