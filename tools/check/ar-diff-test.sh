#!/usr/bin/env bash
# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
# Negative controls of tools/check/ar-diff.py (what tools/check/double-build.sh prints for an archive that differs), on
# archives written here byte by byte, no compiler or archiver: two identical archives pass silently; a member whose bytes
# differ is named with its offsets; a BSD __.SYMDEF that differs only past its last symbol name is called string-table
# padding (the Xcode ranlib case), one that differs in a symbol name is not; a member only one archive has, a header
# field (mtime), a GNU long name (the // table), a System V / GNU "/" index, and bytes between members are each
# reported; the same padding rule holds for a __.SYMDEF_64; a file that is not an archive, a member that runs past the
# end, and a BSD name length that is no number, exit 2 (never a traceback). --llvm-index passes llvm-ar's __.SYMDEF and
# __.SYMDEF_64 with zeroed headers and refuses Xcode's __.SYMDEF SORTED, a member with an mtime, and a non-archive.
# Usage: ar-diff-test.sh
set -uo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
rc=0
python3 -I - "$tmp" <<'PY'
import struct, sys, os
d = sys.argv[1]

def hdr(name, size, mtime=0):
    return f"{name:<16}{mtime:<12}{0:<6}{0:<6}{'100644':<8}{size:<10}`\n".encode()

def bsd_member(name, body, mtime=0):
    n = name.encode()
    nl = (len(n) + 8) & ~7   # name padded with NULs, as cctools and llvm-ar do
    data = n.ljust(nl, b"\0") + body
    out = hdr(f"#1/{nl}", len(data), mtime) + data
    return out + (b"\n" if len(data) & 1 else b"")

def symdef(syms, pad, w=4):
    """BSD index (w=4: __.SYMDEF, w=8: __.SYMDEF_64): syms = [(name, member offset)], the string table padded with `pad`."""
    f = "<I" if w == 4 else "<Q"
    strtab, ents = b"", b""
    for name, off in syms:
        ents += struct.pack(f, len(strtab)) + struct.pack(f, off)
        strtab += name.encode() + b"\0"
    strtab += pad
    return struct.pack(f, len(ents)) + ents + struct.pack(f, len(strtab)) + strtab

def bsd(members, pad=b"\0\0\0\0", syms=(("_a", 0), ("_bb", 1)), mtime_b=0, index="__.SYMDEF SORTED"):
    out = b"!<arch>\n" + bsd_member(index, symdef(syms, pad, 8 if "_64" in index else 4))
    for name, body in members:
        out += bsd_member(name, body, mtime_b if name == "b.o" else 0)
    return out

def w(name, data):
    with open(os.path.join(d, name), "wb") as f:
        f.write(data)

m = [("a.o", b"AAAAAAAA"), ("b.o", b"BBBBBBBB")]
w("base.a", bsd(m)); w("same.a", bsd(m))
w("member.a", bsd([("a.o", b"AAAAAAAA"), ("b.o", b"BBBBxBBB")]))
w("pad.a", bsd(m, pad=b"\0\x1a\x88\x03"))
w("sym.a", bsd(m, syms=(("_a", 0), ("_bc", 1))))
w("extra.a", bsd(m + [("c.o", b"CC")]))
w("mtime.a", bsd(m, mtime_b=1759363200))
w("b64.a", bsd(m, index="__.SYMDEF_64")); w("b64pad.a", bsd(m, pad=b"\0\x01\x02\x03", index="__.SYMDEF_64"))
w("b64sym.a", bsd(m, syms=(("_a", 0), ("_bc", 1)), index="__.SYMDEF_64"))
w("llvm.a", bsd(m, index="__.SYMDEF")); w("llvmtime.a", bsd(m, index="__.SYMDEF", mtime_b=1759363200))
w("badname.a", b"!<arch>\n" + hdr("#1/x", 4) + b"abcd")
# System V / GNU: the // long-name table, /<offset> names, a trailing / on short names
def gnu(body_long, sym=b"\0\0\0\x01\0\0\0\x5c_xy\0"):
    names = b"a_very_long_member_name.o/\n"
    out = b"!<arch>\n" + hdr("/", len(sym)) + sym   # the System V index: a count, offsets, names
    out += hdr("//", len(names)) + names + b"\n"   # 27 bytes: padded to an even offset
    out += hdr("short.o/", 4) + b"SSSS"
    out += hdr("/0", len(body_long)) + body_long
    return out
w("gnu1.a", gnu(b"LLLL")); w("gnu2.a", gnu(b"LLxL")); w("gnu3.a", gnu(b"LLLL", sym=b"\0\0\0\x01\0\0\0\x5c_xz\0"))
odd = lambda sep: b"!<arch>\n" + hdr("x.o/", 3) + b"XXX" + sep + hdr("y.o/", 2) + b"YY"
w("odd1.a", odd(b"\n")); w("odd2.a", odd(b"\n\n"))
w("notar.a", b"not an archive\n")
w("trunc.a", b"!<arch>\n" + hdr("t.o/", 100) + b"short")
PY
run() { python3 -I "$here/ar-diff.py" "$tmp/$1" "$tmp/$2" 2>&1; }
check() { # <name> <expected exit> <grep -E pattern or empty for no output> <a> <b>
  local out code
  out=$(run "$4" "$5"); code=$?
  local ok=1
  if [ -z "$3" ]; then [ -z "$out" ] || ok=0; else grep -qE -- "$3" <<< "$out" || ok=0; fi
  if [ "$code" = "$2" ] && [ $ok = 1 ]; then
    echo "PASS $1"
  else
    echo "FAIL $1: exit $code: $out"; rc=1
  fi
}
check "identical archives: exit 0, nothing printed" 0 "" base.a same.a
check "negative_memberBytesNamed" 1 "member 2 'b.o': 8 vs 8 bytes, 1 differ, offsets 4\.\.4" base.a member.a
check "negative_indexPaddingCalledPadding" 1 "archive index '__.SYMDEF SORTED'.*3 differ.*string table's padding" base.a pad.a
out=$(run base.a sym.a)
if grep -q "archive index '__.SYMDEF SORTED'" <<< "$out" && ! grep -q padding <<< "$out"; then echo "PASS negative_indexSymbolNameNotPadding"; else echo "FAIL negative_indexSymbolNameNotPadding: $out"; rc=1; fi
check "negative_extraMemberNamed" 1 "member 3 'c.o' \(2 bytes\): only in the second" base.a extra.a
check "negative_headerFieldNamed" 1 "member 2 'b.o': header fields .*0 0 0 100644 vs 1759363200 0 0 100644" base.a mtime.a
check "negative_gnuLongNameResolved" 1 "member 3 'a_very_long_member_name.o': 4 vs 4 bytes, 1 differ, offsets 2\.\.2" gnu1.a gnu2.a
check "negative_gnuIndexNamed" 1 "member 0 archive index '/': 12 vs 12 bytes, 1 differ, offsets 10\.\.10" gnu1.a gnu3.a
check "identical __.SYMDEF_64 archives: exit 0" 0 "" b64.a b64.a
check "negative_index64PaddingCalledPadding" 1 "archive index '__.SYMDEF_64'.*3 differ.*string table's padding" b64.a b64pad.a
out=$(run b64.a b64sym.a)
if grep -q "archive index '__.SYMDEF_64'" <<< "$out" && ! grep -q padding <<< "$out"; then echo "PASS negative_index64SymbolNameNotPadding"; else echo "FAIL negative_index64SymbolNameNotPadding: $out"; rc=1; fi
check "negative_badBsdNameLengthExit2" 2 "bad BSD name length '#1/x'" badname.a base.a
check "negative_framingNamed" 1 "every member is identical: the archive framing differs" odd1.a odd2.a
check "negative_notAnArchiveExit2" 2 "not an ar archive" base.a notar.a
check "negative_truncatedMemberExit2" 2 "runs past the end" trunc.a base.a
li() { python3 -I "$here/ar-diff.py" --llvm-index "$@" 2>&1; }
lcheck() { # <name> <expected exit> <pattern or empty> <archive>...
  local name="$1" code="$2" pat="$3" out c; shift 3; out=$(li "${@/#/$tmp/}"); c=$?
  if [ "$c" = "$code" ] && { [ -z "$pat" ] && [ -z "$out" ] || [ -n "$pat" ] && grep -qE -- "$pat" <<< "$out"; }; then echo "PASS $name"; else echo "FAIL $name: exit $c: $out"; rc=1; fi
}
lcheck "--llvm-index: llvm-ar's __.SYMDEF and __.SYMDEF_64 pass" 0 "" llvm.a b64.a
lcheck "negative_llvmIndexRefusesXcodeSorted" 1 "first member '__.SYMDEF SORTED', not llvm-ar's" llvm.a base.a
lcheck "negative_llvmIndexRefusesMemberMtime" 1 "1 member header\(s\) with a nonzero mtime.*'b.o' 1759363200" llvmtime.a
lcheck "negative_llvmIndexNotAnArchiveExit2" 2 "not an ar archive" notar.a
[ $rc = 0 ] && echo "ar-diff: all controls passed"
exit $rc
