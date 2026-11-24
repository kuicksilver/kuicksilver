#!/usr/bin/env bash
# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
# Negative controls of tools/check/ar-diff.py (what tools/check/double-build.sh prints for an archive that differs), on
# archives written here byte by byte, no compiler or archiver: two identical archives pass silently; a member whose bytes
# differ is named with its offsets; a BSD __.SYMDEF that differs only past its last symbol name is called string-table
# padding (the Xcode ranlib case), one that differs in a symbol name is not; a member only one archive has, a header
# field (mtime), a GNU long name (the // table), and bytes between members are each reported; a file that is not an
# archive, and a member that runs past the end, exit 2.
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

def symdef(syms, pad):
    """BSD 32-bit index: syms = [(name, member offset)], the string table padded with `pad`."""
    strtab, ents = b"", b""
    for name, off in syms:
        ents += struct.pack("<II", len(strtab), off)
        strtab += name.encode() + b"\0"
    strtab += pad
    return struct.pack("<I", len(ents)) + ents + struct.pack("<I", len(strtab)) + strtab

def bsd(members, pad=b"\0\0\0\0", syms=(("_a", 0), ("_bb", 1)), mtime_b=0):
    out = b"!<arch>\n" + bsd_member("__.SYMDEF SORTED", symdef(syms, pad))
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
# System V / GNU: the // long-name table, /<offset> names, a trailing / on short names
def gnu(body_long):
    names = b"a_very_long_member_name.o/\n"
    out = b"!<arch>\n" + hdr("//", len(names)) + names + b"\n"   # 27 bytes: padded to an even offset
    out += hdr("short.o/", 4) + b"SSSS"
    out += hdr("/0", len(body_long)) + body_long
    return out
w("gnu1.a", gnu(b"LLLL")); w("gnu2.a", gnu(b"LLxL"))
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
check "negative_gnuLongNameResolved" 1 "member 2 'a_very_long_member_name.o': 4 vs 4 bytes, 1 differ, offsets 2\.\.2" gnu1.a gnu2.a
check "negative_framingNamed" 1 "every member is identical: the archive framing differs" odd1.a odd2.a
check "negative_notAnArchiveExit2" 2 "not an ar archive" base.a notar.a
check "negative_truncatedMemberExit2" 2 "runs past the end" trunc.a base.a
[ $rc = 0 ] && echo "ar-diff: all controls passed"
exit $rc
