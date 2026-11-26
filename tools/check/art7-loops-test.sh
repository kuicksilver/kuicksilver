#!/usr/bin/env bash
# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
# Negative controls of tools/check/art7-loops.py on dexdump fixtures (the shape of KuicksilverEngine.learnAltSvcFrames that
# aborted ART 7.0, cut down), one pair per rule where a rule can be shown both ways. Each fixture is one method whose loop
# makes a guarded call and copies a register with move-object; tools/check/art7-loops.py --help says what a site is.
#   site (exit 1): the shape (in a coroutine, a suspend fun, a plain method); a copy at the join it copies; a phi from a
#     join before the loop; two ways to the copy's join with no write; a call brought in by a small static method, by a
#     static chain of depth 3, by the small target of a guarded call, by the class a one-class entry names; a call on an
#     open class; a loop formed through a catch handler, by a switch; a public interface of the API (never automatic); an
#     ArrayList the dex subclasses (no framework-leaf).
#   no site (exit 0): the copy read later (liveness); the value read since its join; a move of the value to a register
#     read later; a value defined in the loop with no join; the copy not reached from the call without its register
#     written (forward); the call not reached from a join without it written (backward); a callee with a try block, over
#     32 code units, at depth 4; a private method, a final method, Object.getClass, a final owner class (the receiver's
#     type unknown), a final class; a receiver made by new-instance, declared of a final class, only null (also through
#     a range invoke); a class outside io/kuicksilver; the shape without a move-object copy (release); an unjudged call
#     on six classes, whose targets are not followed (IC_SIZE).
#   automatic (exit 0): framework-leaf (ArrayList), one-class-dex (an internal interface with one class), no-inline (every
#     target over 32 code units).
#   the allow file and the lock: a judged and an open site pass; refused: a fixed site still there, a stale entry, an entry
#     without a reason, with an unknown verdict, one-class without its class or naming one the dex lacks, a site not in
#     the lock, a lock count that changed, a stale lock line.
#   the dex: a switch whose table is not in the given dex fails loudly (exit 2).
# Every rule of the check fails at least one control when it is taken out (the sweep in docs/spec/art7-deopt-loops.md).
# Usage: art7-loops-test.sh
set -uo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT; rc=0
mkdir -p "$tmp/noapi" "$tmp/api/kuicksilver-x/api/android"
printf 'public abstract interface class io/kuicksilver/x/Iface {\n}\n' > "$tmp/api/kuicksilver-x/api/android/kuicksilver-x.api"
python3 -I - "$tmp" <<'PY'
import os, struct, sys, zipfile
out = sys.argv[1]
BASE = 0x1000
MARK = "sget-object v1, Lkotlin/coroutines/intrinsics/CoroutineSingletons;.COROUTINE_SUSPENDED:Lkotlin/coroutines/intrinsics/CoroutineSingletons; // field@0001"
A = "Lio/kuicksilver/x/A;"
ISEMPTY = "invoke-interface {v0}, Ljava/util/Map;.isEmpty:()Z // method@0004"
COPY = "move-object v6, v2"
OTHER = f"iget-object v2, v5, {A}.other:Ljava/lang/Object; // field@0003"
base = [0]

def dotted(d):
    return d[1:-1].replace("/", ".")

def method(cls, name, proto, body, regs=7, ins=2, size=20, access="0x0011 (PUBLIC FINAL)", catches=()):
    """one method of a dexdump -d: body is [(address, instruction)]; catches [(start, end, [(type, handler)])]"""
    b = base[0]; base[0] += 0x400
    lines = [f"    #0              : (in {cls})", f"      name          : '{name}'", f"      type          : '{proto}'",
             f"      access        : {access}", "      code          -", f"      registers     : {regs}", f"      ins           : {ins}",
             "      outs          : 2", f"      insns size    : {size} 16-bit code units",
             f"{b:06x}:                                        |[{b:06x}] {dotted(cls)}.{name}:{proto}"]
    lines += [f"{b + 2 * a:06x}: 0000                                   |{a:04x}: {t}" for a, t in body]
    if catches:
        lines.append(f"      catches       : {len(catches)}")
        for st, en, hs in catches:
            lines.append(f"        0x{st:04x} - 0x{en:04x}")
            lines += [f"          {t} -> 0x{h:04x}" for t, h in hs]
    else:
        lines.append("      catches       : (none)")
    lines += ["      positions     :", "        0x0000 line=42", "      locals        :", ""]
    return "\n".join(lines), b

def klass(desc, methods, access="0x0011 (PUBLIC FINAL)", sup="Ljava/lang/Object;", ifaces=()):
    t = [f"Class #0            -", f"  Class descriptor  : '{desc}'", f"  Access flags      : {access}", f"  Superclass        : '{sup}'",
         "  Interfaces        -"] + [f"    #0              : '{i}'" for i in ifaces] + [
         "  Static fields     -", "  Instance fields   -", "  Direct methods    -", "  Virtual methods   -"]
    return "\n".join(t + [m for m in methods]) + "\n"

def small(name, body, size=4, catches=()):
    return method("Lio/kuicksilver/x/Small;", name, "(Ljava/util/Map;)Z", body, regs=1, ins=1, size=size,
                  access="0x0019 (PUBLIC STATIC FINAL)", catches=catches)[0]

def helpers():
    call = lambda n: [(0, f"invoke-static {{v0}}, Lio/kuicksilver/x/Small;.{n}:(Ljava/util/Map;)Z // method@0005"), (3, "move-result v0"), (4, "return v0")]
    leaf = [(0, ISEMPTY), (3, "move-result v0"), (4, "return v0")]
    ret0 = lambda: [(0, "const/4 v0, #int 0 // #0"), (1, "return v0")]
    sm = [small("isEmpty", leaf), small("isEmptyBig", leaf, size=40),
          small("isEmptyTry", leaf, catches=[(0, 3, [("<any>", 4)])]),
          small("s1", call("s2")), small("s2", call("s3")), small("s3", call("s4")), small("s4", leaf),
          method("Lio/kuicksilver/x/Small;", "use", "(Ljava/lang/Object;)V", [(0, "return-void")], regs=1, ins=1, size=1,
                 access="0x0019 (PUBLIC STATIC FINAL)")[0]]
    open_ = [method("Lio/kuicksilver/x/Open;", "size", "()I", ret0(), regs=2, ins=1, size=2, access="0x0001 (PUBLIC)")[0],
             method("Lio/kuicksilver/x/Open;", "secret", "()I", ret0(), regs=2, ins=1, size=2, access="0x0002 (PRIVATE)")[0],
             method("Lio/kuicksilver/x/Open;", "fixedSize", "()I", ret0(), regs=2, ins=1, size=2, access="0x0011 (PUBLIC FINAL)")[0]]
    sub = [method("Lio/kuicksilver/x/Sub;", "size", "()I", ret0(), regs=2, ins=1, size=2, access="0x0001 (PUBLIC)")[0]]
    wide = "".join(klass(f"Lio/kuicksilver/x/WideImpl{n};", [method(f"Lio/kuicksilver/x/WideImpl{n};", "run", "()Z",
                   [(0, f"iget-object v0, v1, Lio/kuicksilver/x/WideImpl{n};.map:Ljava/util/Map; // field@000a"), (2, ISEMPTY),
                    (5, "move-result v0"), (6, "return v0")], regs=2, ins=1, size=7)[0]], ifaces=["Lio/kuicksilver/x/Wide;"])
                   for n in range(1, 7))
    impl = [method("Lio/kuicksilver/x/IfaceImpl;", "run", "()Z", ret0(), regs=2, ins=1, size=2)[0]]
    host = [method("Lio/kuicksilver/x/HostImpl;", "run", "()Z", [(0, "iget-object v0, v1, Lio/kuicksilver/x/HostImpl;.map:Ljava/util/Map; // field@000a"),
                                                                (2, ISEMPTY), (5, "move-result v0"), (6, "return v0")], regs=2, ins=1, size=7)[0]]
    big = [method("Lio/kuicksilver/x/BigImpl;", "run", "()Z", ret0(), regs=2, ins=1, size=50)[0]]
    return (klass("Lio/kuicksilver/x/Small;", sm) + klass("Lio/kuicksilver/x/Open;", open_, access="0x0001 (PUBLIC)")
            + klass("Lio/kuicksilver/x/Sub;", sub, sup="Lio/kuicksilver/x/Open;")
            + klass("Lio/kuicksilver/x/Iface;", [], access="0x0601 (PUBLIC INTERFACE ABSTRACT)")
            + klass("Lio/kuicksilver/x/IfaceImpl;", impl, ifaces=["Lio/kuicksilver/x/Iface;"])
            + klass("Lio/kuicksilver/x/Host;", [], access="0x0601 (PUBLIC INTERFACE ABSTRACT)")
            + klass("Lio/kuicksilver/x/HostImpl;", host, ifaces=["Lio/kuicksilver/x/Host;"])
            + klass("Lio/kuicksilver/x/Wide;", [], access="0x0601 (PUBLIC INTERFACE ABSTRACT)") + wide
            + klass("Lio/kuicksilver/x/Big;", [], access="0x0601 (PUBLIC INTERFACE ABSTRACT)")
            + klass("Lio/kuicksilver/x/BigImpl;", big, ifaces=["Lio/kuicksilver/x/Big;"]))

def shape(call=ISEMPTY, copy=COPY, recv=f"iget-object v0, v5, {A}.map:Ljava/util/Map; // field@0002", after_call=None, after_copy=None):
    """the learner's shape: a loop at 0005 (a join) that calls, copies v2 (dead) and writes v2 before its turn"""
    b = [(0x00, MARK), (0x02, recv), (0x04, "move-object v2, v0"), (0x05, call), (0x08, "move-result v3")]
    if after_call: b.append((0x09, after_call))
    b.append((0x0a, copy))
    if after_copy: b.append((0x0b, after_copy))
    b += [(0x0c, "if-nez v3, 0014 // +0008"), (0x0e, OTHER), (0x10, "goto 0005 // -000b"), (0x14, "return-object v1")]
    return b

dex_blobs = {}
def write(name, body, cls=A, mname="invokeSuspend", extra="", catches=(), blob=None):
    text, b = method(cls, mname, "(Ljava/lang/Object;)Ljava/lang/Object;", body, catches=catches)
    with open(os.path.join(out, name + ".dump"), "w") as f:
        f.write("Processing 'x.zip'...\nOpened 'x.zip:classes.dex', DEX version '037'\n")
        f.write(klass(cls, [text]) + helpers() + extra)
    with zipfile.ZipFile(os.path.join(out, name + ".zip"), "w") as z:
        if blob is not None:
            z.writestr("classes.dex", blob(b))

RECV = lambda t: f"iget-object v0, v5, {A}.map:{t}; // field@0002"
write("debug", shape())
write("suspendfun", shape(), cls="Lio/kuicksilver/x/B;", mname="load")
write("plain", shape(), cls="Lio/kuicksilver/x/C;", mname="plainLoop")
write("outside", shape(), cls="Lother/lib/D;")
write("release", shape(copy="move v4, v3"))
write("live", shape(after_copy="invoke-static {v6}, Lio/kuicksilver/x/Small;.use:(Ljava/lang/Object;)V // method@0006"))
write("usedsincejoin", shape(after_call="invoke-static {v2}, Lio/kuicksilver/x/Small;.use:(Ljava/lang/Object;)V // method@0006"))
write("nojoin", shape(after_call=OTHER))
write("via", shape(call="invoke-static {v0}, Lio/kuicksilver/x/Small;.isEmpty:(Ljava/util/Map;)Z // method@0005"))
write("bigcallee", shape(call="invoke-static {v0}, Lio/kuicksilver/x/Small;.isEmptyBig:(Ljava/util/Map;)Z // method@0005"))
write("trycallee", shape(call="invoke-static {v0}, Lio/kuicksilver/x/Small;.isEmptyTry:(Ljava/util/Map;)Z // method@0005"))
write("depth3", shape(call="invoke-static {v0}, Lio/kuicksilver/x/Small;.s2:(Ljava/util/Map;)Z // method@0005"))
write("depth4", shape(call="invoke-static {v0}, Lio/kuicksilver/x/Small;.s1:(Ljava/util/Map;)Z // method@0005"))
write("open", shape(call="invoke-virtual {v0}, Lio/kuicksilver/x/Open;.size:()I // method@0006", recv=RECV("Lio/kuicksilver/x/Open")))
write("private", shape(call="invoke-virtual {v0}, Lio/kuicksilver/x/Open;.secret:()I // method@0006", recv=RECV("Lio/kuicksilver/x/Open")))
write("final", shape(call="invoke-virtual {v0}, Lio/kuicksilver/x/Sub;.size:()I // method@0006", recv=RECV("Lio/kuicksilver/x/Sub")))
write("declaredfinal", shape(call="invoke-virtual {v0}, Lio/kuicksilver/x/Open;.size:()I // method@0006", recv=RECV("Lio/kuicksilver/x/Sub")))
write("fresh", shape(call="invoke-virtual {v0}, Lio/kuicksilver/x/Open;.size:()I // method@0006", recv="new-instance v0, Lio/kuicksilver/x/Open; // type@0007"))
write("null", shape(call="invoke-virtual {v0}, Lio/kuicksilver/x/Open;.size:()I // method@0006", recv="const/4 v0, #int 0 // #0"))
write("range", shape(call="invoke-virtual/range {v0 .. v0}, Lio/kuicksilver/x/Open;.size:()I // method@0006", recv="const/4 v0, #int 0 // #0"))
write("leaf", shape(call="invoke-virtual {v0}, Ljava/util/ArrayList;.size:()I // method@0008", recv=RECV("Ljava/util/ArrayList")))
write("leafsub", shape(call="invoke-virtual {v0}, Ljava/util/ArrayList;.size:()I // method@0008", recv=RECV("Ljava/util/ArrayList")),
      extra=klass("Lio/kuicksilver/x/MyList;", [], sup="Ljava/util/ArrayList;"))
write("onedex", shape(call="invoke-interface {v0}, Lio/kuicksilver/x/Iface;.run:()Z // method@0009", recv=RECV("Lio/kuicksilver/x/Iface")))
write("guardedvia", shape(call="invoke-interface {v0}, Lio/kuicksilver/x/Host;.run:()Z // method@0009", recv=RECV("Lio/kuicksilver/x/Host")))
write("noinline", shape(call="invoke-interface {v0}, Lio/kuicksilver/x/Big;.run:()Z // method@0009", recv=RECV("Lio/kuicksilver/x/Big")))
# a phi from a join before the loop: v2 is set on either side of an if, the loop never writes it
write("joinbefore", [(0x00, MARK), (0x02, f"iget-object v0, v5, {A}.map:Ljava/util/Map; // field@0002"), (0x04, "if-eqz v0, 0008 // +0004"),
                     (0x06, "move-object v2, v0"), (0x07, "goto 000a // +0003"), (0x08, OTHER), (0x0a, ISEMPTY),
                     (0x0d, "move-result v3"), (0x0e, COPY), (0x0f, "if-nez v3, 0014 // +0005"), (0x11, "goto 000a // -0007"),
                     (0x14, "return-object v1")])
# the copy at the join itself, the call after it (the loop leads back to the join): a site
write("atjoin", [(0x00, MARK), (0x02, f"iget-object v0, v5, {A}.map:Ljava/util/Map; // field@0002"), (0x04, "move-object v2, v0"),
                 (0x05, COPY), (0x06, ISEMPTY), (0x09, "move-result v3"), (0x0c, "if-nez v3, 0010 // +0004"),
                 (0x0e, "goto 0005 // -0009"), (0x10, "return-object v1")])
# two ways from the loop's join H to the copy's join J: through the call S, or around it (Z); v2 written on S's way
# after the call (only the forward test decides), before it (only the backward test decides), or nowhere (a site)
def twopaths(write):
    w = lambda where: OTHER if write == where else "const/4 v4, #int 0 // #0"
    return [(0x00, MARK), (0x02, f"iget-object v0, v5, {A}.map:Ljava/util/Map; // field@0002"), (0x04, "move-object v2, v0"),
            (0x05, "if-eqz v0, 000f // +000a"), (0x07, w("before")), (0x08, ISEMPTY), (0x0b, "move-result v3"),
            (0x0c, w("after")), (0x0d, "goto 0010 // +0003"), (0x0f, "const/4 v3, #int 0 // #0"), (0x10, COPY),
            (0x11, "if-nez v3, 0016 // +0005"), (0x13, "goto 0005 // -000e"), (0x16, "return-object v1")]
write("twopaths", twopaths(None))
write("forward", twopaths("after"))
write("backward", twopaths("before"))
# a move of v2 to a register read later, between the join and the dead copy: the value is used, no dead phi
write("movelive", shape(after_call="move-object v4, v2", after_copy="invoke-static {v4}, Lio/kuicksilver/x/Small;.use:(Ljava/lang/Object;)V // method@0006"))
# a final owner class with a method not marked final, the receiver's type unknown (an array element)
write("finalowner", shape(call="invoke-virtual {v0}, Lio/kuicksilver/x/Sub;.size:()I // method@0006", recv="aget-object v0, v5, v3"))
# a final method of an open class, and Object.getClass (final in the framework), the receiver's type unknown
write("finalmethod", shape(call="invoke-virtual {v0}, Lio/kuicksilver/x/Open;.fixedSize:()I // method@0006", recv="aget-object v0, v5, v3"))
write("frameworkfinal", shape(call="invoke-virtual {v0}, Ljava/lang/Object;.getClass:()Ljava/lang/Class; // method@000b", recv="aget-object v0, v5, v3"))
# a guarded call on an interface six classes of the dex implement: not followed unless an entry names the class
write("wide", shape(call="invoke-interface {v0}, Lio/kuicksilver/x/Wide;.run:()Z // method@0009", recv=RECV("Lio/kuicksilver/x/Wide")))
# a loop through a catch handler: the call throws into a handler before it, which goes on into the call again
write("catchloop", [(0x00, MARK), (0x02, f"iget-object v0, v5, {A}.map:Ljava/util/Map; // field@0002"), (0x04, "move-object v2, v0"),
                    (0x05, "goto 0008 // +0003"), (0x06, "move-exception v4"), (0x07, COPY), (0x08, ISEMPTY),
                    (0x0b, "move-result v3"), (0x0c, "return-object v1")],
      catches=[(0x08, 0x0b, [("<any>", 0x06)])])
# a loop formed by a switch: its table (in the dex) sends one case back to 0005
def switch_body():
    return [(0x00, MARK), (0x02, f"iget-object v0, v5, {A}.map:Ljava/util/Map; // field@0002"), (0x04, "move-object v2, v0"),
            (0x05, ISEMPTY), (0x08, "move-result v3"), (0x09, COPY), (0x0a, OTHER), (0x0c, "packed-switch v3, 00000010 // +00000004"),
            (0x0f, "return-object v1"), (0x10, "packed-switch-data (6 units)")]
def table(b):
    d = bytearray(b + 2 * 0x20)
    struct.pack_into("<HHii", d, b + 2 * 0x10, 0x0100, 1, 0, 0x05 - 0x0c)
    return bytes(d)
write("switchloop", switch_body(), blob=table)
write("switchnodex", switch_body())
PY

# expect <0|1|2> <what> <pattern> <fixture> [art7-loops.py options...]
expect() {
  local want="$1" what="$2" pat="$3" fx="$4"; shift 4
  python3 -I "$here/art7-loops.py" --allow "$tmp/allow" --api-root "$tmp/noapi" "$@" "$tmp/$fx.dump:$tmp/$fx.zip" > "$tmp/out.txt" 2>&1; local got=$?
  if [ "$got" = "$want" ] && grep -qF -- "$pat" "$tmp/out.txt"; then echo "ok: $( [ "$want" != 0 ] && echo 'negative: ')$what"
  else echo "FAIL: $what (exit $got, want $want and '$pat')"; sed 's/^/  | /' "$tmp/out.txt"; rc=1; fi
}
# expect_not <0|1|2> <what> <pattern that must not show> <fixture> [options...]
expect_not() {
  local want="$1" what="$2" pat="$3" fx="$4"; shift 4
  python3 -I "$here/art7-loops.py" --allow "$tmp/allow" --api-root "$tmp/noapi" "$@" "$tmp/$fx.dump:$tmp/$fx.zip" > "$tmp/out.txt" 2>&1; local got=$?
  if [ "$got" = "$want" ] && ! grep -qF -- "$pat" "$tmp/out.txt"; then echo "ok: $what"
  else echo "FAIL: $what (exit $got, want $want and no '$pat')"; sed 's/^/  | /' "$tmp/out.txt"; rc=1; fi
}
A='io.kuicksilver.x.A.invokeSuspend'
NONE="0 methods with guarded calls"
: > "$tmp/allow"
expect 1 "the shape: an interface call in a loop that copies a dead phi" "$A | java.util.Map.isEmpty" debug
expect 1 "the same in a suspend fun" "io.kuicksilver.x.B.load | java.util.Map.isEmpty" suspendfun
expect 1 "the same in a method that is no state machine" "io.kuicksilver.x.C.plainLoop | java.util.Map.isEmpty" plain
expect 1 "a copy at the join it copies" "$A | java.util.Map.isEmpty" atjoin
expect 1 "a phi from a join before the loop, never written in it" "$A | java.util.Map.isEmpty" joinbefore
expect 1 "two ways to the copy's join, v2 written on neither" "$A | java.util.Map.isEmpty" twopaths
expect 1 "a call brought in by a small static method" "via io.kuicksilver.x.Small.isEmpty" via
expect 1 "a static chain of depth 3" "<- io.kuicksilver.x.Small.s2" depth3
expect 1 "a call brought in by the small target of a guarded call" "via io.kuicksilver.x.HostImpl.run" guardedvia
expect 1 "a call on an open class" "$A | io.kuicksilver.x.Open.size" open
expect 1 "a loop formed through a catch handler" "$A | java.util.Map.isEmpty" catchloop
expect 1 "a loop formed by a switch" "$A | java.util.Map.isEmpty" switchloop
expect 2 "a switch whose table is not in the given dex" "the dex bytes are not given" switchnodex
expect 1 "an ArrayList the dex subclasses: no framework-leaf" "$A | java.util.ArrayList.size" leafsub
expect 1 "a public interface of the API: no automatic verdict" "$A | io.kuicksilver.x.Iface.run" onedex --api-root "$tmp/api"
expect 0 "the release shape: no move-object copy" "$NONE" release
expect 0 "the copy read later (liveness)" "$NONE" live
expect 0 "the value read since its join" "$NONE" usedsincejoin
expect 0 "a value defined in the loop, no join" "$NONE" nojoin
expect 0 "the copy not reached from the call without its register written (forward)" "$NONE" forward
expect 0 "the call not reached from a join without the register written (backward)" "$NONE" backward
expect 0 "a move of the value to a register read later counts as a use" "$NONE" movelive
expect 0 "a final owner class binds the call, the receiver's type unknown" "$NONE" finalowner
expect 0 "a final method of an open class binds the call" "$NONE" finalmethod
expect 0 "a final method of the framework (Object.getClass) binds the call" "$NONE" frameworkfinal
expect_not 1 "an unjudged call on six classes: their targets not followed (IC_SIZE)" "via io.kuicksilver.x.WideImpl" wide
expect 0 "a callee with a try block is not inlined" "$NONE" trycallee
expect 0 "a callee over 32 code units is not inlined" "$NONE" bigcallee
expect 0 "a static chain of depth 4 is not inlined" "$NONE" depth4
expect 0 "a private method is bound" "$NONE" private
expect 0 "a call on a final class is bound" "$NONE" final
expect 0 "a receiver declared of a final class" "$NONE" declaredfinal
expect 0 "a receiver made by new-instance" "$NONE" fresh
expect 0 "a receiver that is only null" "$NONE" null
expect 0 "the same through a range invoke ({v0 .. v0})" "$NONE" range
expect 0 "a class outside io/kuicksilver" "$NONE" outside
expect 0 "framework-leaf: an ArrayList" "1 automatic" leaf
expect 0 "one-class-dex: an internal interface with one class" "1 automatic" onedex
expect 0 "no-inline: every target over 32 code units" "1 automatic" noinline

printf '%s\n' "$A | java.util.Map.isEmpty | one-class java.util.HashMap | the map is always a HashMap made here" > "$tmp/allow"
expect 0 "a judged site" "1 judged (0 open)" debug
printf '%s\n' "$A | io.kuicksilver.x.Wide.run | one-class io.kuicksilver.x.WideImpl3 | always the third class, made here" > "$tmp/allow"
expect 1 "a one-class entry's class is followed, whatever the bound" "via io.kuicksilver.x.WideImpl3.run" wide
printf '%s\n' "$A | io.kuicksilver.x.Wide.run | one-class io.kuicksilver.x.Nope | always a class the dex lacks" > "$tmp/allow"
expect 1 "a one-class entry naming a class the dex does not define" "which wide.dump does not define" wide
printf '%s\n' "$A | java.util.Map.isEmpty | one-class | the map is always a HashMap made here" > "$tmp/allow"
expect 1 "a one-class entry without its class" "one-class <class>" debug
printf '%s\n' "$A | java.util.Map.isEmpty | open | left for later: a helper would fix it" > "$tmp/allow"
expect 0 "an open site passes, counted" "1 judged (1 open)" debug
printf '%s\n' "$A | java.util.Map.isEmpty | fixed | moved into a helper ART does not inline" > "$tmp/allow"
expect 1 "an entry judged fixed whose site is still there" "judged fixed, but the loop still makes the call" debug
printf '%s\n' "$A | java.util.Map.size | one-class java.util.HashMap | the map is always a HashMap made here" > "$tmp/allow"
expect 1 "a stale entry" "is no site any more" release
printf '%s\n' "$A | java.util.Map.isEmpty | one-class java.util.HashMap | short" > "$tmp/allow"
expect 1 "an entry without a reason" "at least four words" debug
printf '%s\n' "$A | java.util.Map.isEmpty | fine | the map is always a HashMap made here" > "$tmp/allow"
expect 1 "an unknown verdict" "unknown verdict" debug

: > "$tmp/allow"
printf '%s\n' "$A | java.util.Map.isEmpty | 1" > "$tmp/lock"
expect 0 "a site listed in the lock" "1 known" debug --known "$tmp/lock"
printf '%s\n' "$A | java.util.Map.isEmpty | 2" > "$tmp/lock"
expect 1 "a lock count that changed (a loop more or less)" "listed with 2 call instruction(s)" debug --known "$tmp/lock"
: > "$tmp/lock"
expect 1 "a site not listed in the lock" "nor listed in lock" debug --known "$tmp/lock"
printf '%s\n' "$A | java.util.Map.isEmpty | 1" > "$tmp/lock"
expect 1 "a stale lock line" "is no site any more: remove the line" release --known "$tmp/lock"
exit $rc
