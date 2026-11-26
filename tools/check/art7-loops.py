#!/usr/bin/env python3
# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
"""Loops that ART 7.x (Android 7.0/7.1, API 24/25) can deoptimize into a GC abort, found in an app's dex.

The crash class (docs/spec/art7-deopt-loops.md, KuicksilverEngine.learnAltSvcFrames): ART 7's JIT compiles a hot method
with the inline caches the interpreter filled, and inlines the target of an invoke-virtual or invoke-interface that saw one
receiver class (or a few) behind a class guard that deoptimizes when another class comes. The deoptimization fills the
dex registers the compiled code has no value for with 0xEBADDE09 (kDeadValue): a phi that only environments use is such a
register, ART 7 drops it (ssa_phi_elimination). If the interpreter that goes on from there runs a move-object of that
register (a debug build's dex copies its locals at each loop turn), mterp's move-object puts the raw 0xEBADDE09 into the
frame's references and the next GC aborts ("Tried to mark 0xebadde09 not contained by any spaces").

A site, in the dex an app gets (dexdump -d of R8's or D8's output, with the zip of the dex files for the switch tables):
  in a method of a class under io/kuicksilver, a loop (the instructions on a cycle through a backward branch: reachable
  from the branch's target and reaching the branch; exception edges and switch targets included), a dead phi copy in that
  loop (a move-object whose value no instruction other than a move reads after it, nor since the join it came from: the
  phi; every join counts, whether ART builds a phi there or not), and in the loop an invoke-virtual or invoke-interface that ART 7
  may guard on an inline cache, at a point where the copied register holds a join's value and from which the copy is
  reached without the register being written. Guarded: not bound to one target (a final class or method, a private
  method, a final class of java.lang, Object.getClass and the final methods of Enum), not on a receiver made by
  new-instance or declared of a final class (ART's type propagation knows the class). ART 7 inlines a callee of at most 32
  code units without a try block, up to a depth of 3: the calls of such a callee are sites too ("via" in the report),
  whether it is static, direct or bound (with the argument types passed in), or the target of a guarded call: the class a
  one-class entry names, else every class of the dex that can reach the call when there are at most 5 (an inline cache
  holds them all; for a wider type, an unjudged site's verdict answers for its targets).
  An inlined callee's own calls are cached in the callee's profile, which every caller of the callee in the process shares
  (ART 7's inliner reads the callee's inline caches): a "via" site is judged against every caller of that callee, not
  against the loop's method alone.
Automatic verdicts, from the class hierarchy of the dex (no entry needed), never for a type an application can implement
(a public non-final type of Kuicksilver's API, read from the */api/android/*.api dumps, or a non-final type of another
library) nor for a framework type:
  no-inline       every class of the dex the call can reach runs a method ART 7 cannot inline: no guard is compiled
  one-class-dex   one concrete class of the dex can reach the call
  framework-leaf  the receiver is a framework class no framework API hands this code a subclass of (ArrayList,
                  LinkedHashMap, the atomics...) and the dex subclasses it nowhere this code's values come from
Any other site needs an entry in tools/check/art7-loops.allow: <class>.<method> | <owner>.<name> | <verdict> | <reason>
(<class> the dex class, <owner>.<name> the called method as the dex names it; one entry covers the owner's every site in
that method; reason: at least four words). Verdicts:
  one-class <class>  only <class> reaches the site whatever runs, for a via site from every caller of its callee (the
              reason says why); the check follows that class's target into its body
  cold        the method runs so rarely (once per engine or endpoint) that ART 7 does not compile it
  fixed       the call was moved out of the loop; must not show as a site any more
  open        a site that can deoptimize, left as it is: the reason says why and what would fix it
Usage: art7-loops.py [--allow FILE] [--api-root DIR] [--known FILE | --write-known FILE] [--report] <dexdump>:<dex zip> [...]
  --known: a lock of sites accepted without a verdict, <class>.<method> | <owner>.<name> | <n>, n the number of call
  instructions of that site (a new loop with the same call raises it), for the debug dex (tools/check/art7-loops.sh); a
  site neither judged nor listed with its count fails, so does a line no site needs. --write-known writes the lock.
  Without --known, an entry of the allow file that no site needs fails. --report prints every site. --api-root: the
  repository whose */api/android/*.api files name the public types (default: this one).
  exit 0 when every site is judged or listed; 1 on a finding; 2 on a usage error or a dex it cannot read.
Not seen: deoptimizations that are not inline-cache guards (bounds-check elimination's, a debugger's), a dead value the
interpreter reads otherwise than by move-object, loops in other libraries' code (kotlinx.coroutines, Ktor, an app's own),
ART's own type knowledge beyond the declared types (a guard this check reports may never be compiled), the classes the
app adds to a type an app cannot implement only by Kotlin's rules (internal types).
"""
import collections
import glob
import os
import re
import struct
import sys
import zipfile

sys.dont_write_bytecode = True

INLINE_MAX = 32          # kDefaultInlineMaxCodeUnits (ART 7.0 compiler_options.h), passed by the JIT
INLINE_DEPTH = 3         # kDefaultInlineDepthLimit (ART 7.0)
IC_SIZE = 5              # InlineCache::kIndividualCacheSize (ART 7.0): the classes one call site's cache holds
PREFIX = "Lio/kuicksilver/"
VERDICTS = ("one-class", "cold", "fixed", "open")
# framework classes that are final, whose calls ART binds without an inline cache
FINAL_FRAMEWORK = re.compile(
    r"^Ljava/lang/(String|StringBuilder|StringBuffer|Integer|Long|Short|Byte|Boolean|Character|Double|Float|Class|Math|"
    r"StrictMath|System|Void)(;|\$)|^Lsun/misc/Unsafe;")
# final methods of open framework classes
FINAL_FRAMEWORK_METHODS = {("Ljava/lang/Object;", "getClass"), ("Ljava/lang/Enum;", "ordinal"), ("Ljava/lang/Enum;", "name"),
                           ("Ljava/lang/Enum;", "compareTo"), ("Ljava/lang/Enum;", "equals"), ("Ljava/lang/Enum;", "hashCode"),
                           ("Ljava/lang/Enum;", "getDeclaringClass")}
LEAF_FRAMEWORK = {  # framework classes no framework API hands this code a subclass of; checked: the dex extends none
    "Ljava/util/ArrayList;", "Ljava/util/LinkedHashMap;", "Ljava/util/LinkedHashSet;", "Ljava/util/ArrayDeque;",
    "Ljava/util/concurrent/atomic/AtomicBoolean;", "Ljava/util/concurrent/atomic/AtomicInteger;",
    "Ljava/util/concurrent/atomic/AtomicLong;", "Ljava/util/concurrent/atomic/AtomicReference;",
    "Ljava/util/concurrent/atomic/AtomicReferenceArray;", "Ljava/util/concurrent/atomic/AtomicIntegerArray;",
    "Ljava/util/concurrent/ConcurrentHashMap;", "Ljava/util/concurrent/ConcurrentLinkedQueue;",
    "Ljava/util/concurrent/ConcurrentLinkedDeque;", "Ljava/util/concurrent/locks/ReentrantLock;",
}
# subclasses of those that other libraries in the dex define for their own use, never handed to this code's collections
FOREIGN_SUBCLASSES = {"Lkotlin/reflect/jvm/internal/impl/types/model/ArgumentList;", "Lio/ktor/util/LRUCache;"}

HDR = re.compile(r"^\s*([0-9a-f]+):\s.*\|\[([0-9a-f]+)\] (.*)$")
INS = re.compile(r"^([0-9a-f]+):\s[0-9a-f .]*\|([0-9a-f]{4}): (\S+)(?: (.*))?$")
INVOKE = re.compile(r"^\{([^}]*)\}, (L[^;]+;)\.([^:]+):(\([^)]*\)\S+)")
BRANCH_TARGET = re.compile(r"(?:^|, )([0-9a-f]{4,8}) // [+-]")
REG = re.compile(r"\b([vp]\d+)\b")
RANGE = re.compile(r"^\s*v(\d+)\s*\.\.\s*v(\d+)\s*$")
MOVE_OBJECT = re.compile(r"^move-object(/from16|/16)?$")
# ops that write their first register
WRITES_FIRST = re.compile(r"^(move|const|new-|iget|sget|aget|check-cast|instance-of|array-length|neg-|not-|int-to|long-to|"
                          r"float-to|double-to|add-|sub-|mul-|div-|rem-|and-|or-|xor-|shl-|shr-|ushr-|rsub-|cmp)")
NO_READ_FIRST = re.compile(r"^(const|new-instance|move-result|move-exception|sget)")
TWO_ADDR = re.compile(r"/2addr$")
FIELD_TYPE = re.compile(r";\.[^:]+:(\S+)")
RETURN_TYPE = re.compile(r"\)(\S+?)(?: //|$)")


class DexError(Exception):
    """a dex this check cannot read as it must (a switch table it cannot find)"""


class Method:
    __slots__ = ("cls", "name", "proto", "access", "size", "tries", "ins", "catches", "fileoff", "dex", "is_abstract", "regs",
                 "nins", "lines", "_succ", "_back", "_pred", "_pos", "_live", "_info")

    def __init__(self, cls, name, proto, access):
        self.cls, self.name, self.proto, self.access = cls, name, proto, access
        self.size, self.tries, self.ins, self.catches = 0, 0, [], []
        self.fileoff, self.dex, self.is_abstract = {}, None, True
        self.regs = self.nins = 0
        self.lines = []
        self._succ = self._back = self._pred = self._pos = self._live = self._info = None

    @property
    def key(self):
        return f"{self.cls}.{self.name}:{self.proto}"

    def inlinable(self):
        return (not self.is_abstract) and self.tries == 0 and self.size <= INLINE_MAX and "NATIVE" not in self.access


class Klass:
    __slots__ = ("desc", "access", "sup", "ifaces", "methods")

    def __init__(self, desc):
        self.desc, self.access, self.sup, self.ifaces, self.methods = desc, "", None, [], {}

    def final(self):
        return "FINAL" in self.access

    def interface(self):
        return "INTERFACE" in self.access

    def abstract(self):
        return "ABSTRACT" in self.access


def parse(dump, dexes):
    """the classes of a dexdump -d of a zip of dex files (dexes: entry name -> bytes; one 'Opened' line per dex)"""
    classes = {}
    dex_bytes = next(iter(dexes.values())) if len(dexes) == 1 else None
    k = m = None
    section = None
    pending = None  # (name, proto, access) before the code header
    in_ifaces = False
    with open(dump, errors="replace") as f:
        for line in f:
            if line.startswith("Opened '"):
                name = line.split("'")[1].rsplit(":", 1)[-1]
                dex_bytes = dexes.get(name, dex_bytes); k = m = None; continue
            if line.startswith("  Class descriptor"):
                k = Klass(line.split("'")[1]); classes[k.desc] = k; m = None; in_ifaces = False
                continue
            if k is None:
                continue
            if line.startswith("  Access flags") and m is None and pending is None:
                k.access = line.split("(", 1)[1] if "(" in line else ""; continue
            if line.startswith("  Superclass"):
                s = line.split("'"); k.sup = s[1] if len(s) > 1 else None; continue
            if line.startswith("  Interfaces"):
                in_ifaces = True; continue
            if in_ifaces:
                if line.startswith("    #") and "'" in line:
                    k.ifaces.append(line.split("'")[1]); continue
                in_ifaces = False
            if line.startswith("  Direct methods") or line.startswith("  Virtual methods"):
                section = "m"; m = None; continue
            if line.startswith("  Static fields") or line.startswith("  Instance fields"):
                section = "f"; continue
            if section != "m":
                continue
            s = line.strip()
            if s.startswith("name          :"):
                pending = [s.split("'")[1], None, ""]; continue
            if s.startswith("type          :") and pending is not None:
                pending[1] = s.split("'")[1]; continue
            if s.startswith("access        :") and pending is not None:
                pending[2] = s.split("(", 1)[1] if "(" in s else ""
                m = Method(k.desc, pending[0], pending[1], pending[2]); k.methods[(m.name, m.proto)] = m; m.dex = dex_bytes
                pending = None; continue
            if m is None:
                continue
            if s.startswith("registers     :"):
                m.regs = int(s.split(":")[1]); continue
            if s.startswith("ins           :"):
                m.nins = int(s.split(":")[1]); continue
            if s.startswith("insns size"):
                m.size = int(s.split(":")[1].split()[0]); m.is_abstract = False; continue
            if s.startswith("catches"):
                v = s.split(":", 1)[1].strip(); m.tries = 0 if v.startswith("(none)") else int(v); continue
            mi = INS.match(line)
            if mi:
                addr = int(mi.group(2), 16)
                m.ins.append((addr, mi.group(3), mi.group(4) or ""))
                m.fileoff[addr] = int(mi.group(1), 16)
    return classes


def find_by_header(classes, header):
    """the method of a dexdump code header (io.kuicksilver.Foo.bar:(sig)ret)"""
    name_part, proto = header.split(":", 1)
    cls_dot, mname = name_part.rsplit(".", 1)
    k = classes.get("L" + cls_dot.replace(".", "/") + ";")
    return k.methods.get((mname, proto)) if k else None


def read_catches(dump, classes):
    """try ranges [start, end) with their handlers (address, type or None for any), and the line table, per method"""
    meth = None
    rng = None
    in_c = in_p = False
    with open(dump, errors="replace") as f:
        for line in f:
            h = HDR.match(line)
            if h:
                meth = find_by_header(classes, h.group(3)); in_c = in_p = False; continue
            s = line.strip()
            if s.startswith("catches"):
                in_c = not s.endswith("(none)") and meth is not None; rng = None; continue
            if s.startswith("positions"):
                in_c = False; in_p = meth is not None; continue
            if s.startswith("locals"):
                in_c = in_p = False; continue
            if in_p:
                mp = re.match(r"^0x([0-9a-f]+) line=(\d+)$", s)
                if mp:
                    meth.lines.append((int(mp.group(1), 16), int(mp.group(2))))
                continue
            if not in_c:
                continue
            mr = re.match(r"^0x([0-9a-f]+) - 0x([0-9a-f]+)$", s)
            if mr:
                rng = [int(mr.group(1), 16), int(mr.group(2), 16), []]; meth.catches.append(rng); continue
            mh = re.search(r"^(\S+) -> 0x([0-9a-f]+)$", s)
            if mh and rng is not None:
                rng[2].append((int(mh.group(2), 16), None if mh.group(1) == "<any>" else mh.group(1)))


def switch_targets(m, addr, args):
    """targets of a packed- or sparse-switch at addr, read from the payload in the dex; DexError when it is not there"""
    mt = BRANCH_TARGET.search(args)
    where = f"{m.key} at {addr:04x}"
    if not mt:
        raise DexError(f"{where}: no payload offset in '{args}'")
    if m.dex is None or addr not in m.fileoff:
        raise DexError(f"{where}: the dex bytes are not given (pass the zip of the dex files after the dexdump)")
    payload = int(mt.group(1), 16)
    off = m.fileoff[addr] + (payload - addr) * 2
    d = m.dex
    if off < 0 or off + 4 > len(d):
        raise DexError(f"{where}: the payload is outside the dex")
    ident, size = struct.unpack_from("<HH", d, off)
    if ident == 0x0100:
        rel = struct.unpack_from("<%di" % size, d, off + 8)
    elif ident == 0x0200:
        rel = struct.unpack_from("<%di" % size, d, off + 4 + 4 * size)
    else:
        raise DexError(f"{where}: no switch payload at the offset (ident {ident:#06x})")
    return [addr + r for r in rel]


def cfg(m):
    """(successors per instruction address, normal and exceptional; backward branches as (from, to))"""
    if m._succ is not None:
        return m._succ, m._back
    addrs = [a for a, op, _ in m.ins if not op.endswith("-data")]
    nxt = {a: b for a, b in zip(addrs, addrs[1:])}
    succ, back = {}, []
    for a, op, args in m.ins:
        if op.endswith("-data"):
            continue
        s = []
        if op == "goto/32" and args.startswith("#"):
            rel = int(args[1:9], 16)
            s = [a + (rel - (1 << 32) if rel & 0x80000000 else rel)]
        elif op.startswith("goto"):
            s = [int(BRANCH_TARGET.search(args).group(1), 16)]
        elif op.startswith("if-"):
            s = [int(BRANCH_TARGET.search(args).group(1), 16)] + ([nxt[a]] if a in nxt else [])
        elif op in ("packed-switch", "sparse-switch"):
            s = switch_targets(m, a, args) + ([nxt[a]] if a in nxt else [])
        elif op.startswith("return") or op == "throw":
            s = []
        elif a in nxt:
            s = [nxt[a]]
        for t in s:
            if t <= a:
                back.append((a, t))  # a goto, an if or a switch back (a goto to itself too)
        for st, en, hs in m.catches:
            if st <= a < en:
                for h, _ in hs:
                    s = s + [h]
                    if h <= a:
                        back.append((a, h))  # a handler before the throwing instruction: a loop through the catch
        succ[a] = s
    m._succ, m._back = succ, back
    return succ, back


def preds(m):
    if m._pred is None:
        succ, _ = cfg(m)
        m._pred = collections.defaultdict(list)
        for a, ss in succ.items():
            for b in ss:
                m._pred[b].append(a)
        m._pos = {a: i for i, (a, _, _) in enumerate(m.ins)}
    return m._pred


def reach(start, edges):
    seen, todo = {start}, [start]
    while todo:
        x = todo.pop()
        for y in edges.get(x, ()):
            if y not in seen:
                seen.add(y); todo.append(y)
    return seen


def loops(m):
    """(head, latch, body) of every backward edge whose head reaches its latch"""
    succ, back = cfg(m)
    pred = preds(m)
    out = []
    for latch, head in back:
        body = reach(head, succ) & reach(latch, pred)
        if latch in body:
            out.append((head, latch, body))
    return out


def invoke_regs(args):
    """the registers of an invoke's braces: {v1, v2} or a range {v1 .. v5}"""
    inside = args[args.index("{") + 1:args.index("}")]
    mr = RANGE.match(inside)
    if mr:
        return [f"v{i}" for i in range(int(mr.group(1)), int(mr.group(2)) + 1)]
    return [r.strip() for r in inside.split(",") if r.strip()]


def invoke_parts(args):
    mi = INVOKE.match(args)
    if not mi:
        return None
    return invoke_regs(args), mi.group(2), mi.group(3), mi.group(4)


def regs_of(args):
    if args.startswith("{"):
        return invoke_regs(args)
    return REG.findall(args.split(" // ")[0].split(", L")[0].split('"')[0])


def use_def(op, args):
    """(uses, defs, move source) of one instruction, by register name"""
    rs = regs_of(args)
    if MOVE_OBJECT.match(op) or op in ("move", "move/from16", "move/16"):
        return set(), {rs[0]}, rs[1]
    if op.startswith("invoke-") or op.startswith("filled-new-array"):
        return set(rs), set(), None
    if not rs:
        return set(), set(), None
    if NO_READ_FIRST.match(op):
        return set(rs[1:]), {rs[0]}, None
    if op == "check-cast" or TWO_ADDR.search(op):
        return set(rs), {rs[0]}, None
    if WRITES_FIRST.match(op):
        return set(rs[1:]), {rs[0]}, None
    return set(rs), set(), None   # iput, sput, aput, if-, return, throw, switch, monitor, fill-array-data


def info(m):
    if m._info is None:
        m._info = {a: use_def(op, args) for a, op, args in m.ins if not op.endswith("-data")}
    return m._info


def live_out(m, a):
    """the registers whose value an instruction other than a move reads after a, through the moves that pass it on"""
    if m._live is None:
        succ, _ = cfg(m)
        inf = info(m)
        order = [x for x, op, _ in m.ins if not op.endswith("-data")]
        live_in = {x: frozenset() for x in order}
        changed = True
        while changed:
            changed = False
            for x in reversed(order):
                out = set()
                for b in succ.get(x, ()):
                    out |= live_in.get(b, frozenset())
                uses, defs, src = inf[x]
                new = (out - defs) | uses
                if src is not None and defs & out:
                    new.add(src)
                new = frozenset(new)
                if new != live_in[x]:
                    live_in[x] = new; changed = True
        m._live = live_in
    succ, _ = cfg(m)
    out = set()
    for b in succ.get(a, ()):
        out |= m._live.get(b, frozenset())
    return out


def dead_copies(m):
    """move-object instructions that copy a phi nothing really uses, by address -> source register. A value is really used
    when an instruction other than a move reads it (moves only pass it on). The SSA form ART builds has no moves: a phi whose
    value only moves read has no use but the environments, and ART 7 drops it (ssa_phi_elimination); a deoptimization then
    leaves 0xEBADDE09 in its register, which such a move copies into the frame's references. A dex built for debugging
    copies the locals the debugger may show at each loop's turn; D8's and R8's release output does so rarely"""
    pred = preds(m)
    inf = info(m)
    dead = {}
    for a, op, args in m.ins:
        if not MOVE_OBJECT.match(op):
            continue
        _, defs, src = inf[a]
        out = live_out(m, a)
        if defs & out or src in out or src in defs:
            continue  # the copy, or the value left in the source, is used later
        # nor used before, since the join it came from (the phi). That the value comes from a join at all is not asked
        # here: a site needs a path from a join to the call and on to the copy without the register written
        # (reaches_dead_phi), and the copy's own walk follows that path back to the join. Whether ART builds a phi at that
        # join (two values meet, or inputs that conflict in type) is not decided: every join counts
        seen, todo, used = set(), [(a, src)], False
        while todo and not used:
            x, r = todo.pop()
            for p in pred.get(x, ()):
                if (p, r) in seen:
                    continue
                seen.add((p, r))
                u, d, s2 = inf.get(p, (set(), set(), None))
                if r in d:
                    if s2 is not None and MOVE_OBJECT.match(m.ins[m._pos[p]][1]):
                        todo.append((p, s2))
                    continue
                if r in u:
                    used = True; break
                if s2 == r and d & live_out(m, p):
                    used = True; break
                if len(pred.get(p, ())) > 1:
                    continue   # a join: before it the register holds the phi's inputs, other values
                todo.append((p, r))
        if not used:
            dead[a] = src
    return dead


def reaches_dead_phi(m, site, copies, body):
    """a dead copy whose source register holds, at the site, a value merged at a join (the phi) and still holds it when
    the copy runs: a deoptimization at the site leaves 0xEBADDE09 there, and the interpreter copies it"""
    succ, _ = cfg(m)
    pred = preds(m)
    inf = info(m)
    for c, r in copies.items():
        # forward: the site to the copy, r not written on the way
        seen, todo, fwd = {site}, [site], False
        while todo and not fwd:
            x = todo.pop()
            for y in succ.get(x, ()):
                if y == c:
                    fwd = True; break
                if y in seen or r in inf[y][1]:   # a path from the site to a copy of the loop stays in the loop
                    continue
                seen.add(y); todo.append(y)
        if not fwd:
            continue
        # backward: from the site to a join, r not written on the way
        seen, todo, back = {site}, [site], False
        while todo and not back:
            x = todo.pop()
            if len(pred.get(x, ())) > 1:
                back = True; break
            for y in pred.get(x, ()):
                if y in seen or r in inf[y][1]:
                    continue
                seen.add(y); todo.append(y)
        if back:
            return True
    return False


class Hierarchy:
    def __init__(self, classes, api_open):
        self.c = classes
        self.api_open = api_open
        self.sub = collections.defaultdict(set)   # type -> direct subtypes (classes and interfaces)
        for k in classes.values():
            if k.sup:
                self.sub[k.sup].add(k.desc)
            for i in k.ifaces:
                self.sub[i].add(k.desc)
        self._concrete = {}

    def concrete(self, t):
        """concrete classes of the dex that are t or below it"""
        if t in self._concrete:
            return self._concrete[t]
        seen, todo, out = {t}, [t], []
        while todo:
            x = todo.pop()
            k = self.c.get(x)
            if k is not None and not k.interface() and not k.abstract():
                out.append(x)
            for y in self.sub.get(x, ()):
                if y not in seen:
                    seen.add(y); todo.append(y)
        self._concrete[t] = out
        return out

    def is_final(self, t):
        k = self.c.get(t)
        if k is not None:
            return k.final()
        return bool(FINAL_FRAMEWORK.match(t))

    def app_extensible(self, t):
        """an application can add a class of its own below t: a public non-final type of Kuicksilver's API, a non-final type
        of another library or of the framework"""
        if t.startswith(PREFIX):
            return t in self.api_open
        return not self.is_final(t)

    def resolve(self, desc, name, proto):
        """the method a class runs for name+proto: its own, a superclass's, else an interface default; (method, known)"""
        x = desc
        while x:
            k = self.c.get(x)
            if k is None:
                return None, False       # reaches a framework class: unknown
            m = k.methods.get((name, proto))
            if m is not None and not m.is_abstract:
                return m, True
            x = k.sup
        todo, seen = [desc], set()   # default methods
        while todo:
            x = todo.pop()
            k = self.c.get(x)
            if k is None:
                continue
            for i in k.ifaces + ([k.sup] if k.sup else []):
                if i in seen:
                    continue
                seen.add(i)
                ki = self.c.get(i)
                if ki is None:
                    return None, False
                m = ki.methods.get((name, proto))
                if m is not None and not m.is_abstract:
                    return m, True
                todo.append(i)
        return None, True               # abstract everywhere the dex knows

    def bound(self, op, owner, name, proto):
        """True when ART 7 calls one target without an inline cache"""
        if op.startswith("invoke-interface"):
            return False
        if FINAL_FRAMEWORK.match(owner) or (owner, name) in FINAL_FRAMEWORK_METHODS:
            return True
        k = self.c.get(owner)
        if k is None:
            return False
        if k.final():
            return True
        m, _ = self.resolve(owner, name, proto)
        if m is None:
            x = owner
            while x in self.c:
                x = self.c[x].sup
            return bool(x) and (x, name) in FINAL_FRAMEWORK_METHODS
        return "FINAL" in m.access or "PRIVATE" in m.access

    def guarded_targets(self, types, owner, name, proto):
        """the methods of the dex a guarded call can inline, when the dex has at most IC_SIZE classes that can reach it (an
        inline cache can hold them all); none for a wider type (a FunctionN, Continuation: every lambda of the app) or a
        framework type, whose targets the site's own verdict answers for"""
        out = []
        classes = []
        for t in (sorted(types) if types else [owner]):
            if t not in self.c:
                return []
            classes += [c for c in self.concrete(t) if c not in classes]
        if len(classes) > IC_SIZE:
            return []
        for c in classes:
            mm, known = self.resolve(c, name, proto)
            if known and mm is not None and mm not in out:
                out.append(mm)
        return out


def param_types(m):
    """register -> declared type of each parameter (this first for an instance method)"""
    types = [] if "STATIC" in m.access else [m.cls]
    for t in re.findall(r"\[*(?:L[^;]+;|[ZBSCIFJD])", m.proto[1:m.proto.index(")")]):
        types.append(t)
        if t in ("J", "D"):
            types.append(None)
    base = m.regs - m.nins
    return {f"v{base + i}": t for i, t in enumerate(types)}


def catch_types(m, handler):
    """the exception types a handler catches; None when it catches any"""
    t = set()
    for _, _, hs in m.catches:
        for h, ty in hs:
            if h == handler:
                if ty is None:
                    return None
                t.add(ty)
    return t or None


def receiver_types(m, idx, reg, ptypes=None, limit=4000):
    """the declared types of what reg can hold at instruction idx (null constants left out; '!' before a type made by
    new-instance, whose class is exact); None when one is unknown. ptypes: what the caller passes, by parameter register,
    when m is inlined into it"""
    pred = preds(m)
    out, seen, todo = set(), set(), [(idx, reg)]
    params = None
    while todo:
        i, r = todo.pop()
        a = m.ins[i][0]
        ps = pred.get(a, [])
        if not ps:
            if i != 0:
                return None   # unreachable code
            if ptypes is not None and r in ptypes:
                if ptypes[r] is None:
                    return None
                out |= ptypes[r]; continue
            params = params if params is not None else param_types(m)
            t = params.get(r)
            if t is None:
                return None
            out.add(t); continue
        for pa in ps:
            j = m._pos.get(pa)
            if j is None or (j, r) in seen:
                continue
            seen.add((j, r))
            if len(seen) > limit:
                return None
            _, op, args = m.ins[j]
            regs = regs_of(args)
            if not (regs and regs[0] == r and WRITES_FIRST.match(op)):
                todo.append((j, r)); continue
            if op.startswith("move-object"):
                todo.append((j, regs[1])); continue
            if op == "new-instance":
                out.add("!" + args.split(", ")[-1].split(" //")[0].strip()); continue
            if op == "check-cast":
                out.add(args.split(", ")[-1].split(" //")[0].strip()); continue
            if op.startswith("const-string"):
                out.add("Ljava/lang/String;"); continue
            if op == "const-class":
                out.add("Ljava/lang/Class;"); continue
            if op.startswith("const") and re.search(r", #(int|long) 0\b", args):
                continue  # null
            if op.startswith("iget-object") or op.startswith("sget-object"):
                mt = FIELD_TYPE.search(args)
                if not mt:
                    return None
                out.add(mt.group(1)); continue
            if op == "move-exception":
                caught = catch_types(m, pa)
                if caught is None:
                    return None
                out |= caught; continue
            if op == "move-result-object":
                k = j - 1
                if k >= 0 and m.ins[k][1].startswith(("invoke-", "filled-new-array")):
                    mt = RETURN_TYPE.search(m.ins[k][2])
                    if mt:
                        out.add(mt.group(1)); continue
                return None
            return None
    return out


def method_of(classes, owner, name, proto):
    k = classes.get(owner)
    return k.methods.get((name, proto)) if k else None


def line_at(m, addr):
    best = None
    for a, n in m.lines:
        if a <= addr:
            best = n
    return best


def arg_types(m, i, regs, callee, ptypes):
    """what the call at instruction i passes to each parameter register of callee"""
    base = callee.regs - callee.nins
    return {f"v{base + k}": receiver_types(m, i, r, ptypes) for k, r in enumerate(regs)}


class Scanner:
    def __init__(self, classes, h, entries):
        self.classes, self.h, self.entries = classes, h, entries
        self.memo = {}
        self.where = None
        self.missing = set()   # (where, call, class): a one-class entry names a class the dex does not have

    def inlined(self, callee, depth, ptypes):
        """the sites of a callee ART 7 inlines at depth: (op, owner, name, proto, via, types) with via from the callee on"""
        if callee is None or not callee.inlinable() or depth > INLINE_DEPTH:
            return []
        key = (self.where, callee.key, depth, None if ptypes is None else tuple(sorted(
            (r, None if t is None else tuple(sorted(t))) for r, t in ptypes.items())))
        if key in self.memo:
            return self.memo[key]
        self.memo[key] = []   # a recursive call inlines nothing more
        out = [(op, o, n, p, (callee.key,) + via, ty)
               for op, o, n, p, via, ty, _ in self.sites(callee, range(len(callee.ins)), depth, ptypes)]
        self.memo[key] = out
        return out

    def sites(self, m, idxs, depth, ptypes=None):
        """the guarded calls among the instructions idxs of m and in what ART 7 inlines from them, with the address of the
        call of m they come from: (op, owner, name, proto, via, types, address)"""
        h = self.h
        out = []
        for i in idxs:
            a, op, args = m.ins[i]
            if not op.startswith("invoke-"):
                continue
            p = invoke_parts(args)
            if not p:
                continue
            regs, owner, name, proto = p
            callees = []
            if op.startswith("invoke-virtual") or op.startswith("invoke-interface"):
                if h.bound(op, owner, name, proto):
                    callees = [h.resolve(owner, name, proto)[0]]
                else:
                    types = receiver_types(m, i, regs[0], ptypes) if regs else None
                    if types is not None and not types:
                        continue  # only null reaches: the call never runs
                    plain = {t.lstrip("!") for t in types} if types else set()
                    if len(plain) == 1 and (all(t.startswith("!") for t in types) or h.is_final(next(iter(plain)))):
                        # made by new-instance, or declared of a final class: ART's type propagation binds the call
                        callees = [h.resolve(next(iter(plain)), name, proto)[0]]
                    else:
                        out.append((op.split("/")[0], owner, name, proto, (), plain or None, a))
                        # the guard inlines the target it saw: that target's calls are in the loop too. A one-class
                        # entry names the class: its target; else every target, when the dex has at most IC_SIZE
                        call = f"{dotted(owner)}.{name}"
                        e = self.entries.get((self.where, call))
                        if e and e[0] == "one-class":
                            desc = "L" + e[3].replace(".", "/") + ";"
                            if desc in self.classes:
                                targets = [t for t in [h.resolve(desc, name, proto)[0]] if t is not None]
                            else:
                                targets = []
                                if not desc.startswith(("Ljava/", "Ljavax/", "Landroid/", "Ldalvik/", "Lsun/")):
                                    self.missing.add((self.where, call, e[3]))
                        else:
                            targets = h.guarded_targets(plain, owner, name, proto)
                        for t in targets:
                            out += [x + (a,) for x in self.inlined(t, depth + 1, None)]
                        continue
            elif op.startswith("invoke-static") or op.startswith("invoke-direct"):
                callees = [method_of(self.classes, owner, name, proto)]
            for callee in callees:
                if callee is not None and callee.inlinable():
                    out += [x + (a,) for x in self.inlined(callee, depth + 1, arg_types(m, i, regs, callee, ptypes))]
        return out


def judge(h, owner, name, proto, types):
    """an automatic verdict, else None (the site needs an entry)"""
    cands = sorted(types) if types else [owner]
    if len(cands) == 1 and cands[0] in LEAF_FRAMEWORK and not set(h.concrete(cands[0])) - {cands[0]} - FOREIGN_SUBCLASSES:
        return "framework-leaf"
    for t in cands + [owner]:
        if t not in h.c or t.startswith("[") or h.app_extensible(t):
            return None
    targets, classes_seen = set(), set()
    for t in cands:
        for c in h.concrete(t):
            mm, known = h.resolve(c, name, proto)
            if not known:
                return None
            classes_seen.add(c)
            if mm is not None:
                targets.add(mm)
    if not classes_seen:
        return None
    if all(not t.inlinable() for t in targets):
        return "no-inline"
    if len(classes_seen) == 1:
        return "one-class-dex"
    return None


def dotted(desc):
    return desc[1:-1].replace("/", ".")


def dotted_key(k):
    cls, rest = k.split(";.", 1)
    return f"{dotted(cls + ';')}.{rest.split(':')[0]}"


def read_api(root):
    """the public non-final types of Kuicksilver's API, from the Android ABI dumps"""
    out = set()
    for path in glob.glob(os.path.join(root, "kuicksilver-*", "api", "android", "*.api")):
        with open(path) as f:
            for line in f:
                mt = re.match(r"^public (.*?)(?:class|interface) (io/kuicksilver/\S+)", line)
                if mt and "final" not in mt.group(1).split():
                    out.add("L" + mt.group(2) + ";")
    return out


def scan(pairs, api_open, entries, errors):
    """state machine or method -> {owner.name: [(op, verdict, via, tag, types, line, address)]}"""
    found = collections.OrderedDict()
    for dump, dex in pairs:
        with zipfile.ZipFile(dex) as z:
            dexes = {n: z.read(n) for n in z.namelist() if re.match(r"^classes\d*\.dex$", n)}
        classes = parse(dump, dexes)
        read_catches(dump, classes)
        h = Hierarchy(classes, api_open)
        sc = Scanner(classes, h, entries)
        tag = os.path.basename(dump)
        for k in classes.values():
            if not k.desc.startswith(PREFIX):
                continue
            for m in k.methods.values():
                if m.is_abstract or not m.ins or not any(MOVE_OBJECT.match(op) for _, op, _ in m.ins):
                    continue
                lps = loops(m)
                if not lps:
                    continue
                dead = dead_copies(m)
                with_copies = []
                for _, _, body in lps:
                    copies = {c: r for c, r in dead.items() if c in body}
                    if copies:
                        with_copies.append((body, copies))
                if not with_copies:
                    continue
                pos = {a: i for i, (a, _, _) in enumerate(m.ins)}
                union = set().union(*(b for b, _ in with_copies))
                where = f"{dotted(k.desc)}.{m.name}"
                sc.where = where
                calls = sc.sites(m, sorted(pos[a] for a in union if a in pos), 0)
                at = {}   # call address -> whether a deoptimization there reaches a dead phi copy of a loop around it
                for a in {x[-1] for x in calls}:
                    at[a] = any(a in body and reaches_dead_phi(m, a, copies, body) for body, copies in with_copies)
                hits = [x for x in calls if at[x[-1]]]
                if not hits:
                    continue
                d = found.setdefault(where, collections.OrderedDict())
                for op, owner, name, proto, via, types, a in hits:
                    v = judge(h, owner, name, proto, types)
                    d.setdefault(f"{dotted(owner)}.{name}", []).append((op, v, via, tag, types, line_at(m, a), a))
        for where, call, cls in sorted(sc.missing):
            if call in found.get(where, {}):
                errors.append(f"{where} | {call}: the one-class entry names {cls}, which {tag} does not define")
    return found


def read_allow(path, errors):
    entries = {}
    if not os.path.exists(path):
        return entries
    with open(path) as f:
        for n, line in enumerate(f, 1):
            s = line.strip()
            if not s or s.startswith("#"):
                continue
            parts = [p.strip() for p in s.split("|")]
            if len(parts) != 4:
                errors.append(f"{path}:{n}: want <class>.<method> | <owner>.<name> | <verdict> | <reason>"); continue
            where, call, verdict_field, reason = parts
            words = verdict_field.split()
            verdict = words[0] if words else ""
            if verdict not in VERDICTS:
                errors.append(f"{path}:{n}: unknown verdict '{verdict_field}' (one of {', '.join(VERDICTS)})"); continue
            if verdict == "one-class" and len(words) != 2:
                errors.append(f"{path}:{n}: one-class names the class that reaches the site: one-class <class>"); continue
            if verdict != "one-class" and len(words) != 1:
                errors.append(f"{path}:{n}: only one-class names a class"); continue
            if len(reason.split()) < 4:
                errors.append(f"{path}:{n}: the reason needs at least four words"); continue
            if (where, call) in entries:
                errors.append(f"{path}:{n}: {where} | {call} judged twice"); continue
            entries[(where, call)] = (verdict, reason, n, words[1] if len(words) > 1 else None)
    return entries


KNOWN_HEADER = """\
# Sites of tools/check/art7-loops.py in the dex of an app's debug build (D8 --debug), which the device tests run too:
# <class>.<method> | <owner>.<name> | <call instructions>. Known, not judged one by one: docs/spec/art7-deopt-loops.md says
# why a debug dex has them, which were fixed and what is left. A site that is not here, or has another count (a new loop
# with the same call), fails tools/check/art7-loops.sh, so does a line no site needs any more.
# KSL_ART7_WRITE_LOCK=1 bash tools/check/art7-loops.sh <client AAR> <server AAR> rewrites this file.
"""


def read_known(path, errors):
    known = {}
    if path is None or not os.path.exists(path):
        return known
    with open(path) as f:
        for n, line in enumerate(f, 1):
            s = line.strip()
            if not s or s.startswith("#"):
                continue
            parts = [p.strip() for p in s.split("|")]
            if len(parts) != 3 or not parts[2].isdigit():
                errors.append(f"{path}:{n}: want <class>.<method> | <owner>.<name> | <call instructions>"); continue
            known[(parts[0], parts[1])] = (int(parts[2]), n)
    return known


def main(argv):
    here = os.path.dirname(os.path.abspath(__file__))
    allow = os.path.join(here, "art7-loops.allow")
    api_root = os.path.dirname(os.path.dirname(here))
    report = False
    known_path = write_known = None
    pairs = []
    args = list(argv)
    try:
        while args:
            a = args.pop(0)
            if a == "--allow":
                allow = args.pop(0)
            elif a == "--api-root":
                api_root = args.pop(0)
            elif a == "--known":
                known_path = args.pop(0)
            elif a == "--write-known":
                write_known = args.pop(0)
            elif a == "--report":
                report = True
            elif ":" in a:
                d, x = a.rsplit(":", 1)
                if not (os.path.isfile(d) and os.path.isfile(x)):
                    print(f"FAIL: no dexdump {d} or dex zip {x}"); return 2
                pairs.append((d, x))
            else:
                print(f"FAIL: unknown argument {a}"); return 2
    except IndexError:
        print(f"FAIL: {a} needs a value"); return 2
    if not pairs:
        print("usage: art7-loops.py [--allow FILE] [--api-root DIR] [--known FILE | --write-known FILE] [--report] "
              "<dexdump>:<dex zip> [...]")
        return 2
    errors = []
    entries = read_allow(allow, errors)
    known = read_known(known_path, errors)
    try:
        found = scan(pairs, read_api(api_root), entries, errors)
    except DexError as e:
        print(f"FAIL: {e}"); return 2
    used, known_used, unjudged = set(), set(), []
    n_sites = n_auto = n_judged = n_known = n_open = 0
    for where, calls in found.items():
        lines = []
        for call, hits in calls.items():
            n_sites += 1
            auto = {x[1] for x in hits}
            count = len({(x[6], x[2]) for x in hits})
            vias = sorted({" <- ".join(dotted_key(v) for v in reversed(x[2])) for x in hits if x[2]})
            tags = sorted({x[3] for x in hits})
            lns = sorted({x[5] for x in hits if x[5]})
            e = entries.get((where, call))
            if e:
                used.add((where, call))
            if None not in auto:
                n_auto += 1; state = "/".join(sorted(auto)) + " (automatic)"
            elif e and e[0] != "fixed":
                n_judged += 1; n_open += e[0] == "open"; state = f"{e[0]}{' ' + e[3] if e[3] else ''}: {e[1]}"
            elif e and e[0] == "fixed":
                state = "FIXED BUT STILL A SITE"
                errors.append(f"{where} | {call}: judged fixed, but the loop still makes the call ({', '.join(tags)})")
            elif (where, call) in known and known[(where, call)][0] == count:
                n_known += 1; known_used.add((where, call)); state = "known (debug lock)"
            else:
                state = "UNJUDGED"
                unjudged.append((where, call, count))
                if (where, call) in known:
                    known_used.add((where, call))
                if write_known is None:
                    why = (f"listed with {known[(where, call)][0]} call instruction(s) in {os.path.basename(known_path)}, "
                           f"now {count}") if (where, call) in known else (
                        f"not judged in {os.path.basename(allow)}"
                        f"{' nor listed in ' + os.path.basename(known_path) if known_path else ''}")
                    errors.append(f"{where} | {call}: a guarded call in a loop, {why} ({hits[0][0]}, {', '.join(tags)}, "
                                  f"lines {','.join(map(str, lns)) or '?'}{'; via ' + '; '.join(vias) if vias else ''})")
            tys = sorted({",".join(sorted(dotted(t) if t.startswith("L") else t for t in x[4])) if x[4] else "?" for x in hits})
            lines.append(f"    {call} [{hits[0][0]}] {state}; receivers {' | '.join(tys)}; lines {','.join(map(str, lns)) or '?'} "
                         f"({', '.join(tags)})" + (f" (via {'; '.join(vias)})" if vias else ""))
        if report:
            print(where); print("\n".join(lines))
    if known_path is None and write_known is None:
        # the release scan: every entry must still name a site
        for key, (verdict, _, n, _) in entries.items():
            if key not in used and verdict != "fixed":
                errors.append(f"{os.path.basename(allow)}:{n}: {key[0]} | {key[1]} is no site any more: remove the entry")
    for key, (_, n) in known.items():
        if key not in known_used:
            errors.append(f"{os.path.basename(known_path)}:{n}: {key[0]} | {key[1]} is no site any more: remove the line")
    if write_known is not None:
        rows = sorted(unjudged + [(w, c, known[(w, c)][0]) for w, c in known_used if (w, c) not in {(x, y) for x, y, _ in unjudged}])
        with open(write_known, "w") as f:
            f.write(KNOWN_HEADER)
            for w, c, n in rows:
                f.write(f"{w} | {c} | {n}\n")
        print(f"art7-loops: wrote {len(rows)} sites to {write_known}")
    print(f"art7-loops: {len(found)} methods with guarded calls in a loop, {n_sites} sites: {n_auto} automatic, "
          f"{n_judged} judged ({n_open} open){f', {n_known} known' if known_path else ''}, {len(errors)} findings")
    for e in errors:
        print(f"FAIL: {e}")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
