<!--
Copyright 2026 The Kuicksilver Authors
SPDX-License-Identifier: Apache-2.0
-->

# Loops that ART 7.x can deoptimize into a GC abort

Android 7.0 and 7.1 (API 24 and 25, ART 7.x) are within `minSdk 24`. On API 24 the device tests aborted three times in the
GC with `Tried to mark 0xebadde09 not contained by any spaces`: in the ALTSVC frame learner
(`KuicksilverEngine.learnAltSvcFrames`, run 45685880281) and in the flood loops of two tests (`ServerH2FloodTest.flood`,
`ClientH2FloodTest.flooded`, run 44453449060). Each was fixed where it was found; this page is the audit of the library
for the same crash class before 0.3.0-rc1, the check that keeps it audited (`tools/check/art7-loops.sh`) and what it found.

## The mechanism

All of the following has to happen in one method:

1. **A hot method, compiled by the JIT with filled inline caches.** The interpreter records the receiver classes of each
   `invoke-virtual` and `invoke-interface` (up to 5, `InlineCache::kIndividualCacheSize`). When the method is compiled, a
   call whose cache saw one class (or a few) and whose target can be inlined (at most 32 code units, no try block:
   `inliner.cc:792` and `:801`, `kDefaultInlineMaxCodeUnits`, which the JIT passes; up to a depth of 3) is inlined behind
   a class guard that deoptimizes when another class comes. A call bound to one target (a final class or method, a
   private method, a receiver whose exact class ART knows) has no guard; a call whose every target is too large or has a
   try block is not inlined and has no guard either.
2. **Another receiver class after compilation.** The guard fails, and the frame is handed to the interpreter.
3. **A phi that only environments use.** ART 7 drops such a phi (`ssa_phi_elimination.cc:45`), and the deoptimization fills
   the registers it has no value for with `0xEBADDE09` (kDeadValue, `quick_exception_handler.cc:408`).
4. **A `move-object` of that register in the interpreter**, which copies the raw register into the frame's references
   (mterp's `op_move.S`, `SET_VREG_OBJECT`).
5. **A GC before the register is written again**, which marks the frame's references and aborts.

The ART sources cited are AOSP `android-7.0.0_r1` (`art/`); `android-7.1.2_r1` has the same code, so API 25 is exposed too.
Nothing of this needs a coroutine: any loop qualifies. Coroutine state machines are where it was seen, because they copy
their locals between registers at each loop turn and resumption.

Condition 4 is what separates the dex an application ships from the dex its debug build and the device tests run. D8 in
debug mode keeps every local the debugger may show in its register and copies them at each loop's turn, values that nothing
reads: in the dex of a debug build such copies are everywhere. D8 and R8 in release mode drop dead values, and a dead copy
is rare. The learner shows it: the int37 AAR's `learnAltSvcFrames`, dexed with `D8 --debug`, is reported by the check
below (Map.isEmpty, the logger, the state flow, ...); dexed with `D8 --release` or R8 it is not. Its abort was in the
device tests, whose APK is a debug build.

## The check

`tools/check/art7-loops.py` reads the `dexdump -d` of a dex and reports a site: in a method of a class under
`io/kuicksilver`, a loop (a cycle through a backward branch, a switch or an exception handler); a dead copy in that loop
(a `move-object` whose value no instruction other than a move reads after it, nor since the join it came from, where a
move to a register that is read later counts as a read; every join counts as a phi, whether ART builds one there or only
might); and an `invoke-virtual` or `invoke-interface` in the loop that ART 7 may guard, at a point where the copied register
holds a join's value and from which the copy is reached without the register being written. (That the copied value comes
from a join needs no test of its own: the copy's walk back follows the path from that join through the call.) Bound calls
are not sites: a final class or method, a private method, a final class of `java.lang`, `Object.getClass` and `Enum`'s
final methods, a receiver made by `new-instance` or declared of a final class, a receiver that is only ever null.

A call to a method ART 7 inlines brings that method's calls into the loop, up to the depth of 3: a static, direct or bound
callee, and the target of a guarded call. For a guarded call, the target is that of the class its `one-class` entry names;
for a site with no such entry, the targets of every class of the dex that can reach it when there are at most 5 (an inline
cache holds them all); for a wider type (a `FunctionN`, `Continuation`: every lambda of the app) the site's verdict
answers for its targets. An inlined callee's calls are cached in the callee's own profile, which every caller of that
callee in the process shares: such a "via" site is judged against every caller of the callee, not against the loop's
method alone. A request's `Attributes` are concurrent ones, but Ktor's `AttributesJvmBase` methods they inline also
serve the `HashMapAttributes` of Ktor's other uses, so their map calls are not one class: `H3Pool.execute` reads the
request's attributes before its loop and touches them in it only through `h3RequestMark`, which ART 7 does not inline.

Three verdicts are automatic, from the class hierarchy of the dex: `no-inline` (every class of the dex the call reaches
runs a target ART 7 cannot inline), `one-class-dex` (one concrete class of the dex can reach it) and `framework-leaf` (an
`ArrayList`, `LinkedHashMap`, an atomic: a framework class no framework API hands this code a subclass of). None is given
for a type an application can implement: a public non-final type of Kuicksilver's API (read from each module's Android
ABI dump, such as `kuicksilver-quic/api/android/kuicksilver-quic.api`: `QlogSink`, `KuicksilverLogger`, the event
listeners, `QuicConnection`), a non-final type of another library (Ktor, kotlinx) or of the framework. Every other site
needs a verdict in `tools/check/art7-loops.allow`: `one-class <class>` (only that class reaches it whatever runs, with the
reason; the check follows that class's target), `cold`, `fixed` or `open` (a site that can deoptimize, left with the
reason and its fix).

`tools/check/art7-loops.sh` builds three dexes from the client and server AARs as an application's build would:
`--min-api 24`, every class jar an app links with them, the keep rules of every Kuicksilver AAR given, `android.jar` of the
`compileSdk` (35) and the `dexdump` of the build tools AGP 9.3 uses by default (36.0.0; the hosted CI's setup installs
both). The app is a stub compiled with javac (`tools/check/art7-app/App.java`) that installs event listeners, loggers and
an `AsyncQlogSink` on the client and the server, two classes of each listener and logger: without one, R8 proves the
listener null and removes every call of it; with one class only, R8 could bind the calls to it.

| dex | as built by | gate |
| --- | --- | --- |
| R8 `--release` | a minified release build | every site judged in `art7-loops.allow` |
| D8 `--release` | a release build without minification | every site judged in `art7-loops.allow` |
| D8 `--debug` | a debug build, and the device tests | every site listed in `art7-loops.debug.lock` with its number of call instructions: a new site, or a new loop with a listed call, fails |

The helpers the AARs' consumer rules keep from R8's inlining are listed in the script (as `r8-inlining.sh` lists the
ALTSVC learner's): each block must be in the AARs' rules with exactly its helpers, and every helper defined and called in
the R8 dex; a block of that kind that is not listed fails. `EngineEvents` (`deliver`) and `AsyncQlogSink` (`perform`,
`closeLive`): R8 9.3 inlines a helper without the block, and the block alone must change R8's output (each is its own
negative control). `H3PoolKt` (`h3FailureFacts`, `h3RequestMark`): R8 9.3 inlines neither without it; the block guards a
later R8, so its presence is checked and its effect is not. The positive control is that the debug dex has sites;
`tools/check/art7-loops-test.sh` has the negative controls on dexdump fixtures (52 cases). The hosted CI runs it in the
`android (35)` job after `r8-inlining.sh`, the local gate as the step `android: loops ART 7 can deoptimize (R8, D8)`.

Each rule of the filter was taken out of a copy of `art7-loops.py` in turn, and the controls run against it (2026-11-27);
every one fails at least one control:

| rule taken out | failing controls |
| --- | ---: |
| liveness of the copy | 2 |
| a real read since the join | 1 |
| a move to a live register is a use | 1 |
| the copy's walk stops at a join | 1 |
| forward: copy reached without a write | 2 |
| backward: no write between join and call | 1 |
| backward: a join before the call | 26 |
| callee: no try block | 1 |
| callee: at most 32 code units | 1 |
| inline depth 3 | 1 |
| private method bound | 1 |
| final method bound | 1 |
| final owner class bound | 1 |
| final framework class or method bound | 1 |
| receiver declared final | 1 |
| receiver made by new-instance | 1 |
| only-null receiver | 2 |
| framework-leaf | 1 |
| one-class-dex | 1 |
| no-inline | 1 |
| public API types not automatic | 1 |
| exception edges | 1 |
| switch edges | 2 |
| range invokes | 1 |
| follow a guarded call's targets | 1 |
| IC_SIZE bound | 1 |
| one-class entry's class followed | 2 |
| lock counts | 1 |
| only io/kuicksilver | 1 |
| stale allow entries | 1 |

The modules scanned are those an Android app ships: `kuicksilver-native`, `-tls`, `-quic`, `-http2`, `-http3`,
`-ktor-network`, `-ktor-client` and `-ktor-server` (published with an Android target). `kuicksilver-testing` is not
published.

## Results (0.3.0-rc1)

| dex | methods with a site | sites | automatic | judged | listed |
| --- | ---: | ---: | ---: | ---: | ---: |
| R8 `--release`, after | 0 | 0 | | | |
| D8 `--release`, before | 1 | 28 | 2 | 26 to judge | |
| D8 `--release`, after | 1 | 17 | 2 | 15 `one-class`, 0 `open` | |
| D8 `--debug`, before | 190 | 917 | 85 | | 832 to judge |
| D8 `--debug`, after | 189 | 885 | 81 | 15 | 789 |

"Before" is the tree this audit started from (`4214a86e1`), scanned by the final check without the app stub; with the
stub R8 also keeps the listener's calls, which the fixes below take out of the loops.

### The release dex

R8's output has no site. D8's release output has one method with sites, `H3Pool.execute`, the HTTP/3 request's retry loop,
all of them in its failure path:

| call | verdict |
| --- | --- |
| the listener's `retry` and `connectionReleased`, the logger's `isEnabled` and `log` | fixed: the listener and the logger change class from engine to engine; they are called in `EngineEvents.deliver` now |
| `Throwable.getCause` (the cause walks `echRejectionIn`, `resumedServerCidChange`, the stall check) | fixed: the loop reads an `H3FailureFacts` that `h3FailureFacts` computes once per failure |
| `Attributes.getOrNull`, `put`, `contains` and what they inline (`AttributesJvmBase.getMap`, `Map.get`, `Map.put`) | fixed: the diagnostics and the WebSocket flag are read before the loop (the engine sets both before the request reaches the pool and changes neither during it); the loop's other reads and writes go through `h3RequestMark` |
| `Set.contains` (`conn in retryOffered`) | fixed, then `one-class java.util.LinkedHashSet`: the set held `emptySet()` until the first change and a `LinkedHashSet` after; it holds a `LinkedHashSet` from the start |
| `H3Entry.release`'s `released` lambda | fixed: `::noteReleased` was made at two places (two classes); the entry calls its pool now |
| `Deferred.isCompleted`, `getCompleted` | `one-class kotlinx.coroutines.CompletableDeferredImpl`: `H3Session.closed` and the QUIC connection's `closed` are both `CompletableDeferred()` |
| `CompletableDeferred.isCompleted`, `isCancelled`, inlined from `ConnectionRuntime.isHandshakeComplete` and kotlinx's `ReadonlyDeferred` | `one-class kotlinx.coroutines.CompletableDeferredImpl`, for every caller of those callees: every connection's handshake is `CompletableDeferred()`, and `ReadonlyDeferred` is only made by `asDeferred` over a `CompletableDeferred` |
| `AtomicReferenceFieldUpdater.get`, inlined from kotlinx's `JobSupport.state` | `one-class` the framework's updater: one static updater for every job of the process |
| `QuicConnection.getClosed`, `isHandshakeComplete` | `one-class io.kuicksilver.quic.runtime.ConnectionRuntime`: the pool's QUIC connection, the one implementation the library makes |
| `StateFlow.getValue` | `one-class kotlinx.coroutines.flow.StateFlowImpl`: `H3Session.goAwayReceived` is a `MutableStateFlow` |
| `Mutex.lock`, `unlock`; `MutexImpl.tryLock`, inlined from `MutexImpl.lock` | `one-class kotlinx.coroutines.sync.MutexImpl`: the pool's lock is a `Mutex()`, and every caller of `MutexImpl.lock` locks a `MutexImpl` |
| `HashMap.get`, `remove`, `entrySet` | `one-class java.util.HashMap`: `connections` is a `val` made by `HashMap()` |

`h3FailureFacts` runs the cause walks and `isPeerShutdownClose` and returns their results; it is 54 code units in D8's
output and 131 in R8's, so ART 7 does not inline it, and the client's consumer rules keep an app's R8 from inlining it into
its one caller. Every value is the one the loop computed before, from the same exception and the same connection end
(read only for a failure that is no cancellation, as before). `h3RequestMark` reads the WebSocket lifetime or sets the
GOAWAY or no-coalescing mark, at the same points as before; it is over 32 code units too, kept by the same block.

### The qlog writer

`AsyncQlogSink`'s writer coroutine called the application's `QlogSink.open`, `QlogTrace.write` and `close` in its loop
over the queued operations. It calls `perform` once per operation now, and `closeLive` for the traces left when it ends:
their try blocks keep ART 7's inliner out, and `kuicksilver-quic` publishes consumer rules that keep an app's R8 from
inlining them back (R8 9.3 does without them).

### The debug dex

The 789 listed sites are what an application's debug build on API 24/25 runs, and what the device tests run. By call:
`java.util` collections and iterators (311), coroutines (`Channel`, `Job`, `Deferred`, `CoroutineContext`, selects,
flows: 167), the channels of Ktor and kotlinx.io (87), unboxing (`Number`: 63, one class each), Kuicksilver's own types
(53), lambdas (`Function0` to `Function3`: 50) and 58 others (field updaters, pools, sockets). A debug build does not run
long enough on users' devices for the JIT to compile most of these; the device tests do, with many classes at the same
calls (every test passes its own lambdas, the client and the server run in one process). The lambdas were the cause of two
of the three aborts; of the calls fixed here for the debug dex:

* `pumpBody` (HTTP/3 request and response bodies): the loop called `tunnel()`, a lambda of the client's class on a client
  stream and of the server's on a server stream, both in one process in the device tests. It reads the client's `tunnel`
  flag and the server request's `tunnel` field now.
* The engine's event listener and logger, the request attributes in `H3Pool.execute`, and the qlog writer: fixed with the
  release dex.

Left listed: the callbacks of a connection or an endpoint (one lambda class per call site in production, a test's own in
the tests), the server's event listener in its HTTP/3 accept loop and the logger in the endpoint group's load balancer
(one per server), and the ranked loops of the first scan: `ClientRequestStream.exchange` (the `RequestFrame` comparison of
its `when`, whose frame class changes with each frame, and the iteration of an interim response's fields),
`ServerPipeline.startH1Pipeline` (one `Collection.add`), `Http2Serving.serveH2` (its channel iterator, kotlinx's), and
the non-coroutine loops the scan reaches now (`AltSvcParser.parse`, `DnsMessage.read`, `KuicksilverEngine.<init>`).

## Blind spots

* The check models ART 7's inliner and SSA from the dex alone. It does not see ART's own type knowledge (a guard it reports
  may never be compiled) and counts every join as a phi (ART builds one only where two values meet, or drops one whose
  inputs conflict in type); both err toward reporting. It takes the inliner's limits from the sources the learner's
  analysis cites, and a framework target (a `java.util` class) as inlinable whatever its size.
* The targets of an unjudged guarded call whose type has more than 5 classes in the dex are not followed (a judged one is
  followed into the class its entry names). A "via" site's verdict must hold for every caller of its callee in the
  process, which the check cannot see: the entries say why it does.
* Other deoptimizations (bounds-check elimination's, a debugger's), a dead value the interpreter reads otherwise than by
  `move-object`.
* Loops in other libraries' code (kotlinx.coroutines, Ktor, kotlinx.io) and in the application's own.
* An application's subclass of an internal type (Kotlin's `internal` is public in bytecode) is not considered.
* Verification on ART 7 itself is by the device tests on the API 24 emulator; the check is static.
