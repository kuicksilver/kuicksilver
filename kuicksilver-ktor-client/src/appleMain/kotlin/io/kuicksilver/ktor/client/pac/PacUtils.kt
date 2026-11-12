// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.client.pac

/**
 * The PAC utility functions written in JavaScript, as Netscape's "Navigator Proxy Auto-Config File Format" (1996) and
 * Microsoft's IPv6 extensions (`…Ex`, "WinINet: IPv6 Extensions to Navigator Auto-Config File Format") define them.
 * `dnsResolve`, `dnsResolveEx`, `myIpAddress` and `myIpAddressEx` are native functions of [PacContext]; everything else is
 * here. Times are local time unless the last argument is "GMT". `shExpMatch` takes `*` and `?` as its only wildcards and
 * every other character literally (`.`, `[`, `]`, `+`, `(` …); Mozilla's and Chromium's versions escape only `.` and
 * so read other regular-expression characters as such (from their pac_utils sources as remembered, not checked here:
 * no copy is at hand).
 */
internal const val PAC_UTILS_JS: String = """
function isPlainHostName(host) { return String(host).indexOf('.') < 0; }

function dnsDomainIs(host, domain) {
  host = String(host).toLowerCase(); domain = String(domain).toLowerCase();
  return host.length >= domain.length && host.substring(host.length - domain.length) === domain;
}

function localHostOrDomainIs(host, hostdom) {
  host = String(host).toLowerCase(); hostdom = String(hostdom).toLowerCase();
  return host === hostdom || (host.indexOf('.') < 0 && hostdom.lastIndexOf(host + '.', 0) === 0);
}

function isResolvable(host) { return dnsResolve(host) !== null; }

function isResolvableEx(host) { var a = dnsResolveEx(host); return a !== null && a !== ''; }

function dnsDomainLevels(host) { return String(host).split('.').length - 1; }

function __pacV4(ip) {
  var m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(String(ip));
  if (!m) return null;
  var n = 0;
  for (var i = 1; i <= 4; i++) { var o = parseInt(m[i], 10); if (o > 255) return null; n = n * 256 + o; }
  return n;
}

function isInNet(ipaddr, pattern, maskstr) {
  var ip = __pacV4(ipaddr);
  if (ip === null) { var r = dnsResolve(ipaddr); if (r === null) return false; ip = __pacV4(r); }
  var p = __pacV4(pattern), m = __pacV4(maskstr);
  if (ip === null || p === null || m === null) return false;
  for (var i = 0; i < 4; i++) {
    var d = Math.pow(256, 3 - i);
    var a = Math.floor(ip / d) % 256, b = Math.floor(p / d) % 256, k = Math.floor(m / d) % 256;
    if ((a & k) !== (b & k)) return false;
  }
  return true;
}

function __pacV6(ip) {
  ip = String(ip);
  var pct = ip.indexOf('%'); if (pct >= 0) ip = ip.substring(0, pct);
  var tail = [];
  var lastColon = ip.lastIndexOf(':');
  if (ip.indexOf('.') > lastColon && lastColon >= 0) {
    var v4 = __pacV4(ip.substring(lastColon + 1)); if (v4 === null) return null;
    tail = [Math.floor(v4 / 65536), v4 % 65536]; ip = ip.substring(0, lastColon + 1) + '0:0';
  }
  var halves = ip.split('::'); if (halves.length > 2) return null;
  function words(s) { if (s === '') return []; var w = s.split(':'), out = [];
    for (var i = 0; i < w.length; i++) { if (!/^[0-9a-fA-F]{1,4}$/.test(w[i])) return null; out.push(parseInt(w[i], 16)); }
    return out; }
  var head = words(halves[0]); if (head === null) return null;
  var all;
  if (halves.length === 2) {
    var rest = words(halves[1]); if (rest === null) return null;
    var zeros = 8 - head.length - rest.length; if (zeros < 1) return null;
    all = head; for (var z = 0; z < zeros; z++) all.push(0); all = all.concat(rest);
  } else { all = head; }
  if (all.length !== 8) return null;
  if (tail.length) { all[6] = tail[0]; all[7] = tail[1]; }
  return all;
}

function isInNetEx(ipaddr, prefix) {
  var slash = String(prefix).indexOf('/'); if (slash < 0) return false;
  var net = String(prefix).substring(0, slash), bits = parseInt(String(prefix).substring(slash + 1), 10);
  if (isNaN(bits) || bits < 0) return false;
  var a4 = __pacV4(ipaddr), n4 = __pacV4(net);
  if (a4 !== null && n4 !== null) {
    if (bits > 32) return false;
    var d = Math.pow(2, 32 - bits);
    return Math.floor(a4 / d) === Math.floor(n4 / d);
  }
  var a6 = __pacV6(ipaddr), n6 = __pacV6(net);
  if (a6 === null || n6 === null || bits > 128) return false;
  for (var i = 0; i < 8 && bits > 0; i++, bits -= 16) {
    var take = bits >= 16 ? 16 : bits, sh = Math.pow(2, 16 - take);
    if (Math.floor(a6[i] / sh) !== Math.floor(n6[i] / sh)) return false;
  }
  return true;
}

function sortIpAddressList(list) {
  if (list === null || list === undefined || String(list) === '') return false;
  var items = String(list).split(';'), keyed = [];
  for (var i = 0; i < items.length; i++) {
    var s = items[i].replace(/^\s+|\s+$/g, ''), v6 = __pacV6(s), v4 = __pacV4(s), key;
    if (v4 !== null) key = '1' + ('0000000000' + v4).slice(-10);
    else if (v6 !== null) { key = '0'; for (var j = 0; j < 8; j++) key += ('0000' + v6[j].toString(16)).slice(-4); }
    else return false;
    keyed.push([key, s]);
  }
  keyed.sort(function (x, y) { return x[0] < y[0] ? -1 : x[0] > y[0] ? 1 : 0; });
  var out = []; for (var k = 0; k < keyed.length; k++) out.push(keyed[k][1]);
  return out.join(';');
}

function getClientVersion() { return '1.0'; }

function shExpMatch(str, shexp) {
  var re = '^';
  shexp = String(shexp);
  for (var i = 0; i < shexp.length; i++) {
    var c = shexp.charAt(i);
    if (c === '*') re += '.*'; else if (c === '?') re += '.';
    else if ('\\^$.|+()[]{}/'.indexOf(c) >= 0) re += '\\' + c; else re += c;
  }
  return new RegExp(re + '$').test(String(str));
}

var __pacDays = ['SUN', 'MON', 'TUE', 'WED', 'THU', 'FRI', 'SAT'];
var __pacMonths = ['JAN', 'FEB', 'MAR', 'APR', 'MAY', 'JUN', 'JUL', 'AUG', 'SEP', 'OCT', 'NOV', 'DEC'];

function __pacNow(args) {
  var gmt = args.length > 0 && String(args[args.length - 1]).toUpperCase() === 'GMT';
  var a = Array.prototype.slice.call(args, 0, gmt ? args.length - 1 : args.length);
  return { gmt: gmt, args: a, now: new Date() };
}

function weekdayRange() {
  var p = __pacNow(arguments), day = p.gmt ? p.now.getUTCDay() : p.now.getDay();
  var w1 = __pacDays.indexOf(String(p.args[0]).toUpperCase());
  if (w1 < 0) return false;
  if (p.args.length < 2) return day === w1;
  var w2 = __pacDays.indexOf(String(p.args[1]).toUpperCase());
  if (w2 < 0) return false;
  return w1 <= w2 ? (day >= w1 && day <= w2) : (day >= w1 || day <= w2);
}

function dateRange() {
  var p = __pacNow(arguments), n = p.now, a = p.args;
  var cur = { d: p.gmt ? n.getUTCDate() : n.getDate(), m: p.gmt ? n.getUTCMonth() : n.getMonth(),
              y: p.gmt ? n.getUTCFullYear() : n.getFullYear() };
  var parts = [];
  for (var i = 0; i < a.length; i++) {
    var s = String(a[i]).toUpperCase(), mi = __pacMonths.indexOf(s);
    if (mi >= 0) parts.push({ k: 'm', v: mi });
    else { var v = parseInt(s, 10); if (isNaN(v)) return false; parts.push(v > 31 ? { k: 'y', v: v } : { k: 'd', v: v }); }
  }
  function val(t, kinds) {
    var r = 0;
    for (var j = 0; j < kinds.length; j++) {
      var k = kinds[j], x = k === 'y' ? t.y : k === 'm' ? t.m : t.d;
      r = r * (k === 'y' ? 10000 : 100) + x;
    }
    return r;
  }
  if (parts.length === 1) {
    var q = parts[0]; return q.k === 'y' ? cur.y === q.v : q.k === 'm' ? cur.m === q.v : cur.d === q.v;
  }
  if (parts.length % 2 !== 0) return false;
  var half = parts.length / 2, kinds = [], lo = {}, hi = {};
  for (var h = 0; h < half; h++) {
    if (parts[h].k !== parts[h + half].k) return false;
    kinds.push(parts[h].k); lo[parts[h].k] = parts[h].v; hi[parts[h].k] = parts[h + half].v;
  }
  var order = ['y', 'm', 'd'].filter(function (k) { return kinds.indexOf(k) >= 0; });
  function key(src) { return val({ y: src.y, m: src.m, d: src.d }, order); }
  var c = key(cur), l = key(lo), u = key(hi);
  return l <= u ? (c >= l && c <= u) : (c >= l || c <= u);
}

function timeRange() {
  var p = __pacNow(arguments), n = p.now, a = p.args;
  for (var i = 0; i < a.length; i++) { a[i] = parseInt(a[i], 10); if (isNaN(a[i])) return false; }
  var h = p.gmt ? n.getUTCHours() : n.getHours(), m = p.gmt ? n.getUTCMinutes() : n.getMinutes(),
      s = p.gmt ? n.getUTCSeconds() : n.getSeconds();
  // as Mozilla's pac_utils: one hour; two hours, the end hour excluded; with minutes, the whole end minute included
  if (a.length === 1) return h === a[0];
  if (a.length === 2) return a[0] <= h && h < a[1];
  var c = h * 3600 + m * 60 + s, lo, hi;
  if (a.length === 4) { lo = a[0] * 3600 + a[1] * 60; hi = a[2] * 3600 + a[3] * 60 + 59; }
  else if (a.length === 6) { lo = a[0] * 3600 + a[1] * 60 + a[2]; hi = a[3] * 3600 + a[4] * 60 + a[5]; }
  else return false;
  return lo <= c && c <= hi;
}

function alert(message) {}
"""
