// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
// Minimal RFC 6455 framing for the Node.js interop scripts of NodeH2WebSocketInteropTest: whole frames only (FIN set),
// lengths up to 2^16 - 1, a masking key from crypto.randomBytes when `mask` is set.
import crypto from 'node:crypto';

export const TEXT = 0x1;
export const CLOSE = 0x8;

export function frame(opcode, payload, mask) {
  const len = payload.length;
  const head = [0x80 | opcode];
  if (len < 126) head.push((mask ? 0x80 : 0) | len);
  else head.push((mask ? 0x80 : 0) | 126, len >> 8, len & 0xff);
  if (!mask) return Buffer.concat([Buffer.from(head), payload]);
  const key = crypto.randomBytes(4);
  const body = Buffer.from(payload);
  for (let i = 0; i < body.length; i++) body[i] ^= key[i % 4];
  return Buffer.concat([Buffer.from(head), key, body]);
}

export function closeFrame(code, mask) {
  const p = Buffer.alloc(2);
  p.writeUInt16BE(code);
  return frame(CLOSE, p, mask);
}

/** Parses the whole frames at the start of `buf`; returns them and the rest. */
export function parse(buf) {
  const frames = [];
  let p = 0;
  while (buf.length - p >= 2) {
    const b0 = buf[p], b1 = buf[p + 1];
    let len = b1 & 0x7f, at = p + 2;
    if (len === 126) {
      if (buf.length - at < 2) break;
      len = buf.readUInt16BE(at);
      at += 2;
    } else if (len === 127) {
      if (buf.length - at < 8) break;
      len = Number(buf.readBigUInt64BE(at));
      at += 8;
    }
    const masked = (b1 & 0x80) !== 0;
    const keyAt = at;
    if (masked) at += 4;
    if (buf.length - at < len) break;
    const payload = Buffer.from(buf.subarray(at, at + len));
    if (masked) for (let i = 0; i < len; i++) payload[i] ^= buf[keyAt + (i % 4)];
    frames.push({ fin: (b0 & 0x80) !== 0, rsv: (b0 >> 4) & 0x7, opcode: b0 & 0xf, masked, payload });
    p = at + len;
  }
  return { frames, rest: buf.subarray(p) };
}
