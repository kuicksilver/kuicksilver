// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
// An independent RFC 8441 server (Node.js http2, built on nghttp2) for NodeH2WebSocketInteropTest: TLS on 127.0.0.1 with
// the given certificate, SETTINGS_ENABLE_CONNECT_PROTOCOL = 1, a GET answered "ok", and an Extended CONNECT with
// :protocol websocket answered 200 and served as an echo ("node:" + each text frame; a Close answered with a Close and
// END_STREAM). It prints `LISTENING <port>`, then a line for each CONNECT (`CONNECT <headers as JSON>`), the client's
// END_STREAM (`CLIENT_END_STREAM`) and the stream's end (`STREAM_CLOSED rst=<code>`). Usage: node server.mjs <cert.pem> <key.pem>
import http2 from 'node:http2';
import fs from 'node:fs';
import { TEXT, CLOSE, frame, parse } from './ws-frames.mjs';

const [certPath, keyPath] = process.argv.slice(2);
const server = http2.createSecureServer({
  cert: fs.readFileSync(certPath),
  key: fs.readFileSync(keyPath),
  settings: { enableConnectProtocol: true },
});
server.on('stream', (stream, headers) => {
  if (headers[':method'] !== 'CONNECT') {
    stream.respond({ ':status': 200, 'content-type': 'text/plain' });
    stream.end('ok');
    return;
  }
  console.log(`CONNECT ${JSON.stringify(headers)}`);
  if (headers[':protocol'] !== 'websocket') {
    stream.respond({ ':status': 501 }, { endStream: true });
    return;
  }
  const offered = headers['sec-websocket-protocol'];
  stream.respond(offered ? { ':status': 200, 'sec-websocket-protocol': offered.split(',')[0].trim() } : { ':status': 200 });
  let buf = Buffer.alloc(0);
  stream.on('data', (chunk) => {
    buf = Buffer.concat([buf, chunk]);
    const { frames, rest } = parse(buf);
    buf = rest;
    for (const f of frames) {
      if (!f.masked) console.log('UNMASKED_FRAME');
      if (f.opcode === TEXT) stream.write(frame(TEXT, Buffer.from(`node:${f.payload.toString()}`), false));
      else if (f.opcode === CLOSE) stream.end(frame(CLOSE, f.payload.subarray(0, 2), false));
    }
  });
  stream.on('end', () => console.log('CLIENT_END_STREAM'));
  stream.on('close', () => console.log(`STREAM_CLOSED rst=${stream.rstCode}`));
  stream.on('error', (e) => console.log(`STREAM_ERROR ${e.message}`));
});
server.listen(0, '127.0.0.1', () => console.log(`LISTENING ${server.address().port}`));
