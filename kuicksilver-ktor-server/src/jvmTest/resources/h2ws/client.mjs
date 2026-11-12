// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
// An independent RFC 8441 client (Node.js http2, built on nghttp2) for NodeH2WebSocketInteropTest: it connects to
// 127.0.0.1:<port> over TLS (ALPN h2, the test CA, SNI server.test), waits for the server's SETTINGS, opens an Extended
// CONNECT with :protocol websocket to /ws, sends a masked text frame "node", expects its echo, closes with 1000 and its
// END_STREAM, and expects the server's Close and END_STREAM. It prints what it saw, one line each, and `OK` last;
// `FAIL <why>` and exit code 1 otherwise. Usage: node client.mjs <port> <ca.pem>
import http2 from 'node:http2';
import fs from 'node:fs';
import { TEXT, CLOSE, frame, closeFrame, parse } from './ws-frames.mjs';

const [port, caPath] = process.argv.slice(2);
const fail = (why) => {
  console.log(`FAIL ${why}`);
  process.exit(1);
};
setTimeout(() => fail('no result within 20 s'), 20000).unref();

const session = http2.connect(`https://127.0.0.1:${port}`, { ca: fs.readFileSync(caPath), servername: 'server.test' });
session.on('error', (e) => fail(`session: ${e.message}`));
let started = false;
session.on('remoteSettings', (settings) => {
  if (started) return;
  started = true;
  console.log(`SETTINGS enableConnectProtocol=${settings.enableConnectProtocol}`);
  if (!settings.enableConnectProtocol) fail('the server did not enable Extended CONNECT');
  const req = session.request(
    {
      ':method': 'CONNECT',
      ':protocol': 'websocket',
      ':scheme': 'https',
      ':authority': 'server.test',
      ':path': '/ws',
      'sec-websocket-version': '13',
    },
    { endStream: false },
  );
  req.on('error', (e) => fail(`stream: ${e.message}`));
  req.on('response', (headers) => {
    console.log(`STATUS ${headers[':status']}`);
    if (headers[':status'] !== 200) fail(`status ${headers[':status']}`);
    if ('sec-websocket-accept' in headers) fail('sec-websocket-accept in the 200');
    req.write(frame(TEXT, Buffer.from('node'), true));
  });
  let buf = Buffer.alloc(0);
  let closed = false;
  req.on('data', (chunk) => {
    buf = Buffer.concat([buf, chunk]);
    const { frames, rest } = parse(buf);
    buf = rest;
    for (const f of frames) {
      if (f.masked) fail('a masked frame from the server');
      if (f.opcode === TEXT) {
        console.log(`TEXT ${f.payload.toString()}`);
        req.end(closeFrame(1000, true)); // our Close, then END_STREAM
      } else if (f.opcode === CLOSE) {
        closed = true;
        console.log(`CLOSE ${f.payload.readUInt16BE(0)}`);
      }
    }
  });
  req.on('end', () => {
    console.log('SERVER_END_STREAM');
    if (!closed) fail('END_STREAM before the server\'s Close');
  });
  req.on('close', () => {
    console.log(`STREAM_CLOSED rst=${req.rstCode}`);
    if (!closed) fail('no Close from the server');
    session.close();
    console.log('OK');
  });
});
