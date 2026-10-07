import { test } from "node:test";
import { Buffer } from "node:buffer";
import { execFileSync } from "node:child_process";
import assert from "node:assert/strict";
import ts from "typescript";
import { readFileSync } from "node:fs";
async function module(name) {
  const source = readFileSync(
    new URL(`../src/lib/${name}.ts`, import.meta.url),
    "utf8",
  );
  const compiled = ts.transpileModule(source, {
    compilerOptions: {
      target: ts.ScriptTarget.ES2021,
      module: ts.ModuleKind.ESNext,
    },
  }).outputText;
  return import(
    "data:text/javascript;base64," + Buffer.from(compiled).toString("base64")
  );
}
const { groupChains, parseRequests, pythonReplay } = await module("chains");
const { renderHighlights, matchRanges } = await module("highlight");
const { parsePorts } = await module("capture");
const origin = Date.parse("2026-10-06T12:00:00Z");
const result = (id, ip, start, end = start) => ({
  Stream: {
    ID: id,
    Client: { Host: ip, Port: 30000 + id, Bytes: 0 },
    Server: { Host: "127.0.0.1", Port: 7070, Bytes: 0 },
    Protocol: "TCP",
    Index: "",
    FirstPacket: new Date(origin + start).toISOString(),
    LastPacket: new Date(origin + end).toISOString(),
  },
  Tags: [],
});
const stream = (raw, id = 1, start = 0) => ({
  ...result(id, "10.0.0.1", start),
  Data: [
    {
      Direction: 0,
      Content: btoa(raw.slice(0, 17)),
      Time: new Date(origin + start).toISOString(),
    },
    {
      Direction: 0,
      Content: btoa(raw.slice(17)),
      Time: new Date(origin + start + 1).toISOString(),
    },
  ],
  Converters: [],
  ActiveConverter: "",
});
test("same-IP chains include exact 1s gaps, isolate IPs and split longer gaps", () => {
  const groups = groupChains([
    result(4, "a", 2001),
    result(2, "a", 1000),
    result(1, "a", 0),
    result(3, "b", 500),
  ]);
  assert.deepEqual(
    groups.map((g) => g.streams.map((s) => s.Stream.ID)),
    [[4], [3], [1, 2]],
  );
});
test("reassembles fragmented and pipelined HTTP without corrupting binary body", () => {
  const reqs = parseRequests(
    stream(
      "POST /register HTTP/1.1\r\nContent-Length: 3\r\n\r\n\x00\xffaGET /flag HTTP/1.1\r\nHost: test\r\n\r\n",
    ),
  );
  assert.equal(reqs.length, 2);
  assert.equal(reqs[0].body, "\x00\xffa");
  assert.equal(reqs[1].target, "/flag");
});
test("decodes chunked body and trailers before next request", () => {
  const reqs = parseRequests(
    stream(
      "POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n3;foo=bar\r\nabc\r\n0\r\nX-T: yes\r\n\r\nGET / HTTP/1.1\r\n\r\n",
    ),
  );
  assert.equal(reqs.length, 2);
  assert.equal(reqs[0].body, "abc");
});
test("rejects incomplete, TLS and upgraded traffic instead of exporting a broken replay", () => {
  for (const raw of [
    "POST / HTTP/1.1\r\nContent-Length: 5\r\n\r\nx",
    "\x16\x03\x01",
    "GET / HTTP/1.1\r\nUpgrade: websocket\r\n\r\n",
  ])
    assert.throws(() => parseRequests(stream(raw)));
});
test("farm export is readable, chronological, uses argv IP, flushes every response and preserves binary bodies", () => {
  const code = pythonReplay([
    stream("GET /flag HTTP/1.1\r\nHost: localhost:7070\r\n\r\n", 2, 500),
    stream("POST /register HTTP/1.1\r\nContent-Length: 3\r\n\r\n\x00\xffa"),
  ]);
  assert.ok(code.startsWith("#!/usr/bin/env python3\n"));
  assert.match(code, /IP = sys.argv\[1\]/);
  assert.ok(code.indexOf("s.post(") < code.indexOf("s.get("));
  assert.match(code, /f"http:\/\/\{IP\}:7070\/flag"/);
  assert.equal(code.match(/print\(r.text, flush=True\)/g).length, 2);
  assert.match(code, /data=b"\\x00\\xffa"/);
  assert.match(code, /"Host": "localhost:7070"/);
});
test("farm replay uses fresh cookies and cookie-based CSRF after registration and reaches the flag", () => {
  const code = pythonReplay([
    stream(
      "POST /register HTTP/1.1\r\nHost: localhost:7070\r\nContent-Length: 3\r\n\r\nabc",
      1,
      0,
    ),
    stream(
      "POST /login HTTP/1.1\r\nHost: localhost:7070\r\nCookie: sid=stale; csrf_token=old-token\r\nContent-Length: 14\r\n\r\ncsrf=old-token",
      2,
      10,
    ),
    stream(
      "GET /flag HTTP/1.1\r\nHost: localhost:7070\r\nCookie: sid=stale; csrf_token=old-token\r\n\r\n",
      3,
      20,
    ),
  ]);
  const harness = `
import base64, contextlib, io, sys, threading
from http.server import BaseHTTPRequestHandler, HTTPServer
class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args): pass
    def do_POST(self):
        assert self.headers.get('Host') == 'localhost:7070'
        if self.path == '/register':
            assert self.rfile.read(int(self.headers['Content-Length'])) == b'abc'
            self.send_response(200)
            self.send_header('Set-Cookie', 'sid=fresh; Path=/')
            self.send_header('Set-Cookie', 'csrf_token=fresh-token; Path=/')
        else:
            assert self.path == '/login'
            assert 'sid=fresh' in self.headers.get('Cookie', '')
            assert self.rfile.read(int(self.headers['Content-Length'])) == b'csrf=fresh-token'
            self.send_response(200)
            self.send_header('Set-Cookie', 'sid=loggedin; Path=/')
        self.end_headers()
    def do_GET(self):
        assert self.path == '/flag'
        assert 'sid=loggedin' in self.headers.get('Cookie', '')
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b'ABCDEFGHIJKLMNOPQRSTUVWXYZ12345=')
server = HTTPServer(('127.0.0.1', 0), Handler)
threading.Thread(target=server.serve_forever, daemon=True).start()
code = base64.b64decode('${Buffer.from(code).toString("base64")}').decode()
code = code.replace('{IP}:7070', '{IP}:' + str(server.server_port))
sys.argv = ['replay-chain.py', '127.0.0.1']
out = io.StringIO()
with contextlib.redirect_stdout(out):
    exec(compile(code, 'replay.py', 'exec'), {})
server.shutdown()
assert 'ABCDEFGHIJKLMNOPQRSTUVWXYZ12345=' in out.getvalue(), out.getvalue()
print('registration -> login -> flag OK')
`;
  assert.match(
    execFileSync("python3", ["-c", harness], {
      encoding: "utf8",
      timeout: 10000,
    }),
    /flag OK/,
  );
});
test("ports parser rejects injection, invalid ranges, zero and oversized lists", () => {
  assert.deepEqual(
    parsePorts("7070,8080-8082, 7070"),
    [7070, 8080, 8081, 8082],
  );
  for (const bad of ["0", "65536", "90-80", "1-65535", "7070;touch /tmp/x", ""])
    assert.throws(() => parsePorts(bad));
});
test("yellow flag ranges survive overlapping query matches and preserve escaped HTML/selection offsets", () => {
  const flag = "ABCDEFGHIJKLMNOPQRSTUVWXYZ12345=";
  const text = "<" + flag + ">";
  const escaped = [...text].map((c) =>
    c === "<" ? "&lt;" : c === ">" ? "&gt;" : c,
  );
  const html = renderHighlights(escaped, [
    ...matchRanges(text, [/[A-Z]+/g]),
    ...matchRanges(text, [/[A-Z0-9]{31}=/g], true),
  ]);
  assert.match(html, /flag-mark/);
  assert.match(html, /data-offset="1"/);
  assert.equal(html.replace(/<[^>]+>/g, ""), "&lt;" + flag + "&gt;");
});
