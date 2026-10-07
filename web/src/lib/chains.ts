import type { Result, StreamData } from "@/apiClient";

export type Chain = {
  client: string;
  streams: Result[];
  start: number;
  end: number;
};
export function groupChains(results: Result[], gap = 1000): Chain[] {
  const chains: Chain[] = [];
  const latest = new Map<string, Chain>();
  for (const result of [...results].sort(
    (a, b) =>
      Date.parse(a.Stream.FirstPacket) - Date.parse(b.Stream.FirstPacket) ||
      a.Stream.ID - b.Stream.ID,
  )) {
    const stream = result.Stream;
    const start = Date.parse(stream.FirstPacket);
    const end = Date.parse(stream.LastPacket);
    let chain = latest.get(stream.Client.Host);
    if (!chain || start - chain.end > gap) {
      chain = { client: stream.Client.Host, streams: [], start, end };
      latest.set(chain.client, chain);
      chains.push(chain);
    }
    chain.streams.push(result);
    chain.end = Math.max(chain.end, end);
  }
  return chains.sort((a, b) => b.start - a.start);
}

type Request = {
  method: string;
  target: string;
  headers: [string, string][];
  body: string;
  time: number;
  stream: StreamData["Stream"];
};
export function parseRequests(data: StreamData): Request[] {
  // Reassemble bytes across TCP data chunks, retaining their original times.
  const chunks = data.Data.filter((c) => c.Direction === 0);
  const spans: { end: number; time: number }[] = [];
  let raw = "";
  for (const chunk of chunks) {
    raw += atob(chunk.Content);
    spans.push({
      end: raw.length,
      time: Date.parse(chunk.Time ?? data.Stream.FirstPacket),
    });
  }
  const requests: Request[] = [];
  let pos = 0;
  while (pos < raw.length) {
    const headerEnd = raw.indexOf("\r\n\r\n", pos);
    if (headerEnd < 0)
      throw new Error(`Stream ${data.Stream.ID}: incomplete HTTP headers`);
    const lines = raw.slice(pos, headerEnd).split("\r\n");
    const match = /^([A-Z]+) (\S+) HTTP\/1\.[01]$/.exec(lines.shift() ?? "");
    if (!match)
      throw new Error(
        `Stream ${data.Stream.ID}: export supports plain HTTP/1.x only`,
      );
    const headers: [string, string][] = lines.map((line) => {
      const colon = line.indexOf(":");
      if (colon < 1) throw new Error("Invalid HTTP header");
      return [line.slice(0, colon), line.slice(colon + 1).trim()];
    });
    const header = (name: string) =>
      headers.find((h) => h[0].toLowerCase() === name)?.[1];
    if (header("upgrade"))
      throw new Error("HTTP upgrade/WebSocket cannot be exported to requests");
    let next = headerEnd + 4;
    let body = "";
    if (header("transfer-encoding")) {
      if (header("transfer-encoding")?.toLowerCase() !== "chunked")
        throw new Error("Unsupported transfer encoding");
      while (true) {
        const eol = raw.indexOf("\r\n", next);
        const sizeText = raw.slice(next, eol).split(";")[0];
        if (eol < 0 || !/^[0-9a-f]+$/i.test(sizeText))
          throw new Error("Incomplete HTTP chunk");
        const size = parseInt(sizeText, 16);
        next = eol + 2;
        if (size === 0) {
          if (raw.slice(next, next + 2) === "\r\n") next += 2;
          else {
            const trailers = raw.indexOf("\r\n\r\n", next);
            if (trailers < 0) throw new Error("Incomplete HTTP trailers");
            next = trailers + 4;
          }
          break;
        }
        if (raw.slice(next + size, next + size + 2) !== "\r\n")
          throw new Error("Incomplete HTTP chunk body");
        body += raw.slice(next, next + size);
        next += size + 2;
      }
    } else {
      const lengthText = header("content-length") ?? "0";
      if (!/^\d+$/.test(lengthText)) throw new Error("Invalid Content-Length");
      const length = Number(lengthText);
      if (next + length > raw.length)
        throw new Error("Incomplete HTTP request body");
      body = raw.slice(next, next + length);
      next += length;
    }
    requests.push({
      method: match[1],
      target: match[2],
      headers,
      body,
      time:
        spans.find((s) => s.end > pos)?.time ??
        Date.parse(data.Stream.FirstPacket),
      stream: data.Stream,
    });
    pos = next;
  }
  return requests;
}

function pyString(text: string): string {
  return JSON.stringify(text);
}
function pyDict(entries: [string, string][]): string {
  return `{${entries.map(([key, value]) => `${pyString(key)}: ${pyString(value)}`).join(", ")}}`;
}
function pyBytes(text: string): string {
  return (
    'b"' +
    [...text]
      .map((char) => {
        const code = char.charCodeAt(0);
        if (char === '"' || char === "\\") return "\\" + char;
        if (code >= 32 && code < 127) return char;
        return "\\x" + code.toString(16).padStart(2, "0");
      })
      .join("") +
    '"'
  );
}

export function pythonReplay(streams: StreamData[]): string {
  const requests = streams
    .flatMap(parseRequests)
    .sort((a, b) => a.time - b.time || a.stream.ID - b.stream.ID);
  if (!requests.length) throw new Error("No HTTP requests in this chain");
  const hasCookies = requests.some((r) =>
    r.headers.some(([name]) => name.toLowerCase() === "cookie"),
  );
  const lines = [
    "#!/usr/bin/env python3",
    "import requests",
    "import sys",
    ...(hasCookies
      ? [
          "from http.cookies import SimpleCookie",
          "from urllib.parse import quote, quote_plus, urlsplit",
        ]
      : []),
    "",
    "IP = sys.argv[1]",
    "if ':' in IP and not IP.startswith('['):",
    "    IP = f'[{IP}]'",
    "",
    `# Generated from streams ${streams.map((s) => s.Stream.ID).join(", ")}`,
    "s = requests.Session()",
    "s.trust_env = False",
  ];
  if (hasCookies)
    lines.push(
      "",
      ...[
        "# Use fresh cookies from responses and update cookie-based CSRF values.",
        "_replacements = {}",
        "_seeded = set()",
        "def prepare_cookies(captured, host):",
        "    domain = urlsplit('http://' + host).hostname or IP.strip('[]')",
        "    if '.' not in domain:",
        "        domain += '.local'",
        "    cookies = SimpleCookie()",
        "    cookies.load(captured)",
        "    for name, morsel in cookies.items():",
        "        live = next((c.value for c in s.cookies if c.name == name and c.domain.lstrip('.') == domain), None)",
        "        if live is None and (domain, name) not in _seeded:",
        "            s.cookies.set(name, morsel.value, domain=domain, path='/')",
        "            live = morsel.value",
        "        _seeded.add((domain, name))",
        "        if live is not None and morsel.value and live != morsel.value:",
        "            _replacements[morsel.value] = live",
        "",
        "def rewrite(value):",
        "    if isinstance(value, dict):",
        "        return {k: rewrite(v) for k, v in value.items()}",
        "    for old, new in sorted(_replacements.items(), key=lambda item: -len(item[0])):",
        "        for before, after in ((old, new), (quote(old, safe=''), quote(new, safe='')), (quote_plus(old), quote_plus(new))):",
        "            if isinstance(value, bytes):",
        "                value = value.replace(before.encode(), after.encode())",
        "            else:",
        "                value = value.replace(before, after)",
        "    return value",
      ],
    );
  for (const request of requests) {
    const cookie = request.headers.find(
      ([key]) => key.toLowerCase() === "cookie",
    )?.[1];
    const target = /^https?:\/\//i.test(request.target)
      ? new URL(request.target).pathname + new URL(request.target).search
      : request.target;
    if (!target.startsWith("/") || request.method === "CONNECT")
      throw new Error("Cannot export HTTP proxy/tunnel request");
    // Escape f-string braces originating in the captured path, preserving the IP placeholder.
    const url = `f${pyString(`http://{IP}:${request.stream.Server.Port}${target.replaceAll("{", "{{").replaceAll("}", "}}")}`)}`;
    const headers = pyDict(
      request.headers.filter(
        ([name]) =>
          ![
            "content-length",
            "transfer-encoding",
            "cookie",
            "accept-encoding",
          ].includes(name.toLowerCase()),
      ),
    );
    const method = request.method.toLowerCase();
    const standard = [
      "get",
      "post",
      "put",
      "patch",
      "delete",
      "head",
      "options",
    ].includes(method);
    const call = standard
      ? `s.${method}(`
      : `s.request(${pyString(request.method)}, `;
    const adapt = (value: string) => (hasCookies ? `rewrite(${value})` : value);
    lines.push(
      "",
      `# Stream ${request.stream.ID}: ${request.method} ${target.replace(/[\r\n]/g, " ")}`,
    );
    if (cookie) {
      const host = request.headers.find(
        ([key]) => key.toLowerCase() === "host",
      )?.[1];
      lines.push(
        `prepare_cookies(${pyString(cookie)}, ${host ? pyString(host) : "IP"})`,
      );
    }
    const args = [adapt(url), `headers=${adapt(headers)}`];
    if (request.body.length) args.push(`data=${adapt(pyBytes(request.body))}`);
    args.push("allow_redirects=False", "timeout=30");
    lines.push(`r = ${call}${args.join(", ")})`, "print(r.text, flush=True)");
  }
  return lines.join("\n") + "\n";
}
