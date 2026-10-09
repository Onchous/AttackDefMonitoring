import type { Result, StreamData } from "@/apiClient";

export type Chain = {
  client: string;
  streams: Result[];
  start: number;
  end: number;
};
export function groupChains(results: Result[], gap = 1000): Chain[] {
  const chains: Chain[] = [];
  const latest = new Map<string, Chain & { lastStart: number }>();
  for (const result of [...results].sort(
    (a, b) =>
      Date.parse(a.Stream.FirstPacket) - Date.parse(b.Stream.FirstPacket) ||
      a.Stream.ID - b.Stream.ID,
  )) {
    const stream = result.Stream;
    const start = Date.parse(stream.FirstPacket);
    const end = Date.parse(stream.LastPacket);
    const key = stream.Client.Host;
    let chain = latest.get(key);
    if (!chain || start - chain.lastStart > gap) {
      chain = {
        client: stream.Client.Host,
        streams: [],
        start,
        end,
        lastStart: start,
      };
      latest.set(key, chain);
      chains.push(chain);
    }
    chain.streams.push(result);
    chain.end = Math.max(chain.end, end);
    chain.lastStart = start;
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
function pyHeaders(entries: [string, string][]): string {
  return `{${entries
    .map(([key, value]) => `${pyString(key)}: ${pyString(value)}`)
    .join(", ")}}`;
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

function renderPython(
  streams: StreamData[],
  requests: Request[],
  skipped: ReplaySkip[] = [],
): string {
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
          "from urllib.parse import quote, quote_plus",
        ]
      : []),
    "",
    "IP = sys.argv[1]",
    "",
    `# Generated from streams ${streams.map((s) => s.Stream.ID).join(", ")}`,
    ...skipped.map(
      (item) =>
        `# Skipped stream ${item.streamId}: ${item.reason.replace(/[\r\n]+/g, " ")}`,
    ),
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
        "def prepare_cookies(captured):",
        "    cookies = SimpleCookie()",
        "    cookies.load(captured)",
        "    for name, morsel in cookies.items():",
        "        scoped = next((c.value for c in s.cookies if c.name == name and c.domain), None)",
        "        if scoped is not None and name in _seeded:",
        "            try:",
        "                s.cookies.clear(domain='', path='/', name=name)",
        "            except KeyError:",
        "                pass",
        "        live = scoped if scoped is not None else next((c.value for c in s.cookies if c.name == name), None)",
        "        if live is None and name not in _seeded:",
        "            s.cookies.set(name, morsel.value, path='/')",
        "            live = morsel.value",
        "        _seeded.add(name)",
        "        if live is not None and len(morsel.value) >= 6 and live != morsel.value:",
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
  requests.forEach((request, requestIndex) => {
    const cookie = request.headers.find(
      ([key]) => key.toLowerCase() === "cookie",
    )?.[1];
    const target = /^https?:\/\//i.test(request.target)
      ? new URL(request.target).pathname + new URL(request.target).search
      : request.target;
    if (!target.startsWith("/") || request.method === "CONNECT")
      throw new Error("Cannot export HTTP proxy/tunnel request");
    // Escape f-string braces originating in the captured path, preserving the IP placeholder.
    let url = `f${pyString(`http://{IP}:${request.stream.Server.Port}${target.replaceAll("{", "{{").replaceAll("}", "}}")}`)}`;
    const headers = pyHeaders(
      request.headers.filter(
        ([name]) =>
          ![
            "content-length",
            "transfer-encoding",
            "cookie",
            "accept-encoding",
            "connection",
            "proxy-connection",
            "keep-alive",
            "te",
            "trailer",
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
      lines.push(`prepare_cookies(${pyString(cookie)})`);
    }
    if (hasCookies) {
      const pathVariable = `_request_path_${requestIndex + 1}`;
      lines.push(`${pathVariable} = rewrite(${pyString(target.slice(1))})`);
      // Keep the complete authority static. Dynamic replacements are confined
      // to the path after '/', so they can never change the destination host.
      url = `f"http://{IP}:${request.stream.Server.Port}/{${pathVariable}.lstrip('/')}"`;
    }
    const args = [adapt(url), `headers=${adapt(headers)}`];
    if (hasCookies) args[0] = url;
    if (request.body.length) args.push(`data=${adapt(pyBytes(request.body))}`);
    args.push("allow_redirects=False", "timeout=30");
    lines.push(`r = ${call}${args.join(", ")})`, "print(r.text, flush=True)");
  });
  return lines.join("\n") + "\n";
}

export type ReplaySkip = { streamId: number; reason: string };
export type ReplayResult = {
  code: string;
  requestCount: number;
  skipped: ReplaySkip[];
};

export function pythonReplay(streams: StreamData[]): string {
  const requests = streams
    .flatMap(parseRequests)
    .sort((a, b) => a.time - b.time || a.stream.ID - b.stream.ID);
  return renderPython(streams, requests);
}

export function pythonReplayDetailed(streams: StreamData[]): ReplayResult {
  const requests: Request[] = [];
  const skipped: ReplaySkip[] = [];
  for (const stream of streams) {
    try {
      const parsed = parseRequests(stream);
      if (parsed.length) {
        // Validate URL/method constraints per stream so one proxy/tunnel request
        // cannot prevent exporting the remaining HTTP chain.
        renderPython([stream], parsed);
        requests.push(...parsed);
      } else
        skipped.push({
          streamId: stream.Stream.ID,
          reason: "no client HTTP requests",
        });
    } catch (error) {
      skipped.push({ streamId: stream.Stream.ID, reason: String(error) });
    }
  }
  requests.sort((a, b) => a.time - b.time || a.stream.ID - b.stream.ID);
  return {
    code: renderPython(streams, requests, skipped),
    requestCount: requests.length,
    skipped,
  };
}
