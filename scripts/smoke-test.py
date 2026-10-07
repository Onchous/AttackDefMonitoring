#!/usr/bin/env python3
"""Exercise an isolated CI deployment: capture, upload, index, and restart."""
import base64
import json
import subprocess
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.error import URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen


def main():
    config = dict(
        line.split("=", 1)
        for line in Path(".env").read_text().splitlines()
        if line and not line.startswith("#") and "=" in line
    )
    base = "http://127.0.0.1:" + config.get("PKAPPA2_HTTP_PORT", "8080")
    auth = base64.b64encode(
        ("admin:" + config["PKAPPA2_USER_PASSWORD"]).encode()
    ).decode()

    def api(path, method="GET", payload=None):
        request = Request(
            base + path, data=payload, method=method,
            headers={"Authorization": "Basic " + auth},
        )
        with urlopen(request, timeout=25) as response:
            body = response.read()
        return json.loads(body) if body else None

    def wait_for(check):
        deadline = time.monotonic() + 90
        while time.monotonic() < deadline:
            try:
                result = check()
                if result:
                    return result
            except (URLError, TimeoutError, OSError):
                pass
            time.sleep(1)
        raise AssertionError("Deployment did not become ready within 90 seconds")

    wait_for(lambda: api("/api/capture/sources"))
    name = "ci-smoke-" + uuid.uuid4().hex
    marker = b"AttackDefMonitoring-capture-smoke-ok"

    class Service(BaseHTTPRequestHandler):
        def log_message(self, *_args):
            pass

        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-Length", str(len(marker)))
            self.end_headers()
            self.wfile.write(marker)

    server = HTTPServer(("127.0.0.1", 0), Service)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    port = server.server_port
    tag_params = urlencode({"name": "service/" + name, "color": "#00ff00"})
    query = f"sport:{port}"
    try:
        status = api("/api/capture/sources", "POST", json.dumps({
            "Name": name, "Interface": "lo", "Ports": [port],
        }).encode())
        assert any(s["Name"] == name and s["Running"] for s in status["Sources"])
        api("/api/tags?" + tag_params, "PUT", query.encode())
        with urlopen(f"http://127.0.0.1:{port}/test", timeout=10) as response:
            assert response.read() == marker
        results = wait_for(lambda: api(
            "/api/search.json", "POST", (query + " sdata:" + marker.decode()).encode()
        ).get("Results"))
        assert any(r["Stream"]["Server"]["Port"] == port for r in results)
        subprocess.run(["docker", "compose", "restart", "capture"], check=True)
        wait_for(lambda: any(
            s["Name"] == name and s["Running"]
            for s in api("/api/capture/sources")["Sources"]
        ))
        assert any(t["Name"] == "service/" + name for t in api("/api/tags"))
        print("Service creation, capture, authenticated upload, search, and restart OK")
    finally:
        server.shutdown()
        server.server_close()
        api("/api/capture/sources", "DELETE", json.dumps({"Name": name}).encode())
        api("/api/tags?" + tag_params, "DELETE")


if __name__ == "__main__":
    main()
