#!/usr/bin/env python3
"""Persistent capture controller, reachable only through a shared Unix socket."""
import base64
import json
import os
from pathlib import Path
import re
import signal
import socket
import socketserver
import struct
import subprocess
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler
from urllib.error import HTTPError
from urllib.request import Request, urlopen


class PacketWriter:
    """Publish complete PCAP records on a timer without restarting tcpdump."""
    def __init__(self, directory, interface):
        self.directory = Path(directory)
        self.directory.mkdir(parents=True, exist_ok=True)
        self.interface = re.sub(r"[^a-zA-Z0-9_.-]", "_", interface)
        self.header = None
        self.file = None
        self.path = None
        self.lock = threading.RLock()
        self.packets = 0
        self.last_packet = None

    def append(self, record):
        with self.lock:
            if self.file is None:
                self.path = self.directory / f"capture-{self.interface}-{uuid.uuid4().hex}.partial"
                self.file = self.path.open("xb")
                self.file.write(self.header)
            self.file.write(record)
            self.packets += 1
            self.last_packet = time.time()
            if self.file.tell() >= 16 * 1024 * 1024:
                self.publish()

    def publish(self):
        with self.lock:
            if self.file is not None:
                self.file.flush()
                os.fsync(self.file.fileno())
                self.file.close()
                self.path.rename(self.path.with_suffix(".pcap"))
                self.file = None
                self.path = None


def read_exact(pipe, length):
    data = bytearray()
    while len(data) < length:
        part = pipe.read(length - len(data))
        if not part:
            if not data:
                return None
            raise ValueError("tcpdump ended in a partial PCAP record")
        data.extend(part)
    return bytes(data)


class Worker:
    def __init__(self, interface, ports, spool, tcpdump="tcpdump"):
        self.interface = interface
        self.ports = tuple(sorted(set(ports)))
        self.writer = PacketWriter(spool, interface)
        self.error = ""
        self.ready = threading.Event()
        self.finished = threading.Event()
        self.process = None
        expression = " or ".join(f"port {port}" for port in self.ports)
        self.process = subprocess.Popen(
            [tcpdump, "-i", interface, "-p", "-nn", "-s", "0", "-U", "-Z", "root", "-w", "-", f"(tcp or udp) and ({expression})"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=0,
        )
        self.reader = threading.Thread(target=self._read, daemon=True)
        self.stderr = threading.Thread(target=self._stderr, daemon=True)
        self.reader.start()
        self.stderr.start()
        if not self.ready.wait(5) or not self.running:
            self.stop()
            raise ValueError(self.error or f"Unable to start capture on {interface}")

    @property
    def running(self):
        return self.process is not None and self.process.poll() is None and not self.finished.is_set()

    def _stderr(self):
        for line in self.process.stderr:
            text = line.decode(errors="replace").strip()
            # tcpdump may buffer the global PCAP header until the first packet.
            # Confirm startup from its listening message even on an idle service.
            if "listening on" in text:
                self.ready.set()
            if "listening on" not in text and "packets " not in text:
                self.error = text[-1000:]
            print(f"tcpdump[{self.interface}]: {text}", flush=True)

    def _read(self):
        try:
            header = read_exact(self.process.stdout, 24)
            if header is None:
                raise ValueError("tcpdump exited before sending a PCAP header")
            if header[:4] in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"):
                endian = "<"
            elif header[:4] in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"):
                endian = ">"
            else:
                raise ValueError("Unknown PCAP format from tcpdump")
            self.writer.header = header
            self.ready.set()
            while True:
                record = read_exact(self.process.stdout, 16)
                if record is None:
                    break
                length = struct.unpack(endian + "I", record[8:12])[0]
                if length > 16 * 1024 * 1024:
                    raise ValueError("Invalid PCAP packet length")
                body = read_exact(self.process.stdout, length) if length else b""
                if body is None:
                    raise ValueError("Incomplete PCAP packet")
                self.writer.append(record + body)
        except (OSError, ValueError) as exc:
            self.error = str(exc)
        finally:
            self.writer.publish()
            self.finished.set()
            self.ready.set()

    def stop(self):
        if self.process is not None and self.process.poll() is None:
            self.process.send_signal(signal.SIGINT)
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait()
        self.reader.join(timeout=5)
        self.stderr.join(timeout=1)
        self.writer.publish()
        self.process.stdout.close()
        self.process.stderr.close()


class Controller:
    def __init__(self, state, interval=2, worker_factory=Worker):
        self.state = Path(state)
        self.state.mkdir(parents=True, exist_ok=True)
        self.spool = self.state / "spool"
        self.spool.mkdir(exist_ok=True)
        self.config = self.state / "sources.json"
        self.interval = interval
        self.worker_factory = worker_factory
        self.sources = {}
        self.workers = {}
        self.errors = {}
        self.lock = threading.RLock()
        self.upload_error = ""
        self.last_upload = None
        self.closing = threading.Event()
        if self.config.exists():
            for source in json.loads(self.config.read_text()):
                self.sources[source["Name"]] = self.validate(source, require_interface=False)
        # Only complete packet records are ever appended, so orphan files are recoverable.
        for path in self.spool.glob("*.partial"):
            if path.stat().st_size > 24:
                path.rename(path.with_suffix(".pcap"))
            else:
                path.unlink()
        try:
            self._reconcile()
        except ValueError:
            pass

    @staticmethod
    def interfaces():
        return ["any"] + sorted(name for _, name in socket.if_nameindex())

    def validate(self, source, require_interface=True):
        if not isinstance(source, dict):
            raise ValueError("Expected a source object")
        name, interface, ports = source.get("Name"), source.get("Interface"), source.get("Ports")
        if not isinstance(name, str) or not name.strip() or len(name) > 128 or any(ord(c) < 32 for c in name):
            raise ValueError("Invalid service name")
        if not isinstance(interface, str) or (require_interface and interface not in self.interfaces()):
            raise ValueError("Choose an existing network interface")
        if not isinstance(ports, list) or not ports or len(ports) > 1024:
            raise ValueError("Specify between 1 and 1024 ports")
        if any(type(port) is not int or not 1 <= port <= 65535 for port in ports):
            raise ValueError("Ports must be integers between 1 and 65535")
        return {"Name": name.strip(), "Interface": interface, "Ports": sorted(set(ports))}

    def _persist(self):
        temporary = self.config.with_suffix(".tmp")
        temporary.write_text(json.dumps(list(self.sources.values())))
        os.chmod(temporary, 0o600)
        temporary.replace(self.config)

    def _reconcile(self):
        desired = {}
        for source in self.sources.values():
            desired.setdefault(source["Interface"], set()).update(source["Ports"])
        for interface, worker in list(self.workers.items()):
            if interface not in desired or worker.ports != tuple(sorted(desired[interface])) or not worker.running:
                worker.stop()
                del self.workers[interface]
        errors = []
        for interface, ports in desired.items():
            if interface not in self.workers:
                try:
                    self.workers[interface] = self.worker_factory(interface, ports, self.spool)
                    self.errors.pop(interface, None)
                except (OSError, ValueError) as exc:
                    print(f"Capture failed: {exc}", flush=True)
                    self.errors[interface] = str(exc)
                    errors.append(str(exc))
        if errors:
            raise ValueError("; ".join(errors))

    def put(self, source):
        source = self.validate(source)
        with self.lock:
            previous = dict(self.sources)
            self.sources[source["Name"]] = source
            try:
                self._reconcile()
                self._persist()
            except (OSError, ValueError):
                self.sources = previous
                try:
                    self._reconcile()
                except ValueError:
                    pass
                raise
            return self.status()

    def delete(self, name):
        with self.lock:
            previous = dict(self.sources)
            self.sources.pop(name, None)
            try:
                self._reconcile()
                self._persist()
            except (OSError, ValueError):
                self.sources = previous
                self._reconcile()
                raise
            return self.status()

    def status(self):
        with self.lock:
            sources = []
            for source in self.sources.values():
                worker = self.workers.get(source["Interface"])
                sources.append({**source, "Running": bool(worker and worker.running),
                    "Packets": worker.writer.packets if worker else 0,
                    "LastPacket": worker.writer.last_packet if worker else None,
                    "Error": worker.error if worker else self.errors.get(source["Interface"], "Capture is not running")})
            return {"Interfaces": self.interfaces(), "Sources": sources,
                "UploadError": self.upload_error, "LastUpload": self.last_upload,
                "PendingFiles": len(list(self.spool.glob("*.pcap")))}

    def maintenance(self):
        while not self.closing.wait(self.interval):
            with self.lock:
                for worker in self.workers.values():
                    worker.writer.publish()
                try:
                    self._reconcile()
                except ValueError:
                    pass

    def upload(self):
        url = os.environ.get("UPLOAD_URL", "http://127.0.0.1:8080").rstrip("/")
        password = os.environ.get("PKAPPA2_PCAP_PASSWORD", "")
        auth = base64.b64encode(f"pcap:{password}".encode()).decode()
        while not self.closing.is_set():
            for path in sorted(self.spool.glob("*.pcap")):
                try:
                    request = Request(f"{url}/upload/{path.name}", data=path.read_bytes(),
                        headers={"Authorization": f"Basic {auth}", "Content-Type": "application/octet-stream"}, method="POST")
                    with urlopen(request, timeout=10) as response:
                        response.read()
                    path.unlink()
                    self.upload_error = ""
                    self.last_upload = time.time()
                except (OSError, HTTPError) as exc:
                    self.upload_error = str(exc)
                    if isinstance(exc, HTTPError):
                        exc.close()
                    break
            self.closing.wait(1)

    def close(self):
        self.closing.set()
        with self.lock:
            for worker in self.workers.values():
                worker.stop()
            self.workers.clear()


class UnixServer(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True


class Handler(BaseHTTPRequestHandler):
    def log_message(self, format_string, *args):
        print(format_string % args, flush=True)

    def reply(self, status, data):
        body = json.dumps(data).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path != "/sources":
            self.reply(404, {"Error": "Not found"})
            return
        self.reply(200, self.server.controller.status())

    def mutate(self, delete=False):
        if self.path != "/sources":
            self.reply(404, {"Error": "Not found"})
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if not 0 < length <= 65536:
                raise ValueError("Invalid request size")
            body = json.loads(self.rfile.read(length))
            if delete:
                if not isinstance(body, dict) or not isinstance(body.get("Name"), str):
                    raise ValueError("Specify the service name")
                result = self.server.controller.delete(body["Name"])
            else:
                result = self.server.controller.put(body)
            self.reply(200, result)
        except (ValueError, TypeError, OSError) as exc:
            self.reply(400, {"Error": str(exc)})

    def do_POST(self):
        self.mutate()

    def do_DELETE(self):
        self.mutate(delete=True)


def main():
    state = os.environ.get("CAPTURE_STATE", "/state")
    socket_path = Path(os.environ.get("CAPTURE_SOCKET", "/run/pkappa2-capture/control.sock"))
    socket_path.parent.mkdir(parents=True, exist_ok=True)
    socket_path.unlink(missing_ok=True)
    controller = Controller(state)
    server = UnixServer(str(socket_path), Handler)
    server.controller = controller
    os.chmod(socket_path, 0o666)
    for task in (controller.maintenance, controller.upload):
        threading.Thread(target=task, daemon=True).start()
    def shutdown(_signum, _frame):
        controller.close()
        threading.Thread(target=server.shutdown, daemon=True).start()
    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)
    try:
        server.serve_forever()
    finally:
        controller.close()
        server.server_close()
        socket_path.unlink(missing_ok=True)


if __name__ == "__main__":
    main()
