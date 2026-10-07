import base64
import importlib.util
import json
import os
from pathlib import Path
import struct
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("capture_agent", Path(__file__).resolve().parents[1] / "agent.py")
agent = importlib.util.module_from_spec(spec)
spec.loader.exec_module(agent)
HEADER = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
BODY = b"packet-data"
RECORD = struct.pack("<IIII", 100, 500, len(BODY), len(BODY)) + BODY


class FakeWorker:
    calls = []
    fail_port = None
    def __init__(self, interface, ports, spool):
        self.ports = tuple(sorted(ports))
        if self.fail_port in ports:
            raise ValueError("capture failed")
        self.interface = interface
        self.running = True
        self.error = ""
        self.writer = agent.PacketWriter(spool, interface)
        self.writer.header = HEADER
        self.calls.append(self)
    def stop(self):
        self.running = False
        self.writer.publish()


class AgentTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.interfaces = patch.object(agent.Controller, "interfaces", return_value=["lo", "eth0", "any"])
        self.interfaces.start()
        self.addCleanup(self.interfaces.stop)
        FakeWorker.calls = []
        FakeWorker.fail_port = None
        self.controller = agent.Controller(self.tmp.name, worker_factory=FakeWorker)
        self.addCleanup(self.controller.close)

    def source(self, name="test", ports=None):
        return {"Name": name, "Interface": "lo", "Ports": ports or [7070]}

    def test_persistent_sources_start_immediately_and_share_one_capture_per_interface(self):
        status = self.controller.put(self.source())
        self.assertTrue(status["Sources"][0]["Running"])
        self.controller.put(self.source())
        self.assertEqual(len(FakeWorker.calls), 1)
        self.controller.put(self.source("second", [5001, 7070]))
        self.assertEqual(self.controller.workers["lo"].ports, (5001, 7070))
        self.controller.close()
        restarted = agent.Controller(self.tmp.name, worker_factory=FakeWorker)
        self.addCleanup(restarted.close)
        self.assertEqual(len(restarted.status()["Sources"]), 2)
        self.assertTrue(all(s["Running"] for s in restarted.status()["Sources"]))

    def test_failed_update_rolls_back_config_and_running_capture(self):
        self.controller.put(self.source())
        FakeWorker.fail_port = 9090
        with self.assertRaisesRegex(ValueError, "capture failed"):
            self.controller.put(self.source(ports=[9090]))
        self.assertEqual(self.controller.sources["test"]["Ports"], [7070])
        self.assertTrue(self.controller.workers["lo"].running)
        self.assertEqual(json.loads(self.controller.config.read_text())[0]["Ports"], [7070])

    def test_invalid_ports_interfaces_and_command_text_are_rejected(self):
        for ports in [[0], [65536], [True], ["7070;touch /tmp/x"], []]:
            with self.assertRaises(ValueError):
                self.controller.put({"Name": "test", "Interface": "lo", "Ports": ports})
        with self.assertRaises(ValueError):
            self.controller.put({"Name": "test", "Interface": "lo;id", "Ports": [7070]})
        self.assertEqual(self.controller.sources, {})

    def test_publish_is_atomic_and_stop_flushes_the_last_records(self):
        self.controller.put(self.source())
        writer = self.controller.workers["lo"].writer
        writer.append(RECORD)
        self.assertEqual(list(self.controller.spool.glob("*.pcap")), [])
        self.controller.delete("test")
        paths = list(self.controller.spool.glob("*.pcap"))
        self.assertEqual(len(paths), 1)
        self.assertEqual(paths[0].read_bytes(), HEADER + RECORD)
        self.assertEqual(self.controller.status()["Sources"], [])

    def test_failed_upload_retains_file_then_delivers_complete_pcap_with_auth(self):
        received = []
        attempts = []
        class UploadHandler(BaseHTTPRequestHandler):
            def log_message(self, *args): pass
            def do_POST(self):
                payload = self.rfile.read(int(self.headers["Content-Length"]))
                attempts.append(payload)
                if len(attempts) == 1:
                    self.send_response(503)
                else:
                    self.assert_auth = self.headers["Authorization"]
                    received.append((payload, self.assert_auth, self.path))
                    self.send_response(200)
                self.end_headers()
        server = HTTPServer(("127.0.0.1", 0), UploadHandler)
        self.addCleanup(server.server_close)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(server.shutdown)
        self.controller.put(self.source())
        writer = self.controller.workers["lo"].writer
        writer.append(RECORD)
        writer.publish()
        with patch.dict(os.environ, {"UPLOAD_URL": f"http://127.0.0.1:{server.server_port}", "PKAPPA2_PCAP_PASSWORD": "test-secret"}):
            uploader = threading.Thread(target=self.controller.upload, daemon=True)
            uploader.start()
            deadline = time.time() + 5
            while not received and time.time() < deadline:
                time.sleep(0.02)
            self.controller.closing.set()
            uploader.join(2)
        self.assertEqual(len(attempts), 2)
        self.assertEqual(received[0][0], HEADER + RECORD)
        self.assertEqual(received[0][1], "Basic " + base64.b64encode(b"pcap:test-secret").decode())
        self.assertEqual(list(self.controller.spool.glob("*.pcap")), [])

    def test_idle_service_starts_before_the_first_packet(self):
        fake = Path(self.tmp.name) / "tcpdump-idle"
        fake.write_text("#!/usr/bin/env python3\nimport sys, time, signal\nsignal.signal(signal.SIGINT, lambda *_: sys.exit(0))\n" +
            "print('listening on lo, link-type EN10MB', file=sys.stderr, flush=True)\n" +
            "while True: time.sleep(0.1)\n")
        fake.chmod(0o755)
        worker = agent.Worker("lo", [7070], self.controller.spool, tcpdump=str(fake))
        self.addCleanup(worker.stop)
        self.assertTrue(worker.running)
        self.assertIsNone(worker.writer.header)
        self.assertEqual(worker.writer.packets, 0)

    def test_reader_handles_fragmented_tcpdump_pipe_and_publishes_without_restart(self):
        fake = Path(self.tmp.name) / "tcpdump"
        fake.write_text("#!/usr/bin/env python3\nimport sys, time, signal\nsignal.signal(signal.SIGINT, lambda *_: sys.exit(0))\n" +
            f"sys.stdout.buffer.write({HEADER!r}); sys.stdout.buffer.flush()\n" +
            f"data = {RECORD!r}\n" +
            "sys.stdout.buffer.write(data[:5]); sys.stdout.buffer.flush(); time.sleep(0.03)\n" +
            "sys.stdout.buffer.write(data[5:]); sys.stdout.buffer.flush()\n" +
            "while True: time.sleep(0.1)\n")
        fake.chmod(0o755)
        worker = agent.Worker("lo", [7070], self.controller.spool, tcpdump=str(fake))
        self.addCleanup(worker.stop)
        pid = worker.process.pid
        deadline = time.time() + 2
        while not worker.writer.packets and time.time() < deadline:
            time.sleep(0.01)
        worker.writer.publish()
        self.assertTrue(worker.running)
        self.assertEqual(worker.process.pid, pid)
        path = next(self.controller.spool.glob("*.pcap"))
        self.assertEqual(path.read_bytes(), HEADER + RECORD)


if __name__ == "__main__":
    unittest.main()
