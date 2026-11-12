import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import socket
import subprocess
import threading
import time
from unittest.mock import Mock, patch

from common import Fixture
import safe_http as net


class LocalHandler(BaseHTTPRequestHandler):
    hits = []
    def log_message(self, *_): pass
    def do_GET(self):
        self.hits.append(self.path)
        targets = {"/private": "http://127.0.0.1/secret", "/official": "http://brand.example/secret", "/loop": "http://suspect.example/loop"}
        if self.path in targets:
            self.send_response(302); self.send_header("Location", targets[self.path]); self.end_headers()
        elif self.path == "/huge":
            self.send_response(200); self.send_header("Content-Length", "9999999"); self.end_headers()
        elif self.path == "/compressed":
            self.send_response(200); self.send_header("Content-Encoding", "gzip"); self.end_headers()
        elif self.path == "/slow-headers":
            self.connection.sendall(b"HTTP/1.1 200 OK\r\nX-Slow: ")
            try:
                for _ in range(30):
                    self.connection.sendall(b"x"); time.sleep(0.03)
                self.connection.sendall(b"\r\nContent-Length: 0\r\n\r\n")
            except OSError:
                pass
        else:
            self.send_response(200); self.send_header("Content-Length", "5"); self.end_headers(); self.wfile.write(b"hello")


class TestSafeHTTP(Fixture):
    def start_server(self):
        LocalHandler.hits = []
        server = ThreadingHTTPServer(("127.0.0.1", 0), LocalHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
        self.addCleanup(server.server_close); self.addCleanup(server.shutdown)
        self.enterContext(patch.object(net, "public_addresses", return_value=["93.184.216.34"]))
        # Test-only transport injection. Production has no local-address override flag.
        return self.enterContext(patch.object(net, "_connection", side_effect=lambda *a: http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=2)))

    def test_public_addresses_reject_nonpublic_matrix(self):
        for address in ("127.0.0.1", "10.1.2.3", "169.254.169.254", "192.168.1.2", "::1", "fc00::1", "fe80::1", "::ffff:127.0.0.1", "0.0.0.0", "224.0.0.1", "192.0.2.2"):
            with self.subTest(address=address), patch.object(net, "resolve_addresses", return_value=[address]), self.assertRaises(ValueError):
                net.public_addresses("suspect.example", 80)

    def test_mixed_dns_answers_fail_closed(self):
        with patch.object(net, "resolve_addresses", return_value=["93.184.216.34", "127.0.0.1"]), self.assertRaises(ValueError):
            net.public_addresses("suspect.example", 80)

    def test_dns_timeout_is_bounded(self):
        with patch.object(net.subprocess, "run", side_effect=subprocess.TimeoutExpired("dns", 5)), self.assertRaises(OSError):
            net.resolve_addresses("suspect.example", 80)

    def test_local_redirect_never_contacts_second_hop(self):
        connect = self.start_server()
        with self.assertRaises(ValueError): net.fetch("http://suspect.example/private")
        self.assertEqual(connect.call_count, 1); self.assertEqual(LocalHandler.hits, ["/private"])

    def test_official_redirect_never_contacts_second_hop(self):
        connect = self.start_server()
        with self.assertRaises(ValueError): net.fetch("http://suspect.example/official", ["brand.example"])
        self.assertEqual(connect.call_count, 1); self.assertEqual(LocalHandler.hits, ["/official"])

    def test_pin_ip_passed_to_connection(self):
        connect = self.start_server(); result = net.fetch("http://suspect.example/ok")
        self.assertEqual(result.body, b"hello")
        self.assertEqual(connect.call_args.args[:4], ("suspect.example", 80, "93.184.216.34", False))

    def test_redirect_hop_limit(self):
        connect = self.start_server()
        with self.assertRaises(ValueError): net.fetch("http://suspect.example/loop")
        self.assertEqual(connect.call_count, net.MAX_REDIRECTS + 1)

    def test_response_size_budget(self):
        self.start_server()
        with self.assertRaises(ValueError): net.fetch("http://suspect.example/huge")
        with self.assertRaises(ValueError): net.fetch("http://suspect.example/ok", max_bytes=3)

    def test_compressed_response_rejected(self):
        self.start_server()
        with self.assertRaises(ValueError): net.fetch("http://suspect.example/compressed")

    def test_proxy_rejected_before_connection(self):
        with patch.object(net, "_connection") as connect, self.assertRaises(ValueError):
            net.fetch("http://suspect.example/", proxy="http://127.0.0.1:8080")
        connect.assert_not_called()

    def test_local_namespace_rejected_before_dns(self):
        with patch.object(net, "public_addresses") as resolve, self.assertRaises(ValueError):
            net.fetch("http://metadata.internal/")
        resolve.assert_not_called()

    def test_https_downgrade_rejected(self):
        conn = Mock(); response = Mock(status=302)
        response.getheaders.return_value = [("Location", "http://suspect.example/")]
        conn.getresponse.return_value = response; conn.sock.getpeercert.return_value = b"cert"
        with patch.object(net, "public_addresses", return_value=["93.184.216.34"]), patch.object(net, "_connection", return_value=conn), self.assertRaises(ValueError):
            net.fetch("https://suspect.example/")
        conn.close.assert_called_once()

    def test_peer_mismatch_rejected(self):
        raw = Mock(); raw.getpeername.return_value = ("127.0.0.1", 80)
        with patch.object(net.socket, "create_connection", return_value=raw), self.assertRaises(ValueError):
            net._connection("suspect.example", 80, "93.184.216.34", False, 1)
        raw.close.assert_called_once()

    def test_transition_addresses_are_not_public_egress(self):
        for address in ("64:ff9b::7f00:1", "2002:7f00:1::", "2001:0:4136:e378:8000:63bf:3fff:fdd2"):
            with self.subTest(address=address), patch.object(net, "resolve_addresses", return_value=[address]), self.assertRaises(ValueError):
                net.public_addresses("suspect.example", 80)

    def test_slow_headers_cannot_extend_total_budget(self):
        self.start_server(); started = time.monotonic()
        with self.assertRaises(OSError): net.fetch("http://suspect.example/slow-headers", timeout=0.15)
        self.assertLess(time.monotonic() - started, 1.0)

    def test_dns_child_ignores_site_customization(self):
        with patch.object(net.subprocess, "run", return_value=Mock(stdout=b'["93.184.216.34"]')) as run:
            self.assertEqual(net.resolve_addresses("suspect.example", 80), ["93.184.216.34"])
        self.assertIn("-S", run.call_args.args[0]); self.assertIn("-I", run.call_args.args[0])
