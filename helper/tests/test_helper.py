import json
import os
import sys
import threading
import unittest
import urllib.error
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import echo_server  # noqa: E402
import server  # noqa: E402

WINDOWS_ARP = """
Interface: 192.168.1.5 --- 0x7
  Internet Address      Physical Address      Type
  192.168.1.1           a4-2b-b0-11-22-33     dynamic
  192.168.1.255         ff-ff-ff-ff-ff-ff     static
  224.0.0.22            01-00-5e-00-00-16     static
"""
LINUX_ARP = "_gateway (192.168.0.1) at 0:1a:2b:3c:4d:5e [ether] on wlan0\n? (192.168.0.7) at <incomplete> on wlan0\n"
MAC_ARP = "? (10.0.0.1) at 0:11:22:33:44:55 on en0 ifscope [ethernet]\n? (10.0.0.9) at 2:aa:bb:cc:dd:ee on en0 ifscope permanent [ethernet]\n"
PROC_ARP = """IP address       HW type     Flags       HW address            Mask     Device
172.17.0.1       0x1         0x2         02:42:5a:9c:11:01     *        eth0
172.17.0.9       0x1         0x0         00:00:00:00:00:00     *        eth0
"""


class ArpParsing(unittest.TestCase):
    def test_windows(self):
        e = server.parse_arp(WINDOWS_ARP)
        self.assertEqual(len(e), 3)
        self.assertEqual(e[0], {"interface": "192.168.1.5", "ip": "192.168.1.1", "mac": "a4:2b:b0:11:22:33", "type": "dynamic", "note": None})
        self.assertEqual(e[1]["note"], "broadcast")
        self.assertEqual(e[2]["note"], "IPv4 multicast")

    def test_linux_skips_incomplete(self):
        e = server.parse_arp(LINUX_ARP)
        self.assertEqual(len(e), 1)
        self.assertEqual(e[0]["mac"], "00:1a:2b:3c:4d:5e")
        self.assertEqual(e[0]["interface"], "wlan0")

    def test_macos(self):
        e = server.parse_arp(MAC_ARP)
        self.assertEqual([x["ip"] for x in e], ["10.0.0.1", "10.0.0.9"])
        self.assertEqual(e[1]["type"], "static")
        self.assertEqual(e[1]["note"], "locally administered (often randomised)")

    def test_proc_net_arp(self):
        e = server.parse_proc_net_arp(PROC_ARP)
        self.assertEqual(len(e), 1)
        self.assertEqual(e[0]["ip"], "172.17.0.1")


class Validation(unittest.TestCase):
    def test_hostnames(self):
        self.assertTrue(server.valid_hostname("example.com"))
        self.assertTrue(server.valid_hostname("a-b.c.example.org."))
        self.assertFalse(server.valid_hostname("bad host"))
        self.assertFalse(server.valid_hostname("-x.com"))
        self.assertFalse(server.valid_hostname("x;rm -rf /"))

    def test_allowlist(self):
        cfg = {"allowed_test_targets": ["127.0.0.1"], "allowed_ports": [9000]}
        server.check_target(cfg, "127.0.0.1", 9000)
        with self.assertRaises(PermissionError):
            server.check_target(cfg, "8.8.8.8", 9000)
        with self.assertRaises(PermissionError):
            server.check_target(cfg, "127.0.0.1", 22)


class LiveSockets(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tcp, cls.udp = echo_server.start("127.0.0.1", 0)
        cls.port = cls.tcp.server_address[1]
        cls.cfg = {"allowed_test_targets": ["127.0.0.1"], "allowed_ports": [cls.port]}

    @classmethod
    def tearDownClass(cls):
        cls.tcp.shutdown(); cls.udp.shutdown()
        cls.tcp.server_close(); cls.udp.server_close()

    def test_tcp_handshake(self):
        r = server.tcp_connect_test(self.cfg, "127.0.0.1", self.port, attempts=3)
        self.assertEqual(r["succeeded"], 3)
        self.assertIsNotNone(r["avgHandshakeMs"])
        # every connection uses a fresh ephemeral local port
        self.assertEqual(len({s["local"] for s in r["samples"]}), 3)

    def test_udp_echo_no_loss(self):
        r = server.udp_echo_test(self.cfg, "127.0.0.1", self.port, count=5)
        self.assertEqual(r["received"], 5)
        self.assertEqual(r["lossPct"], 0)

    def test_udp_echo_with_injected_loss(self):
        old = echo_server.UDPEcho.loss_pct
        echo_server.UDPEcho.loss_pct = 100
        try:
            r = server.udp_echo_test(self.cfg, "127.0.0.1", self.port, count=3, timeout=0.2)
        finally:
            echo_server.UDPEcho.loss_pct = old
        self.assertEqual(r["lossPct"], 100.0)


class HttpApi(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.httpd = server.make_server(0, {"allowed_test_targets": ["127.0.0.1"], "allowed_ports": [9000]})
        cls.base = f"http://127.0.0.1:{cls.httpd.server_address[1]}"
        threading.Thread(target=cls.httpd.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown(); cls.httpd.server_close()

    def get(self, path, headers=None):
        req = urllib.request.Request(self.base + path, headers=headers or {})
        try:
            with urllib.request.urlopen(req, timeout=5) as r:
                return r.status, json.loads(r.read())
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read())

    def test_health(self):
        code, body = self.get("/health", {"Origin": "chrome-extension://abc"})
        self.assertEqual(code, 200)
        self.assertTrue(body["ok"])

    def test_web_origin_blocked(self):
        code, body = self.get("/health", {"Origin": "https://evil.example"})
        self.assertEqual(code, 403)

    def test_web_page_without_origin_blocked(self):
        # <img src="http://127.0.0.1:8765/..."> on a website sends no Origin, only Sec-Fetch-Mode: no-cors
        for mode in ("no-cors", "navigate"):
            code, _ = self.get("/health", {"Sec-Fetch-Mode": mode})
            self.assertEqual(code, 403, mode)

    def test_extension_fetch_allowed(self):
        code, _ = self.get("/health", {"Origin": "chrome-extension://abc", "Sec-Fetch-Mode": "cors"})
        self.assertEqual(code, 200)

    def test_rebinding_host_blocked(self):
        code, _ = self.get("/health", {"Host": "attacker.example"})
        self.assertEqual(code, 403)

    def test_unapproved_target_rejected(self):
        code, body = self.get("/tcp?host=8.8.8.8&port=53")
        self.assertEqual(code, 403)
        self.assertIn("not an approved", body["error"])

    def test_bad_dns_name(self):
        code, _ = self.get("/dns?name=bad%20host")
        self.assertEqual(code, 400)

    def test_localhost_dns(self):
        code, body = self.get("/dns?name=localhost")
        self.assertEqual(code, 200)
        self.assertTrue(body["records"])
        # timeMs is the address lookup only, so it can never exceed the total
        self.assertLessEqual(body["timeMs"], body["totalMs"])


if __name__ == "__main__":
    unittest.main()
