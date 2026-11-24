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

    def test_empty_allowed_ports_denies_every_port(self):
        cfg = {"allowed_test_targets": ["127.0.0.1"], "allowed_ports": []}
        with self.assertRaises(PermissionError) as ctx:
            server.check_target(cfg, "127.0.0.1", 9000)
        self.assertIn("allowed_ports", str(ctx.exception))
        with self.assertRaises(PermissionError):
            server.check_target(cfg, "127.0.0.1", 22)

    def test_missing_allowed_ports_denies_every_port(self):
        cfg = {"allowed_test_targets": ["127.0.0.1"]}
        with self.assertRaises(PermissionError) as ctx:
            server.check_target(cfg, "127.0.0.1", 9000)
        self.assertIn("allowed_ports", str(ctx.exception))

    def test_listed_port_still_allowed(self):
        cfg = {"allowed_test_targets": ["127.0.0.1"], "allowed_ports": [9000, 9001]}
        server.check_target(cfg, "127.0.0.1", 9001)

    def test_load_config_defaults(self):
        cfg = server.load_config(os.path.join(os.path.dirname(__file__), "no-such-config.json"))
        self.assertEqual(cfg["allowed_ports"], [9000])
        self.assertEqual(cfg["allowed_extension_ids"], [])


class ConfigValidation(unittest.TestCase):
    GOOD_ID = "abcdefghijklmnopabcdefghijklmnop"

    def _load(self, **overrides):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "config.json")
            with open(path, "w", encoding="utf-8") as fh:
                json.dump(overrides, fh)
            return server.load_config(path)

    def test_string_instead_of_list_ids_rejected(self):
        with self.assertRaises(ValueError) as ctx:
            self._load(allowed_extension_ids=self.GOOD_ID)
        self.assertIn("allowed_extension_ids", str(ctx.exception))

    def test_empty_string_id_rejected(self):
        with self.assertRaises(ValueError) as ctx:
            self._load(allowed_extension_ids=[""])
        self.assertIn("allowed_extension_ids", str(ctx.exception))

    def test_malformed_id_rejected(self):
        for bad in ("short", self.GOOD_ID + "a", "z" * 32, "abcdefghijklmnopabcdefghijklmno1"):
            with self.assertRaises(ValueError, msg=bad):
                self._load(allowed_extension_ids=[bad])
        with self.assertRaises(ValueError):
            self._load(allowed_extension_ids=[123])

    def test_uppercase_id_accepted_and_lowercased(self):
        cfg = self._load(allowed_extension_ids=[self.GOOD_ID.upper()])
        self.assertEqual(cfg["allowed_extension_ids"], [self.GOOD_ID])

    def test_string_ports_rejected(self):
        with self.assertRaises(ValueError) as ctx:
            self._load(allowed_ports=["9000"])
        self.assertIn("allowed_ports", str(ctx.exception))
        with self.assertRaises(ValueError):
            self._load(allowed_ports="9000")

    def test_bad_targets_rejected(self):
        with self.assertRaises(ValueError) as ctx:
            self._load(allowed_test_targets="127.0.0.1")
        self.assertIn("allowed_test_targets", str(ctx.exception))
        with self.assertRaises(ValueError):
            self._load(allowed_test_targets=[127])

    def test_valid_config_loads(self):
        cfg = self._load(allowed_ports=[9000, 9001], allowed_test_targets=["localhost"])
        self.assertEqual(cfg["allowed_ports"], [9000, 9001])


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


class HandshakeSizes(unittest.TestCase):
    def test_windows_packet_sizes_off_loopback(self):
        p = {x["name"]: x for x in server.handshake_packets("192.168.1.10", system="Windows")}
        self.assertEqual(p["SYN"]["tcpHeader"], 32)         # 20 + 12 option bytes
        self.assertEqual(p["SYN"]["ipBytes"], 52)           # 20 IP + 32 TCP
        self.assertEqual(p["SYN-ACK"]["ipBytes"], 52)
        self.assertEqual(p["ACK"]["ipBytes"], 40)           # bare 20 + 20
        self.assertEqual(p["SYN"]["frameBytes"], 66)        # + 14 Ethernet
        self.assertEqual(p["ACK"]["frameBytes"], 60)        # 54 padded up to the 60-byte minimum
        self.assertEqual(p["ACK"]["padBytes"], 6)
        self.assertTrue(all(x["payload"] == 0 for x in p.values()))

    def test_linux_options_include_timestamps(self):
        p = {x["name"]: x for x in server.handshake_packets("10.0.0.2", system="Linux")}
        self.assertEqual(p["SYN"]["ipBytes"], 60)
        self.assertEqual(p["ACK"]["ipBytes"], 52)

    def test_loopback_has_no_ethernet_header(self):
        for x in server.handshake_packets("127.0.0.1", system="Windows"):
            self.assertEqual(x["linkBytes"], 0)
            self.assertEqual(x["frameBytes"], x["ipBytes"])

    def test_ipv6_header_is_40_bytes(self):
        syn = server.handshake_packets("2001:db8::1", system="Windows")[0]
        self.assertEqual(syn["ipHeader"], 40)
        self.assertEqual(syn["ipBytes"], 40 + 32)

    def test_data_packet_overhead(self):
        d = server.data_packet("10.0.0.2", 64, system="Windows")
        self.assertEqual(d["ipBytes"], 104)
        self.assertEqual(d["headerOverheadPct"], round(100 * 40 / 104, 1))


class TcpHandshakeLive(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tcp, cls.udp = echo_server.start("127.0.0.1", 0)
        cls.port = cls.tcp.server_address[1]
        cls.cfg = {"allowed_test_targets": ["127.0.0.1"], "allowed_ports": [cls.port]}

    @classmethod
    def tearDownClass(cls):
        cls.tcp.shutdown(); cls.udp.shutdown()
        cls.tcp.server_close(); cls.udp.server_close()

    def test_result_reports_sizes_and_measured_data_round_trip(self):
        r = server.tcp_connect_test(self.cfg, "127.0.0.1", self.port, attempts=2, payload=100)
        s = r["sizes"]
        self.assertEqual(s["label"], "Calculated")
        self.assertEqual(len(s["packets"]), 3)
        self.assertEqual(s["handshakeIpBytes"], sum(p["ipBytes"] for p in s["packets"]))
        self.assertGreater(s["mss"], 0)
        d = s["dataExchange"]
        self.assertEqual((d["sentBytes"], d["receivedBytes"], d["echoed"]), (100, 100, True))
        self.assertGreater(d["rttMs"], 0)
        self.assertEqual(d["ipBytes"], d["headerBytes"] + 100)

    def test_payload_zero_skips_data_exchange_and_is_clamped(self):
        r = server.tcp_connect_test(self.cfg, "127.0.0.1", self.port, attempts=1, payload=0)
        self.assertNotIn("dataExchange", r["sizes"])
        r = server.tcp_connect_test(self.cfg, "127.0.0.1", self.port, attempts=1, payload=10_000_000)
        self.assertEqual(r["sizes"]["dataExchange"]["sentBytes"], server.MAX_PAYLOAD)

    def test_probe_targets_sees_the_echo_server(self):
        self.assertEqual(server.probe_targets(self.cfg), [{"target": f"127.0.0.1:{self.port}", "listening": True}])


class RefusedConnection(unittest.TestCase):
    """The WinError 10061 case: the target is approved but nothing is listening on it."""

    def setUp(self):
        import socket
        with socket.socket() as s:  # grab a port that is certainly free, then close it
            s.bind(("127.0.0.1", 0))
            self.port = s.getsockname()[1]
        self.cfg = {"allowed_test_targets": ["127.0.0.1"], "allowed_ports": [self.port]}

    def test_refused_is_reported_once_with_a_hint(self):
        r = server.tcp_connect_test(self.cfg, "127.0.0.1", self.port, attempts=3)
        self.assertEqual(r["succeeded"], 0)
        self.assertEqual(len(r["samples"]), 1)  # stops after the first refusal
        self.assertTrue(r["samples"][0]["refused"])
        self.assertIn("nothing is listening", r["samples"][0]["error"])
        self.assertIn("echo_server.py", r["hint"])
        self.assertNotIn("sizes", r)

    def test_probe_targets_reports_not_listening(self):
        self.assertEqual(server.probe_targets(self.cfg), [{"target": f"127.0.0.1:{self.port}", "listening": False}])


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

    def test_health_reports_unpinned(self):
        _, body = self.get("/health", {"Origin": "chrome-extension://abc"})
        self.assertIs(body["extensionPinned"], False)

    def test_empty_allowed_ports_blocks_tcp_over_http(self):
        # A config with allowed_ports [] must deny, not allow, every port.
        Handler = server.Handler
        old = Handler.config
        Handler.config = {"allowed_test_targets": ["127.0.0.1"], "allowed_ports": []}
        try:
            code, body = self.get("/tcp?host=127.0.0.1&port=9000")
        finally:
            Handler.config = old
        self.assertEqual(code, 403)
        self.assertIn("allowed_ports", body["error"])


class PinnedHttpApi(unittest.TestCase):
    PINNED = "abcdefghijklmnopabcdefghijklmnop"
    OTHER = "ponmlkjihgfedcbaponmlkjihgfedcba"

    @classmethod
    def setUpClass(cls):
        cls.httpd = server.make_server(0, {"allowed_test_targets": ["127.0.0.1"], "allowed_ports": [9000],
                                           "allowed_extension_ids": [cls.PINNED]})
        cls.base = f"http://127.0.0.1:{cls.httpd.server_address[1]}"
        threading.Thread(target=cls.httpd.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown(); cls.httpd.server_close()

    def get(self, path, headers=None):
        req = urllib.request.Request(self.base + path, headers=headers or {})
        try:
            with urllib.request.urlopen(req, timeout=5) as r:
                return r.status, json.loads(r.read()), r.headers
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read()), e.headers

    def test_pinned_extension_accepted(self):
        code, body, headers = self.get("/health", {"Origin": f"chrome-extension://{self.PINNED}"})
        self.assertEqual(code, 200)
        self.assertIs(body["extensionPinned"], True)
        self.assertEqual(headers["Access-Control-Allow-Origin"], f"chrome-extension://{self.PINNED}")

    def test_other_extension_rejected(self):
        code, body, headers = self.get("/health", {"Origin": f"chrome-extension://{self.OTHER}"})
        self.assertEqual(code, 403)
        self.assertIn("not allowed", body["error"])
        self.assertIsNone(headers["Access-Control-Allow-Origin"])

    def test_no_origin_still_allowed_for_curl(self):
        code, _, _ = self.get("/health")
        self.assertEqual(code, 200)

    def test_web_origin_still_blocked(self):
        code, _, _ = self.get("/health", {"Origin": "https://evil.example"})
        self.assertEqual(code, 403)


class UnpinnedCors(unittest.TestCase):
    def test_unpinned_echoes_any_extension_origin(self):
        httpd = server.make_server(0, {"allowed_test_targets": ["127.0.0.1"], "allowed_ports": [9000],
                                       "allowed_extension_ids": []})
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
        try:
            req = urllib.request.Request(f"http://127.0.0.1:{httpd.server_address[1]}/health",
                                         headers={"Origin": "chrome-extension://anything"})
            with urllib.request.urlopen(req, timeout=5) as r:
                self.assertEqual(r.headers["Access-Control-Allow-Origin"], "chrome-extension://anything")
        finally:
            httpd.shutdown(); httpd.server_close()


if __name__ == "__main__":
    unittest.main()
