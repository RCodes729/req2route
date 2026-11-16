import os
import socket
import struct
import sys
import threading
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import server  # noqa: E402


def encode_name(name):
    return b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\x00"


def fake_answer(query: bytes) -> bytes:
    """Reply to any A query: www.example.com CNAME edge.example.net, edge A 93.184.215.14 (uses compression)."""
    txid = query[:2]
    question = query[12:]
    header = txid + struct.pack("!HHHHH", 0x8180, 1, 2, 0, 0)  # QR, RD, RA, NOERROR
    cname_rdata = encode_name("edge.example.net")
    ans1 = b"\xc0\x0c" + struct.pack("!HHIH", 5, 1, 300, len(cname_rdata)) + cname_rdata
    cname_offset = 12 + len(question) + 12  # where cname_rdata starts
    ans2 = struct.pack("!H", 0xC000 | cname_offset) + struct.pack("!HHIH", 1, 1, 60, 4) + socket.inet_aton("93.184.215.14")
    return header + question + ans1 + ans2


class FakeDns(threading.Thread):
    def __init__(self):
        super().__init__(daemon=True)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 0))
        self.port = self.sock.getsockname()[1]

    def run(self):
        while True:
            try:
                data, addr = self.sock.recvfrom(512)
            except OSError:
                return
            self.sock.sendto(b"\x00\x00junk", addr)  # stray datagram with the wrong ID must be ignored
            self.sock.sendto(fake_answer(data), addr)


class DnsWire(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fake = FakeDns()
        cls.fake.start()

    @classmethod
    def tearDownClass(cls):
        cls.fake.sock.close()

    def test_build_query_bytes(self):
        txid, pkt = server.build_dns_query("example.com", "A", txid=0x1234)
        self.assertEqual(pkt[:12], bytes.fromhex("123401000001000000000000"))
        self.assertEqual(pkt[12:], b"\x07example\x03com\x00\x00\x01\x00\x01")
        with self.assertRaises(ValueError):
            server.build_dns_query("bad name")

    def test_parse_with_compression(self):
        _, q = server.build_dns_query("www.example.com", txid=7)
        r = server.parse_dns_response(fake_answer(q))
        self.assertEqual(r["id"], 7)
        self.assertEqual(r["rcode"], "NOERROR")
        self.assertTrue(r["flags"]["ra"])
        self.assertEqual(r["answers"][0], {"name": "www.example.com", "type": "CNAME", "ttl": 300, "value": "edge.example.net"})
        self.assertEqual(r["answers"][1], {"name": "edge.example.net", "type": "A", "ttl": 60, "value": "93.184.215.14"})

    def test_raw_query_over_udp(self):
        r = server.raw_dns_query("www.example.com", f"127.0.0.1:{self.fake.port}")
        self.assertEqual(r["answers"][1]["value"], "93.184.215.14")
        self.assertEqual(r["transport"], "UDP/53")
        self.assertEqual(r["bytesSent"], 33)

    def test_compare_resolvers(self):
        cfg = {"dns_resolvers": {"Fake": f"127.0.0.1:{self.fake.port}", "Dead": "127.0.0.1:9"}}
        r = server.compare_resolvers(cfg, "localhost")
        by = {x["resolver"]: x for x in r["results"]}
        self.assertTrue(by["Fake"]["ok"])
        self.assertIn("93.184.215.14", by["Fake"]["addresses"])
        self.assertFalse(by["Dead"]["ok"])
        self.assertIsNotNone(r["fastest"])


if __name__ == "__main__":
    unittest.main()
