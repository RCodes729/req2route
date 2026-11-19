#!/usr/bin/env python3
"""Req2Route local helper.

A small localhost-only HTTP service that runs diagnostics a browser extension cannot:
DNS record lookups, TCP handshake timing, UDP echo/loss tests and reading the ARP cache.

Safety rules (keep these when extending the helper):
  * binds to 127.0.0.1 only;
  * accepts requests only from chrome-extension:// origins (or no Origin, e.g. curl);
    if allowed_extension_ids is set in config.json, only those extension IDs;
  * rejects browser no-cors / navigation requests (Sec-Fetch-Mode), which carry no Origin;
  * rejects requests whose Host header is not localhost (blocks DNS-rebinding);
  * TCP/UDP tests run only against targets listed in config.json.

Standard library only. `pip install dnspython` adds TTL, CNAME, MX and NS records.
"""
from __future__ import annotations

import argparse
import json
import os
import platform
import random
import re
import socket
import struct
import subprocess
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

DEFAULT_PORT = 8765
HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_CONFIG = {
    "allowed_test_targets": ["127.0.0.1", "localhost"],
    "allowed_ports": [9000],
    "allowed_extension_ids": [],  # empty = any chrome-extension:// origin; list IDs to pin the helper
    "dns_resolvers": {"Cloudflare": "1.1.1.1", "Google": "8.8.8.8", "Quad9": "9.9.9.9"},
}

HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}\.?$)[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
    r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*\.?$"
)


# --------------------------------------------------------------------------- config
def load_config(path: str | None = None) -> dict:
    cfg = dict(DEFAULT_CONFIG)
    path = path or os.path.join(HERE, "config.json")
    if os.path.exists(path):
        with open(path, encoding="utf-8") as fh:
            loaded = json.load(fh)
        if not isinstance(loaded, dict):
            raise ValueError(f"{path}: the config must be a JSON object")
        cfg.update(loaded)
    return validate_config(cfg)


EXTENSION_ID_RE = re.compile(r"^[a-p]{32}$")


def validate_config(cfg: dict) -> dict:
    """Fail closed on a malformed config: raise ValueError rather than guess what was meant."""
    ids = cfg.get("allowed_extension_ids")
    if not isinstance(ids, list):
        raise ValueError('config "allowed_extension_ids" must be a list of extension ID strings, e.g. ["abc..."]')
    clean_ids = []
    for ext_id in ids:
        if not isinstance(ext_id, str) or not EXTENSION_ID_RE.match(ext_id.lower()):
            raise ValueError(
                f'config "allowed_extension_ids" has an invalid entry {ext_id!r}: '
                "each ID must be 32 letters a-p (copy it from chrome://extensions)"
            )
        clean_ids.append(ext_id.lower())
    cfg["allowed_extension_ids"] = clean_ids

    ports = cfg.get("allowed_ports")
    if not isinstance(ports, list) or not all(isinstance(p, int) and not isinstance(p, bool) for p in ports):
        raise ValueError('config "allowed_ports" must be a list of integers, e.g. [9000]')

    targets = cfg.get("allowed_test_targets")
    if not isinstance(targets, list) or not all(isinstance(t, str) for t in targets):
        raise ValueError('config "allowed_test_targets" must be a list of strings, e.g. ["127.0.0.1"]')
    return cfg


def check_target(cfg: dict, host: str, port: int) -> None:
    if host not in cfg["allowed_test_targets"]:
        raise PermissionError(
            f"{host} is not an approved test target. Add it to helper/config.json "
            "only if your team controls it."
        )
    # A missing or empty allowed_ports means "no port is allowed", never "every port".
    if port not in (cfg.get("allowed_ports") or []):
        raise PermissionError(f"Port {port} is not in allowed_ports in helper/config.json")


def valid_hostname(name: str) -> bool:
    return bool(name) and bool(HOSTNAME_RE.match(name))


# --------------------------------------------------------------------------- DNS
def dns_lookup(name: str) -> dict:
    if not valid_hostname(name):
        raise ValueError("Invalid hostname")
    started = time.perf_counter()
    records: list[dict] = []
    try:
        import dns.resolver  # type: ignore  # optional dependency

        method = "dnspython"
        resolver = dns.resolver.Resolver()
        resolver.lifetime = 2.0  # per query: keeps all five lookups well under the extension's 15 s timeout
        address_ms: list[float] = []
        for rtype in ("A", "AAAA", "CNAME", "MX", "NS"):
            q_started = time.perf_counter()
            try:
                answer = resolver.resolve(name, rtype, raise_on_no_answer=False)
            except dns.resolver.NXDOMAIN as exc:
                raise LookupError(f"{name} does not exist (NXDOMAIN)") from exc
            except (dns.resolver.NoNameservers, dns.resolver.LifetimeTimeout):
                answer = None
            if rtype in ("A", "AAAA"):
                address_ms.append((time.perf_counter() - q_started) * 1000)
            if answer is None or answer.rrset is None:
                continue
            for r in answer:
                records.append({"type": rtype, "value": r.to_text(), "ttl": answer.rrset.ttl})
        servers = list(resolver.nameservers)
        # Browsers ask for A and AAAA in parallel, so the slower of the two is the figure
        # comparable with the browser's own DNS time. CNAME/MX/NS are extra lessons, not timed.
        lookup_ms = max(address_ms)
    except ImportError:
        method = "system resolver (getaddrinfo); install dnspython for TTL/CNAME/MX/NS"
        servers = []
        try:
            infos = socket.getaddrinfo(name, None, proto=socket.IPPROTO_TCP)
        except socket.gaierror as exc:
            raise LookupError(f"Could not resolve {name}: {exc}") from exc
        lookup_ms = (time.perf_counter() - started) * 1000
        seen = set()
        for family, _, _, _, sockaddr in infos:
            ip = sockaddr[0]
            if ip in seen:
                continue
            seen.add(ip)
            records.append({"type": "A" if family == socket.AF_INET else "AAAA", "value": ip, "ttl": None})
    return {
        "name": name,
        "method": method,
        "resolvers": servers,
        "timeMs": round(lookup_ms, 2),
        "totalMs": round((time.perf_counter() - started) * 1000, 2),
        "timeNote": "timeMs is the address (A/AAAA) lookup only, comparable with the browser's DNS time; "
                    "totalMs includes every record type queried.",
        "records": records,
    }


# --------------------------------------------------------------------------- raw DNS over UDP/53
# Hand-built DNS messages (RFC 1035): no dependencies, and the packet itself is the lesson.
QTYPES = {"A": 1, "NS": 2, "CNAME": 5, "MX": 15, "AAAA": 28}
QTYPE_NAMES = {v: k for k, v in QTYPES.items()}
RCODES = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 4: "NOTIMP", 5: "REFUSED"}


def build_dns_query(name: str, qtype: str = "A", txid: int | None = None) -> tuple[int, bytes]:
    if not valid_hostname(name):
        raise ValueError("Invalid hostname")
    txid = random.randint(0, 0xFFFF) if txid is None else txid
    header = struct.pack("!HHHHHH", txid, 0x0100, 1, 0, 0, 0)  # flags: RD=1 (recursion desired)
    qname = b"".join(bytes([len(label)]) + label.encode("ascii") for label in name.rstrip(".").split(".")) + b"\x00"
    return txid, header + qname + struct.pack("!HH", QTYPES[qtype], 1)  # class IN


def _read_name(msg: bytes, offset: int) -> tuple[str, int]:
    labels, end, jumps = [], None, 0
    while True:
        if offset >= len(msg):
            raise ValueError("Truncated DNS name")
        length = msg[offset]
        if length & 0xC0 == 0xC0:  # compression pointer
            if end is None:
                end = offset + 2
            offset = ((length & 0x3F) << 8) | msg[offset + 1]
            jumps += 1
            if jumps > 20:
                raise ValueError("DNS compression loop")
            continue
        if length == 0:
            offset += 1
            break
        labels.append(msg[offset + 1:offset + 1 + length].decode("ascii", "replace"))
        offset += 1 + length
    return ".".join(labels), (end if end is not None else offset)


def parse_dns_response(msg: bytes) -> dict:
    """Parse a DNS reply. Any malformed or truncated packet raises ValueError."""
    try:
        return _parse_dns_response(msg)
    except (struct.error, IndexError) as exc:
        raise ValueError(f"Malformed DNS response ({exc})") from exc


def _parse_dns_response(msg: bytes) -> dict:
    if len(msg) < 12:
        raise ValueError("DNS response too short")
    txid, flags, qd, an, _ns, _ar = struct.unpack("!HHHHHH", msg[:12])
    off = 12
    for _ in range(qd):
        _, off = _read_name(msg, off)
        off += 4
    answers = []
    for _ in range(an):
        name, off = _read_name(msg, off)
        rtype, _rclass, ttl, rdlen = struct.unpack("!HHIH", msg[off:off + 10])
        off += 10
        rdata = msg[off:off + rdlen]
        if rtype == 1:
            value = socket.inet_ntop(socket.AF_INET, rdata)
        elif rtype == 28:
            value = socket.inet_ntop(socket.AF_INET6, rdata)
        elif rtype in (2, 5):
            value, _ = _read_name(msg, off)
        elif rtype == 15:
            pref = struct.unpack("!H", rdata[:2])[0]
            host, _ = _read_name(msg, off + 2)
            value = f"{pref} {host}"
        else:
            value = rdata.hex()
        answers.append({"name": name, "type": QTYPE_NAMES.get(rtype, str(rtype)), "ttl": ttl, "value": value})
        off += rdlen
    return {
        "id": txid,
        "flags": {
            "qr": bool(flags >> 15 & 1), "aa": bool(flags >> 10 & 1), "tc": bool(flags >> 9 & 1),
            "rd": bool(flags >> 8 & 1), "ra": bool(flags >> 7 & 1),
        },
        "rcode": RCODES.get(flags & 0xF, str(flags & 0xF)),
        "answers": answers,
    }


def raw_dns_query(name: str, server: str, qtype: str = "A", timeout: float = 2.0) -> dict:
    host, _, port = server.partition(":")
    port = int(port or 53)
    txid, packet = build_dns_query(name, qtype)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.settimeout(timeout)
        started = time.perf_counter()
        s.sendto(packet, (host, port))
        while True:
            data, _ = s.recvfrom(4096)
            if len(data) >= 2 and struct.unpack("!H", data[:2])[0] == txid:
                break  # ignore stray datagrams with the wrong transaction ID
        elapsed = (time.perf_counter() - started) * 1000
    result = parse_dns_response(data)
    result.update({"server": server, "qtype": qtype, "transport": "UDP/53",
                   "timeMs": round(elapsed, 2), "bytesSent": len(packet), "bytesReceived": len(data)})
    return result


def compare_resolvers(cfg: dict, name: str) -> dict:
    if not valid_hostname(name):
        raise ValueError("Invalid hostname")
    results = []
    started = time.perf_counter()
    try:
        ips = sorted({info[4][0] for info in socket.getaddrinfo(name, None, proto=socket.IPPROTO_TCP)})
        results.append({"resolver": "System (your OS / router)", "server": "system", "ok": True,
                        "timeMs": round((time.perf_counter() - started) * 1000, 2), "addresses": ips,
                        "note": "Uses the OS cache, so a repeat lookup is often ~0 ms"})
    except OSError as exc:
        results.append({"resolver": "System (your OS / router)", "server": "system", "ok": False, "error": str(exc)})
    for label, server in cfg.get("dns_resolvers", {}).items():
        try:
            r = raw_dns_query(name, server)
            results.append({"resolver": label, "server": server, "ok": True, "timeMs": r["timeMs"],
                            "rcode": r["rcode"], "bytesSent": r["bytesSent"], "bytesReceived": r["bytesReceived"],
                            "addresses": [a["value"] for a in r["answers"] if a["type"] in ("A", "AAAA")],
                            "answers": r["answers"]})
        except (OSError, ValueError) as exc:
            results.append({"resolver": label, "server": server, "ok": False, "error": str(exc) or type(exc).__name__})
    ok = [r for r in results if r["ok"]]
    answered = [r for r in ok if r.get("addresses")]
    fastest = min(answered, key=lambda r: r["timeMs"])["resolver"] if answered else None
    return {"name": name, "fastest": fastest, "results": results,
            "note": "Different resolvers may return different IPs for CDN-hosted sites; TTLs show how long each answer may be cached."}


# --------------------------------------------------------------------------- TCP / UDP
def tcp_connect_test(cfg: dict, host: str, port: int, attempts: int = 3, timeout: float = 3.0) -> dict:
    check_target(cfg, host, port)
    samples = []
    for _ in range(attempts):
        started = time.perf_counter()
        try:
            with socket.create_connection((host, port), timeout=timeout) as s:
                elapsed = (time.perf_counter() - started) * 1000
                local, remote = s.getsockname(), s.getpeername()
                samples.append({
                    "ok": True,
                    "handshakeMs": round(elapsed, 3),
                    "local": f"{local[0]}:{local[1]}",
                    "remote": f"{remote[0]}:{remote[1]}",
                })
        except OSError as exc:
            samples.append({"ok": False, "error": str(exc)})
    ok = [s["handshakeMs"] for s in samples if s["ok"]]
    return {
        "test": "tcp-connect",
        "target": f"{host}:{port}",
        "attempts": attempts,
        "succeeded": len(ok),
        "avgHandshakeMs": round(sum(ok) / len(ok), 3) if ok else None,
        "note": "Each sample is a full 3-way handshake; note the new ephemeral local port every time.",
        "samples": samples,
    }


def udp_echo_test(cfg: dict, host: str, port: int, count: int = 10, timeout: float = 1.0) -> dict:
    check_target(cfg, host, port)
    count = max(1, min(int(count), 100))
    rtts: list[float | None] = []
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.settimeout(timeout)
        for seq in range(count):
            payload = f"R2R {seq} ".encode().ljust(32, b".")
            started = time.perf_counter()
            s.sendto(payload, (host, port))
            got = None
            deadline = started + timeout
            while time.perf_counter() < deadline:
                try:
                    data, _ = s.recvfrom(2048)
                except socket.timeout:
                    break
                except OSError:  # e.g. ICMP port unreachable on Windows
                    break
                if data == payload:
                    got = (time.perf_counter() - started) * 1000
                    break
            rtts.append(round(got, 3) if got is not None else None)
    received = [r for r in rtts if r is not None]
    return {
        "test": "udp-echo",
        "target": f"{host}:{port}",
        "sent": count,
        "received": len(received),
        "lossPct": round(100 * (count - len(received)) / count, 1),
        "avgRttMs": round(sum(received) / len(received), 3) if received else None,
        "note": "UDP has no handshake or retransmission: lost datagrams simply never come back.",
        "rttsMs": rtts,
    }


# --------------------------------------------------------------------------- ARP
_WIN_IFACE = re.compile(r"^Interface:\s*([\d.]+)")
_WIN_ROW = re.compile(r"^\s*(\d{1,3}(?:\.\d{1,3}){3})\s+([0-9a-fA-F]{2}(?:-[0-9a-fA-F]{2}){5})\s+(\w+)")
_UNIX_ROW = re.compile(r"\((\d{1,3}(?:\.\d{1,3}){3})\)\s+at\s+(\S+)(?:\s+\[\w+\])?\s+on\s+(\S+)")


def normalize_mac(mac: str) -> str:
    return ":".join(p.zfill(2) for p in re.split(r"[:-]", mac)).lower()


def mac_note(mac: str) -> str | None:
    if mac == "ff:ff:ff:ff:ff:ff":
        return "broadcast"
    if mac.startswith("01:00:5e"):
        return "IPv4 multicast"
    if int(mac.split(":")[0], 16) & 0x02:
        return "locally administered (often randomised)"
    return None


def parse_arp(text: str) -> list[dict]:
    """Parse `arp -a` output from Windows, Linux or macOS."""
    entries = []
    iface = None
    for line in text.splitlines():
        m = _WIN_IFACE.match(line.strip())
        if m:
            iface = m.group(1)
            continue
        m = _WIN_ROW.match(line)
        if m:
            mac = normalize_mac(m.group(2))
            entries.append({"interface": iface, "ip": m.group(1), "mac": mac, "type": m.group(3).lower(), "note": mac_note(mac)})
            continue
        m = _UNIX_ROW.search(line)
        if m and re.fullmatch(r"[0-9a-fA-F]{1,2}(?::[0-9a-fA-F]{1,2}){5}", m.group(2)):
            mac = normalize_mac(m.group(2))
            kind = "static" if "permanent" in line or "PERM" in line else "dynamic"
            entries.append({"interface": m.group(3), "ip": m.group(1), "mac": mac, "type": kind, "note": mac_note(mac)})
    return entries


def parse_proc_net_arp(text: str) -> list[dict]:
    """Linux fallback: /proc/net/arp."""
    entries = []
    for line in text.splitlines()[1:]:
        parts = line.split()
        if len(parts) >= 6 and parts[3] != "00:00:00:00:00:00":
            mac = normalize_mac(parts[3])
            entries.append({"interface": parts[5], "ip": parts[0], "mac": mac,
                            "type": "static" if parts[2] == "0x6" else "dynamic", "note": mac_note(mac)})
    return entries


def read_arp() -> dict:
    try:
        out = subprocess.run(["arp", "-a"], capture_output=True, text=True, timeout=5).stdout
        entries = parse_arp(out)
        source = "arp -a"
    except (FileNotFoundError, subprocess.TimeoutExpired):
        if not os.path.exists("/proc/net/arp"):
            raise RuntimeError("No arp command available on this system")
        with open("/proc/net/arp", encoding="utf-8") as fh:
            entries = parse_proc_net_arp(fh.read())
        source = "/proc/net/arp"
    return {"source": source, "os": platform.system(), "count": len(entries), "entries": entries}


# --------------------------------------------------------------------------- HTTP
class Handler(BaseHTTPRequestHandler):
    server_version = "Req2RouteHelper/1.0"
    config: dict = DEFAULT_CONFIG

    def log_message(self, fmt, *args):  # quieter console
        print(f"[helper] {self.address_string()} {fmt % args}")

    def _send(self, code: int, obj: dict) -> None:
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        origin = self.headers.get("Origin", "")
        if self._origin_ok(origin):
            self.send_header("Access-Control-Allow-Origin", origin)
        self.end_headers()
        self.wfile.write(body)

    def _origin_ok(self, origin: str) -> bool:
        """True for a chrome-extension:// origin that passes the optional ID pin."""
        prefix = "chrome-extension://"
        if not origin.startswith(prefix):
            return False
        pinned = self.config.get("allowed_extension_ids") or []
        return not pinned or origin[len(prefix):] in pinned

    def _allowed(self) -> str | None:
        origin = self.headers.get("Origin")
        if origin and not origin.startswith("chrome-extension://"):
            return "Origin not allowed: only the Req2Route extension may call the helper"
        if origin and not self._origin_ok(origin):
            return "Extension not allowed: its ID is not in allowed_extension_ids in helper/config.json"
        # A web page can reach us without an Origin header via <img>/<script>/<iframe> or a
        # navigation. Browsers label those with Sec-Fetch-Mode; the extension's fetch() is "cors".
        if (self.headers.get("Sec-Fetch-Mode") or "").lower() in ("no-cors", "navigate", "nested-navigate"):
            return "Browser request not allowed: use the Req2Route extension (or curl) to call the helper"
        host = (self.headers.get("Host") or "").rsplit(":", 1)[0].strip("[]")
        if host not in ("127.0.0.1", "localhost", "::1"):
            return "Host header not allowed"
        return None

    def do_GET(self):  # noqa: N802
        problem = self._allowed()
        if problem:
            return self._send(403, {"error": problem})
        url = urlparse(self.path)
        q = {k: v[0] for k, v in parse_qs(url.query).items()}
        try:
            if url.path == "/health":
                try:
                    import dns.resolver  # noqa: F401
                    has_dnspython = True
                except ImportError:
                    has_dnspython = False
                return self._send(200, {"ok": True, "version": "1.0.0", "os": platform.system(),
                                        "dnspython": has_dnspython,
                                        "allowedTargets": self.config["allowed_test_targets"],
                                        "allowedPorts": self.config.get("allowed_ports") or [],
                                        "extensionPinned": bool(self.config.get("allowed_extension_ids"))})
            if url.path == "/dns":
                return self._send(200, dns_lookup(q.get("name", "")))
            if url.path == "/resolvers":
                return self._send(200, compare_resolvers(self.config, q.get("name", "")))
            if url.path == "/tcp":
                return self._send(200, tcp_connect_test(self.config, q.get("host", ""), int(q.get("port", 0))))
            if url.path == "/udp":
                return self._send(200, udp_echo_test(self.config, q.get("host", ""), int(q.get("port", 0)), int(q.get("count", 10))))
            if url.path == "/arp":
                return self._send(200, read_arp())
            return self._send(404, {"error": f"Unknown endpoint {url.path}"})
        except PermissionError as exc:
            return self._send(403, {"error": str(exc)})
        except (ValueError, LookupError) as exc:
            return self._send(400, {"error": str(exc)})
        except Exception as exc:  # report, don't crash the server
            return self._send(500, {"error": f"{type(exc).__name__}: {exc}"})


def make_server(port: int = DEFAULT_PORT, config: dict | None = None) -> ThreadingHTTPServer:
    Handler.config = config or load_config()
    return ThreadingHTTPServer(("127.0.0.1", port), Handler)


def main() -> None:
    ap = argparse.ArgumentParser(description="Req2Route localhost diagnostics helper")
    ap.add_argument("--port", type=int, default=DEFAULT_PORT)
    ap.add_argument("--config", help="path to config.json")
    args = ap.parse_args()
    try:
        config = load_config(args.config)
    except (ValueError, OSError) as exc:  # ValueError includes json.JSONDecodeError
        raise SystemExit(f"Req2Route helper: bad config, not starting. {exc}")
    server = make_server(args.port, config)
    print(f"Req2Route helper listening on http://127.0.0.1:{args.port}  (Ctrl+C to stop)")
    print(f"Approved test targets: {server.RequestHandlerClass.config['allowed_test_targets']}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
