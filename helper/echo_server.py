#!/usr/bin/env python3
"""Team-controlled TCP + UDP echo endpoint for Req2Route's live transport tests.

Run it on a laptop (or a second machine on the same LAN) and point the helper at it.
--loss and --delay inject real impairment on UDP, so students can compare a *Tested*
result with the matching *Simulated* one in the extension.

    python helper/echo_server.py --host 0.0.0.0 --port 9000 --loss 10 --delay 50
"""
from __future__ import annotations

import argparse
import random
import socketserver
import threading
import time


class TCPEcho(socketserver.BaseRequestHandler):
    def handle(self):
        while True:
            data = self.request.recv(65536)
            if not data:
                return
            self.request.sendall(data)


class UDPEcho(socketserver.BaseRequestHandler):
    loss_pct = 0.0
    delay_ms = 0.0

    def handle(self):
        data, sock = self.request
        if random.random() * 100 < self.loss_pct:
            return  # drop it: simulated loss on a real socket
        if self.delay_ms:
            time.sleep(self.delay_ms / 1000)
        sock.sendto(data, self.client_address)


class _TCP(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


class _UDP(socketserver.ThreadingUDPServer):
    allow_reuse_address = True
    daemon_threads = True


def start(host: str = "127.0.0.1", port: int = 9000, loss: float = 0.0, delay: float = 0.0):
    """Start both servers in background threads. Returns (tcp_server, udp_server)."""
    UDPEcho.loss_pct, UDPEcho.delay_ms = loss, delay
    tcp = _TCP((host, port), TCPEcho)
    udp = _UDP((host, tcp.server_address[1]), UDPEcho)  # same port number for both
    for srv in (tcp, udp):
        threading.Thread(target=srv.serve_forever, daemon=True).start()
    return tcp, udp


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=9000)
    ap.add_argument("--loss", type=float, default=0.0, help="UDP drop percentage (0-100)")
    ap.add_argument("--delay", type=float, default=0.0, help="extra UDP delay in ms")
    args = ap.parse_args()
    tcp, _ = start(args.host, args.port, args.loss, args.delay)
    print(f"Echo server on {args.host}:{tcp.server_address[1]} (TCP+UDP), loss={args.loss}%, delay={args.delay}ms")
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
