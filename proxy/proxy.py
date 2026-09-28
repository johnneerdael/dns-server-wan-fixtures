#!/usr/bin/env python3
"""Public authoritative DNS front end with source-gated transport faults."""

from __future__ import annotations

import argparse
import ipaddress
import os
import re
import signal
import socket
import socketserver
import struct
import threading
import time


MAX_DNS = 65535
FAULTS = frozenset({
    "split-prefix", "split-body", "bytewise", "request-split-prefix",
    "request-split-body", "request-bytewise", "persistent", "pipeline",
    "reordered", "coalesced", "close-before", "close-prefix",
    "close-body", "length-mismatch", "stall", "duplicate", "trailing",
    "mismatch-id", "mismatch-question", "zero-prefix", "partial-prefix",
    "partial-body", "delayed", "force-tcp",
})


def config() -> dict:
    domain = os.environ["WAN_DOMAIN"].lower().strip(".")
    if not re.fullmatch(r"[a-z0-9.-]{3,253}", domain) or ".." in domain:
        raise ValueError("WAN_DOMAIN must be a DNS name")
    networks = tuple(ipaddress.ip_network(part.strip(), strict=False) for part in
                     os.getenv("WAN_ALLOWED_FAULT_CLIENTS", "127.0.0.1/32,::1/128").split(","))
    if not networks or any(network.prefixlen == 0 for network in networks):
        raise ValueError("WAN_ALLOWED_FAULT_CLIENTS requires explicit IP/CIDR values; /0 is forbidden")
    return {
        "domain": domain,
        "networks": networks,
        "listen": os.getenv("LISTEN_HOST", "0.0.0.0"),
        "port": int(os.getenv("LISTEN_PORT", "5301")),
        "upstream": os.getenv("UPSTREAM_HOST", "authoritative"),
        "upstream_port": int(os.getenv("UPSTREAM_PORT", "5353")),
        "delay": min(max(int(os.getenv("WAN_FAULT_CHUNK_DELAY_MS", "50")), 0), 1000) / 1000,
        "stall": min(max(int(os.getenv("WAN_FAULT_STALL_SECONDS", "2")), 0), 10),
    }


def read_exact(sock: socket.socket, count: int) -> bytes:
    buf = bytearray()
    while len(buf) < count:
        part = sock.recv(count - len(buf))
        if not part:
            raise EOFError("incomplete DNS-over-TCP frame")
        buf.extend(part)
    return bytes(buf)


def read_frame(sock: socket.socket) -> bytes:
    size = struct.unpack("!H", read_exact(sock, 2))[0]
    if size < 12:
        raise ValueError("invalid DNS-over-TCP length")
    return read_exact(sock, size)


def encode_name(name: str) -> bytes:
    out = bytearray()
    for label in name.rstrip(".").split("."):
        raw = label.encode("ascii")
        out.append(len(raw))
        out.extend(raw)
    out.append(0)
    return bytes(out)


def question(query: bytes) -> tuple[str, int]:
    if len(query) < 12 or struct.unpack_from("!H", query, 4)[0] != 1:
        raise ValueError("exactly one question required")
    pos, labels = 12, []
    while True:
        if pos >= len(query):
            raise ValueError("truncated question")
        n = query[pos]
        pos += 1
        if n == 0:
            break
        if n & 0xc0 or n > 63 or pos + n > len(query):
            raise ValueError("invalid question name")
        labels.append(query[pos:pos + n].decode("ascii").lower())
        pos += n
    if pos + 4 > len(query):
        raise ValueError("truncated question type")
    return ".".join(labels), pos + 4


def scenario(query: bytes, domain: str) -> str:
    try:
        name, _ = question(query)
    except (ValueError, UnicodeDecodeError):
        return "normal"
    if not name.endswith("." + domain):
        return "normal"
    prefix = name[:-(len(domain) + 1)].split(".")
    if len(prefix) == 2 and re.fullmatch(r"[a-f0-9]{32}", prefix[0]) and prefix[1] in FAULTS:
        return prefix[1]
    return "normal"


def permitted(address: str, networks: tuple) -> bool:
    ip = ipaddress.ip_address(address)
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    return any(ip in network for network in networks)


def short_response(query: bytes, rcode: int, truncated: bool = False) -> bytes:
    _, end = question(query)
    ident, flags = struct.unpack_from("!HH", query)
    response_flags = 0x8400 | (flags & 0x0110) | (0x0200 if truncated else 0) | rcode
    opt = b""
    if struct.unpack_from("!H", query, 10)[0] == 1 and len(query) >= end + 11:
        if query[end] == 0 and struct.unpack_from("!H", query, end + 1)[0] == 41:
            length = struct.unpack_from("!H", query, end + 9)[0]
            if end + 11 + length == len(query):
                payload = struct.unpack_from("!H", query, end + 3)[0]
                opt = b"\0" + struct.pack("!HHIH", 41, max(512, min(payload, 1232)), 0, 0)
    return struct.pack("!HHHHHH", ident, response_flags, 1, 0, 0, int(bool(opt))) + query[12:end] + opt


def forward_tcp(cfg: dict, query: bytes) -> bytes:
    with socket.create_connection((cfg["upstream"], cfg["upstream_port"]), timeout=5) as upstream:
        upstream.settimeout(5)
        upstream.sendall(struct.pack("!H", len(query)) + query)
        response = read_frame(upstream)
    if response[:2] != query[:2]:
        raise ValueError("upstream transaction ID mismatch")
    return response


def forward_udp(cfg: dict, query: bytes) -> bytes:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as upstream:
        upstream.settimeout(5)
        upstream.sendto(query, (cfg["upstream"], cfg["upstream_port"]))
        response = upstream.recv(MAX_DNS)
    if response[:2] != query[:2]:
        raise ValueError("upstream transaction ID mismatch")
    return response


def send_frame(sock: socket.socket, response: bytes, mode: str, delay: float) -> None:
    if len(response) > MAX_DNS:
        raise ValueError("DNS reply exceeds two-byte TCP length")
    frame = struct.pack("!H", len(response)) + response
    if mode == "split-prefix":
        chunks = [frame[:1], frame[1:2], frame[2:]]
    elif mode == "split-body":
        chunks = [frame[:2]] + [frame[i:i + 64] for i in range(2, len(frame), 64)]
    elif mode == "bytewise":
        chunks = [frame[i:i + 1] for i in range(len(frame))]
    else:
        chunks = [frame]
    for index, chunk in enumerate(chunks):
        sock.sendall(chunk)
        if index + 1 < len(chunks):
            time.sleep(min(delay, 0.01) if mode == "bytewise" else delay)
    if mode == "duplicate":
        sock.sendall(frame)
    elif mode == "trailing":
        sock.sendall(b"\x00\x10garbage")


class BoundedMixIn(socketserver.ThreadingMixIn):
    daemon_threads = True
    request_queue_size = 128

    def process_request(self, request, client_address):
        if not self.gate.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            self.gate.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self.gate.release()


class TCPServer(BoundedMixIn, socketserver.TCPServer):
    allow_reuse_address = True


class UDPServer(BoundedMixIn, socketserver.UDPServer):
    allow_reuse_address = True


class TCPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        cfg = self.server.cfg
        self.request.settimeout(5)
        try:
            for _ in range(64):
                try:
                    query = read_frame(self.request)
                except EOFError:
                    return
                mode = scenario(query, cfg["domain"])
                if mode != "normal" and not permitted(self.client_address[0], cfg["networks"]):
                    send_frame(self.request, short_response(query, 5), "normal", 0)
                    return
                if mode in {"close-before", "stall"}:
                    if mode == "stall":
                        time.sleep(cfg["stall"])
                    return
                if mode in {"reordered", "coalesced"}:
                    queries = [query, read_frame(self.request), read_frame(self.request)]
                    responses = [forward_tcp(cfg, item) for item in queries]
                    if mode == "reordered":
                        responses.reverse()
                    self.request.sendall(b"".join(struct.pack("!H", len(item)) + item for item in responses))
                    return
                response = forward_tcp(cfg, query)
                if mode == "mismatch-id":
                    response = ((int.from_bytes(response[:2], "big") + 1) & 65535).to_bytes(2, "big") + response[2:]
                elif mode == "mismatch-question":
                    changed = bytearray(response)
                    if len(changed) > 13:
                        changed[13] = ord("z")
                    response = bytes(changed)
                frame = struct.pack("!H", len(response)) + response
                if mode == "close-prefix":
                    self.request.sendall(frame[:2])
                    return
                if mode in {"close-body", "length-mismatch"}:
                    declared = len(response) + (16 if mode == "length-mismatch" else 0)
                    self.request.sendall(struct.pack("!H", declared) + response[:len(response) // 2])
                    return
                send_frame(self.request, response, mode, cfg["delay"])
                if mode in {"duplicate", "trailing", "mismatch-id", "mismatch-question"}:
                    return
        except (OSError, ValueError, UnicodeDecodeError):
            return


class UDPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        query, sock = self.request
        cfg = self.server.cfg
        try:
            mode = scenario(query, cfg["domain"])
            if mode != "normal" and not permitted(self.client_address[0], cfg["networks"]):
                response = short_response(query, 5)
            elif mode in {"close-before", "stall"}:
                return
            elif mode == "force-tcp":
                response = short_response(query, 0, truncated=True)
            else:
                if mode == "delayed":
                    time.sleep(cfg["delay"])
                response = forward_udp(cfg, query)
            sock.sendto(response, self.client_address)
        except (OSError, ValueError, UnicodeDecodeError):
            return


def run(cfg: dict) -> None:
    gate = threading.BoundedSemaphore(64)
    servers = [TCPServer((cfg["listen"], cfg["port"]), TCPHandler),
               UDPServer((cfg["listen"], cfg["port"]), UDPHandler)]
    for server in servers:
        server.cfg = cfg
        server.gate = gate
    threads = [threading.Thread(target=server.serve_forever, daemon=True) for server in servers]
    for thread in threads:
        thread.start()
    stopped = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: stopped.set())
    signal.signal(signal.SIGINT, lambda *_: stopped.set())
    stopped.wait()
    for server in servers:
        server.shutdown()
        server.server_close()
    for thread in threads:
        thread.join(timeout=5)


def healthcheck(cfg: dict) -> None:
    query = struct.pack("!HHHHHH", 0x6313, 0x0100, 1, 0, 0, 0) + encode_name("a." + cfg["domain"]) + struct.pack("!HH", 1, 1)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(2)
        sock.sendto(query, ("127.0.0.1", cfg["port"]))
        response = sock.recv(4096)
    if response[:2] != query[:2] or len(response) < 12 or response[2] & 0x80 == 0:
        raise SystemExit("WAN DNS healthcheck failed")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--healthcheck", action="store_true")
    args = parser.parse_args()
    cfg = config()
    if args.healthcheck:
        healthcheck(cfg)
    else:
        run(cfg)


if __name__ == "__main__":
    main()
