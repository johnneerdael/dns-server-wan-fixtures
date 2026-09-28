import importlib.util
from pathlib import Path
import socket
import struct
import sys
import os
import unittest


ROOT = Path(__file__).resolve().parents[1]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


zone = load("wan_zone", ROOT / "zone/generate.py")
proxy = load("wan_proxy", ROOT / "proxy/proxy.py")


def query(name):
    return struct.pack("!HHHHHH", 123, 0x100, 1, 0, 0, 0) + proxy.encode_name(name) + struct.pack("!HH", 1, 1)


class WanFixtures(unittest.TestCase):
    def test_domain_validation_and_complete_zone(self):
        content = zone.render("wan.example.test", "ns1.wan.example.test", "ns2.wan.example.test",
                              "203.0.113.10", "203.0.113.11", ROOT / "zone")
        self.assertIn("@ 60 IN NS ns1.wan.example.test.", content)
        self.assertIn("ns1.wan.example.test. 60 IN A 203.0.113.10", content)
        self.assertIn("*.near-max.wan.example.test. 0 IN TXT", content)
        self.assertIn("*.max-tcp.wan.example.test. 0 IN TXT", content)
        self.assertIn("*.openpgpkey.wan.example.test.", content)
        self.assertIn("*.large-multi-a.wan.example.test. 0 IN A 192.0.2.128", content)
        self.assertNotIn("dns.quality-assurance.fyi", content)
        with self.assertRaises(ValueError):
            zone.render("bad_name", "ns1.example.test", "ns2.example.test", "203.0.113.1", "203.0.113.2", ROOT / "zone")

    def test_faults_require_exact_scoped_name_and_explicit_source(self):
        domain = "wan.example.test"
        fault = query("a" * 32 + ".split-prefix." + domain)
        normal = query("a" * 32 + ".a." + domain)
        self.assertEqual(proxy.scenario(fault, domain), "split-prefix")
        self.assertEqual(proxy.scenario(normal, domain), "normal")
        self.assertEqual(proxy.scenario(query("split-prefix.example.org"), domain), "normal")
        nets = (proxy.ipaddress.ip_network("203.0.113.0/24"),)
        self.assertTrue(proxy.permitted("203.0.113.4", nets))
        self.assertFalse(proxy.permitted("198.51.100.4", nets))
        self.assertEqual(proxy.short_response(fault, 5)[3] & 15, 5)

    def test_split_prefix_has_identical_payload(self):
        left, right = socket.socketpair()
        try:
            proxy.send_frame(left, b"abcdefghijkl", "split-prefix", 0)
            self.assertEqual(right.recv(100), b"\x00\x0cabcdefghijkl")
        finally:
            left.close()
            right.close()

    @unittest.skipUnless(os.getenv("WAN_TEST_PORT"), "set WAN_TEST_PORT for a running Compose stack")
    def test_live_stack_large_responses_and_udp_truncation(self):
        port = int(os.environ["WAN_TEST_PORT"])
        domain = os.getenv("WAN_DOMAIN", "wan.quality-assurance.fyi")
        name = "0" * 32
        def exchange(label, qtype, tcp=True):
            q = struct.pack("!HHHHHH", 42, 256, 1, 0, 0, 1) + proxy.encode_name(f"{name}.{label}.{domain}") + struct.pack("!HH", qtype, 1)
            q += b"\0" + struct.pack("!HHIH", 41, 1232, 0, 0)
            if tcp:
                with socket.create_connection(("127.0.0.1", port), timeout=5) as sock:
                    sock.settimeout(5)
                    sock.sendall(struct.pack("!H", len(q)) + q)
                    n = struct.unpack("!H", proxy.read_exact(sock, 2))[0]
                    return proxy.read_exact(sock, n)
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.settimeout(5)
                sock.sendto(q, ("127.0.0.1", port))
                return sock.recv(65535)
        a = exchange("a", 1)
        self.assertEqual(struct.unpack_from("!H", a, 6)[0], 1)
        multi = exchange("large-multi-a", 1)
        self.assertEqual(struct.unpack_from("!H", multi, 6)[0], 128)
        near = exchange("near-max", 16)
        self.assertGreater(len(near), 60_000)
        maximum = exchange("max-tcp", 16)
        self.assertGreater(len(maximum), 65_000)
        self.assertLessEqual(len(maximum), 65_535)
        udp = exchange("max-tcp", 16, tcp=False)
        self.assertTrue(udp[2] & 2, "near-limit UDP answer must set TC")


if __name__ == "__main__":
    unittest.main()
