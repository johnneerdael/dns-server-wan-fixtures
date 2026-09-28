#!/usr/bin/env python3
"""Render one authoritative WAN test zone from validated environment values."""

from __future__ import annotations

import ipaddress
import os
from pathlib import Path
import re


SOURCE_DOMAIN = "dns.quality-assurance.fyi."
TEMPLATES = ("base.zone.in", "additional.zone.in", "security.zone.in")
FAULT_KEYS = (
    "split-prefix", "split-body", "bytewise", "request-split-prefix",
    "request-split-body", "request-bytewise", "persistent", "pipeline",
    "reordered", "coalesced", "close-before", "close-prefix",
    "close-body", "length-mismatch", "stall", "duplicate", "trailing",
    "mismatch-id", "mismatch-question", "zero-prefix", "partial-prefix",
    "partial-body", "delayed", "force-tcp",
)


def dns_name(value: str, label: str) -> str:
    value = value.lower().rstrip(".")
    parts = value.split(".")
    if len(value) > 253 or len(parts) < 2 or any(
        not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", part)
        for part in parts
    ):
        raise ValueError(f"{label} must be a valid DNS hostname")
    return value + "."


def render(domain: str, ns1: str, ns2: str, ip1: str, ip2: str, source: Path,
           serial: int = 2026092801) -> str:
    zone = dns_name(domain, "WAN_DOMAIN")
    nameservers = [dns_name(ns1, "WAN_NS1"), dns_name(ns2, "WAN_NS2")]
    if nameservers[0] == nameservers[1]:
        raise ValueError("WAN_NS1 and WAN_NS2 must have different names")
    addresses = [str(ipaddress.IPv4Address(ip1)), str(ipaddress.IPv4Address(ip2))]
    if not 1 <= serial <= 0xffffffff:
        raise ValueError("WAN_ZONE_SERIAL must be a 32-bit positive integer")
    lines = [
        f"$ORIGIN {zone}", "$TTL 60",
        f"@ 60 IN SOA {nameservers[0]} hostmaster.{zone} {serial} 60 60 3600 0",
        *(f"@ 60 IN NS {name}" for name in nameservers),
    ]
    for name, address in zip(nameservers, addresses):
        if name.endswith(zone):
            lines.append(f"{name} 60 IN A {address}")
    for filename in TEMPLATES:
        for raw in (source / filename).read_text().splitlines():
            line = raw.strip()
            if not line or line.startswith((";", "$", "@ IN SOA", "@ IN NS")):
                continue
            line = line.replace(SOURCE_DOMAIN, zone)
            line = line.replace("ns1.example.invalid.", nameservers[0])
            line = line.replace("ns2.example.invalid.", nameservers[1])
            lines.append(line)
    lines.extend([
        f"*.large-multi-a.{zone} 0 IN A 192.0.2.{n}" for n in range(1, 129)
    ])
    lines.extend([
        f"*.large-multi-aaaa.{zone} 0 IN AAAA 2001:db8::{n:x}" for n in range(1, 129)
    ])
    for number in range(1, 65):
        lines.append(f"*.large-srv.{zone} 0 IN SRV 10 {number} 8443 service.{zone}")
    for label, count, width in (("near-max", 240, 250), ("max-tcp", 254, 255)):
        strings = " ".join('"' + "x" * width + '"' for _ in range(count))
        lines.append(f"*.{label}.{zone} 0 IN TXT {strings}")
    for key in FAULT_KEYS:
        lines.append(f"*.{key}.{zone} 0 IN A 192.0.2.10")
    return "\n".join(lines) + "\n"


def main() -> None:
    domain = os.environ["WAN_DOMAIN"]
    ns1 = os.environ["WAN_NS1"]
    ns2 = os.environ["WAN_NS2"]
    ip1 = os.environ["WAN_PUBLIC_IPV4_1"]
    ip2 = os.environ["WAN_PUBLIC_IPV4_2"]
    output = Path(os.environ.get("ZONE_OUTPUT", "/var/cache/bind/zone.db"))
    serial = int(os.environ.get("WAN_ZONE_SERIAL", "2026092801"))
    output.write_text(render(domain, ns1, ns2, ip1, ip2, Path(__file__).parent, serial))


if __name__ == "__main__":
    main()
