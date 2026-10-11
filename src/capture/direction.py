"""Direction filtering for unidirectional (data-diode) deployments."""
from __future__ import annotations

import ipaddress
from typing import Optional

from src.capture.packet_info import PacketInfo


class DirectionFilter:
    """Keeps only packets flowing in the configured one-way direction.

    * ``outbound`` — keep packets whose SOURCE lies inside the trusted
      (protected) networks: what leaves the enclave through the diode.
      This is the exfiltration / malware-beacon view.
    * ``inbound``  — keep packets whose DESTINATION is a monitored host:
      what arrives on the receiving side of the diode.
    * ``any``       — no direction filtering.
    """

    def __init__(self, mode: str = "any",
                 trusted_cidrs: Optional[list[str]] = None,
                 monitored_hosts: Optional[list[str]] = None):
        if mode not in ("outbound", "inbound", "any"):
            raise ValueError(f"unknown direction mode: {mode!r}")
        self.mode = mode
        self.networks = [ipaddress.ip_network(c, strict=False)
                          for c in (trusted_cidrs or [])]
        self.hosts = [ipaddress.ip_address(h) for h in (monitored_hosts or [])]

    def allows(self, pkt: PacketInfo) -> bool:
        if self.mode == "any":
            return True
        try:
            addr_src = ipaddress.ip_address(pkt.src)
            addr_dst = ipaddress.ip_address(pkt.dst)
        except ValueError:
            return False
        if self.mode == "outbound":
            return any(addr_src in net for net in self.networks)
        return any(addr == addr_dst for addr in self.hosts)

    def build_bpf(self) -> Optional[str]:
        """Best-effort BPF pre-filter matching the configured direction.

        Scapy still applies the in-process DirectionFilter afterwards, so this
        is purely a performance optimisation. Returns None when the mode needs
        no filtering (then the caller may fall back to "ip").
        """
        if self.mode == "outbound" and self.networks:
            terms = []
            for net in self.networks:
                terms.append(f"src net {net}")
                if net.prefixlen != 32 and net.version == 4:
                    terms.append(f"src net {net.network_address}")
            # keep only well-formed terms (dedup)
            seen, unique = set(), []
            for t in terms:
                if t not in seen:
                    seen.add(t)
                    unique.append(t)
            return "ip and (" + " or ".join(unique) + ")"
        if self.mode == "inbound" and self.hosts:
            return "ip and (" + " or ".join(f"dst host {h}" for h in self.hosts) + ")"
        return None

    def describe(self) -> str:
        if self.mode == "outbound":
            nets = ", ".join(str(n) for n in self.networks) or "(none)"
            return f"outbound (one-way from trusted nets: {nets})"
        if self.mode == "inbound":
            hosts = ", ".join(str(h) for h in self.hosts) or "(none)"
            return f"inbound (one-way to monitored hosts: {hosts})"
        return "any (no direction filtering)"
