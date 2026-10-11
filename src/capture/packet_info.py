"""Per-packet metadata extracted from Scapy packets.

Everything the flow accumulator needs is pulled out here, so the rest of the
pipeline is Scapy-independent (and unit-testable without a NIC).
"""
from __future__ import annotations

from dataclasses import dataclass

IPPROTO_TCP = 6
IPPROTO_UDP = 17


@dataclass(slots=True)
class PacketInfo:
    """One IP packet, as seen in a single direction (diode semantics)."""
    ts_us: int            # timestamp in microseconds
    src: str
    dst: str
    sport: int
    dport: int
    proto: int            # IP protocol number
    ip_total_len: int     # total length incl. headers (IP.len)
    ip_hdr_len: int       # IP header bytes
    transport_hdr_len: int
    payload_len: int      # bytes above L4 header
    tcp_flags: int        # 0 for non-TCP
    tcp_win: int          # 0 for non-TCP

    @property
    def header_bytes(self) -> int:
        return self.ip_hdr_len + self.transport_hdr_len

    @staticmethod
    def from_scapy(pkt) -> "PacketInfo | None":
        """Build a PacketInfo from a Scapy packet; None for non-IPv4 packets."""
        if not pkt.haslayer("IP"):
            return None
        ip = pkt["IP"]

        proto = int(ip.proto)
        sport = dport = 0
        tcp_flags = tcp_win = 0
        transport_hdr = 0

        if proto == IPPROTO_TCP and pkt.haslayer("TCP"):
            tcp = pkt["TCP"]
            sport, dport = int(tcp.sport), int(tcp.dport)
            transport_hdr = int(tcp.dataofs) * 4
            try:
                tcp_flags = int(tcp.flags)
            except (TypeError, ValueError):
                tcp_flags = 0
            tcp_win = int(tcp.window)
        elif proto == IPPROTO_UDP and pkt.haslayer("UDP"):
            udp = pkt["UDP"]
            sport, dport = int(udp.sport), int(udp.dport)
            transport_hdr = 8

        ip_hdr = int(ip.ihl) * 4
        total_len = int(ip.len)
        # Some capture setups produce malformed ip.len (e.g. offloading);
        # fall back to the captured frame length when it is unusable.
        if total_len < ip_hdr + transport_hdr:
            total_len = max(len(pkt), ip_hdr + transport_hdr)

        payload_len = max(total_len - ip_hdr - transport_hdr, 0)

        return PacketInfo(
            ts_us=int(float(pkt.time) * 1_000_000),
            src=str(ip.src),
            dst=str(ip.dst),
            sport=sport,
            dport=dport,
            proto=proto,
            ip_total_len=total_len,
            ip_hdr_len=ip_hdr,
            transport_hdr_len=transport_hdr,
            payload_len=payload_len,
            tcp_flags=tcp_flags,
            tcp_win=tcp_win,
        )
