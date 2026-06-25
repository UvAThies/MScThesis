#!/usr/bin/env python3
import ipaddress
import sys
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path

from scapy.all import IP, PcapReader

# -------------------------------------------------------------------
# Period boundaries for the two experiments
# -------------------------------------------------------------------
EXP1_START = datetime(2026, 5, 19, 0, 0)
EXP1_END = datetime(2026, 5, 20, 23, 59, 59)

EXP2_START = datetime(2026, 6, 2, 0, 0)
EXP2_END = datetime(2026, 6, 3, 23, 59, 59)

IGNORE = {
    "145.100.108.82",
    "145.100.108.81",
    "102.207.2.160",
    "145.100.108.85",
    "145.100.108.84",
}

# How many top IPs per TTL to show
TOP_N_IPS_PER_TTL = 5


def is_local_like(ip_str: str) -> bool:
    """
    Return True if ip_str is something we consider 'local host stuff':
    - loopback (127.0.0.0/8)
    - private RFC1918
    - link-local
    - unspecified or multicast, etc.
    """
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        # malformed IP; treat as local-ish so it doesn't pollute stats
        return True

    if ip.is_loopback:
        return True
    if ip.is_private:
        return True
    if ip.is_link_local:
        return True
    if ip.is_multicast:
        return True
    if ip.is_unspecified:
        return True

    return False


def print_ttl_with_top_ips(
    period_name: str,
    ttl_counter: Counter[int],
    ttl_to_ip_counter: dict[int, Counter[str]],
    top_n: int = TOP_N_IPS_PER_TTL,
) -> None:
    """
    For each TTL in this period, print:
      - total packet count and share of all packets
      - top N source IPs that used this TTL (and their share within that TTL)
    """

    total_packets = sum(ttl_counter.values())
    print(f"\n=== TTLs and top IPs for {period_name} ===")
    if total_packets == 0:
        print("No packets in this period.")
        return

    print(f"Total packets: {total_packets}")
    print("TTL\tPackets\tPercent_of_all")
    print("----------------------------------------")

    for ttl in sorted(ttl_counter.keys()):
        ttl_count = ttl_counter[ttl]
        pct_all = 100.0 * ttl_count / total_packets
        print(f"\nTTL {ttl}:\t{ttl_count} packets\t({pct_all:6.2f} % of all)")

        ip_counter = ttl_to_ip_counter.get(ttl, Counter())
        if not ip_counter:
            print("  (no IP data for this TTL)")
            continue

        print(f"  Top {min(top_n, len(ip_counter))} IPs for TTL {ttl}:")
        for rank, (ip, ip_count) in enumerate(ip_counter.most_common(top_n), start=1):
            pct_within_ttl = 100.0 * ip_count / ttl_count
            print(
                f"    {rank}. {ip}\t{ip_count} packets\t({pct_within_ttl:6.2f} % of TTL {ttl})"
            )


def analyze_ttls(pcap_path: Path) -> None:
    if not pcap_path.is_file():
        print(f"Error: {pcap_path} does not exist or is not a file", file=sys.stderr)
        sys.exit(1)

    exp1_ttls: Counter[int] = Counter()
    exp2_ttls: Counter[int] = Counter()

    exp1_ttl_to_ips: dict[int, Counter[str]] = defaultdict(Counter)
    exp2_ttl_to_ips: dict[int, Counter[str]] = defaultdict(Counter)

    with PcapReader(str(pcap_path)) as pcap:
        for pkt in pcap:
            if IP not in pkt:
                continue

            try:
                ts = datetime.fromtimestamp(float(pkt.time))
            except Exception:
                continue

            src_ip = pkt[IP].src

            if src_ip in IGNORE or is_local_like(src_ip):
                continue

            try:
                ttl = int(pkt[IP].ttl)
            except Exception:
                continue

            if EXP1_START <= ts <= EXP1_END:
                exp1_ttls[ttl] += 1
                exp1_ttl_to_ips[ttl][src_ip] += 1
            elif EXP2_START <= ts <= EXP2_END:
                exp2_ttls[ttl] += 1
                exp2_ttl_to_ips[ttl][src_ip] += 1

    print_ttl_with_top_ips("Experiment 1", exp1_ttls, exp1_ttl_to_ips)
    print_ttl_with_top_ips("Experiment 2", exp2_ttls, exp2_ttl_to_ips)


def main() -> None:
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} capture.pcap", file=sys.stderr)
        sys.exit(1)

    pcap_path = Path(sys.argv[1])
    analyze_ttls(pcap_path)


if __name__ == "__main__":
    main()
