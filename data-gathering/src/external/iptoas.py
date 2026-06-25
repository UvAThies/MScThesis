import csv
import ipaddress
from bisect import bisect_right
from pathlib import Path
from typing import Any, Dict, List, Optional

_CACHE: Dict[Path, Dict[str, Any]] = {}


def _ipv4_to_int(ip: str) -> int:
    """Convert IPv4 string to integer for easy range comparison."""
    addr = ipaddress.ip_address(ip)
    if not isinstance(addr, ipaddress.IPv4Address):
        raise ValueError(f"Only IPv4 is supported, got {ip} ({type(addr)})")
    return int(addr)


def _init_cache(path: Path) -> None:
    starts: List[int] = []
    ranges: List[Dict[str, Any]] = []

    with path.open(newline="", encoding="utf-8") as f:
        reader = csv.reader(f)
        for row in reader:
            if len(row) != 4:
                continue

            start_ip, end_ip, asn, org = row
            if ":" in start_ip:
                continue
            start_int = _ipv4_to_int(start_ip)
            end_int = _ipv4_to_int(end_ip)

            starts.append(start_int)
            ranges.append(
                {
                    "start_int": start_int,
                    "end_int": end_int,
                    "start_ip": start_ip,
                    "end_ip": end_ip,
                    "asn": int(asn),
                    "org": org,
                }
            )

    sorted_pairs = sorted(zip(starts, ranges), key=lambda x: x[0])
    starts = [p[0] for p in sorted_pairs]
    ranges = [p[1] for p in sorted_pairs]

    _CACHE[path] = {"starts": starts, "ranges": ranges}


def find_ip_in_csv(
    ip: ipaddress.IPv4Address, path: Path
) -> Optional[Dict[str, object]]:
    if path not in _CACHE:
        _init_cache(path)

    cache = _CACHE[path]
    starts: List[int] = cache["starts"]
    ranges: List[Dict[str, Any]] = cache["ranges"]

    target = int(ip)

    idx = bisect_right(starts, target) - 1
    if idx < 0:
        return None

    r = ranges[idx]
    if r["start_int"] <= target <= r["end_int"]:
        return {
            "start_ip": r["start_ip"],
            "end_ip": r["end_ip"],
            "asn": r["asn"],
            "org": r["org"],
        }

    return None
