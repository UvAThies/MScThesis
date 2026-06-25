#!/usr/bin/env python3
import ipaddress
import sys
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Optional

from scapy.all import IP, PcapReader

# Your ip-to-ASN lookup
sys.path.append("/home/thies/project/resip/src/")
from external.iptoas import find_ip_in_csv

# -------------------------------------------------------------------
# Period boundaries for the two experiments
# -------------------------------------------------------------------
BRIGHTDATA_START = datetime(2026, 5, 19, 0, 0)
BRIGHTDATA_END = datetime(2026, 5, 20, 23, 59, 59)

DECODO_START = datetime(2026, 6, 2, 0, 0)
DECODO_END = datetime(2026, 6, 3, 23, 59, 59)

IGNORE = ["145.100.108.82", "145.100.108.81", "102.207.2.160"]


def escape_latex(text: str) -> str:
    replacements = {
        "&": r"\&",
        "%": r"\%",
        "$": r"\$",
        "#": r"\#",
        "_": r"\_",
        "{": r"\{",
        "}": r"\}",
        "~": r"\textasciitilde{}",
        "^": r"\textasciicircum{}",
        "\\": r"\textbackslash{}",
    }
    for k, v in replacements.items():
        text = text.replace(k, v)
    return text


def make_top_n(counter: Counter[str], n: int = 5) -> list[tuple[str, int]]:
    """Return a list of (ip, count) top n from a Counter."""
    return sorted(counter.items(), key=lambda x: x[1], reverse=True)[:n]


def print_latex_table(
    period_name: str, counter: Counter[str], csv_path: Path, out
) -> None:
    """
    Print a LaTeX table with top-5 requestors for a given period.

    Columns: Rank, Source IP, Requests, ASN, Organization.
    """
    top5 = make_top_n(counter, 10)

    out.write(f"% Top 5 requestors during {period_name}\n")
    out.write(r"\begin{table}[h]\n")
    out.write(r"\centering\n")
    out.write(r"\begin{tabular}{llrll}\n")
    out.write(r"\hline\n")
    out.write(r"Rank & Source IP & Requests & ASN & Organization \\\n")
    out.write(r"\hline\n")

    if not top5:
        out.write(r"\multicolumn{5}{c}{No data in this period} \\\n")
    else:
        for rank, (ip_str, count) in enumerate(top5, start=1):
            try:
                ip_obj = ipaddress.ip_address(ip_str)
            except ValueError:
                asn = "-"
                org = "invalid IP"
            else:
                if isinstance(ip_obj, ipaddress.IPv4Address):
                    info: Optional[Dict[str, Any]] = find_ip_in_csv(ip_obj, csv_path)
                    if info is None:
                        asn = "-"
                        org = "No match in CSV"
                    else:
                        asn = str(info.get("asn", "-"))
                        org = str(info.get("org", "-"))
                else:
                    asn = "-"
                    org = "Non-IPv4 address"

            asn_l = escape_latex(asn)
            org_l = escape_latex(org)
            out.write(f"{rank} & {ip_str} & {count} & {asn_l} & {org_l} \\\\\n")

    out.write(r"\hline\n")
    out.write(r"\end{tabular}\n")
    out.write(rf"\caption{{Top 5 requestors during {escape_latex(period_name)}.}}\n")
    out.write(rf"\label{{tab:top5-{period_name.lower().replace(' ', '-')}}}\n")
    out.write(r"\end{table}\n")
    out.write(r"\n")


def analyze_pcap(pcap_path: Path, csv_path: Path) -> None:
    if not pcap_path.is_file():
        print(f"Error: {pcap_path} does not exist or is not a file", file=sys.stderr)
        sys.exit(1)

    if not csv_path.is_file():
        print(f"Error: {csv_path} does not exist or is not a file", file=sys.stderr)
        sys.exit(1)

    brightdata_counter: Counter[str] = Counter()
    decodo_counter: Counter[str] = Counter()

    with PcapReader(str(pcap_path)) as pcap:
        for pkt in pcap:
            if IP not in pkt:
                continue

            try:
                ts = datetime.fromtimestamp(float(pkt.time))
            except Exception:
                continue

            src_ip = pkt[IP].src

            if src_ip in IGNORE:
                continue

            if BRIGHTDATA_START <= ts <= BRIGHTDATA_END:
                brightdata_counter[src_ip] += 1
            elif DECODO_START <= ts <= DECODO_END:
                decodo_counter[src_ip] += 1

    with open("output/brightdata-dns-server.txt", "w", encoding="utf-8") as out:
        print_latex_table("Bright Data", brightdata_counter, csv_path, out)

    with open("output/decodo-dns-server.txt", "w", encoding="utf-8") as out:
        print_latex_table("Decodo", decodo_counter, csv_path, out)


def main() -> None:
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} capture.pcap ip_ranges.csv", file=sys.stderr)
        sys.exit(1)

    pcap_path = Path(sys.argv[1])
    csv_path = Path(sys.argv[2])

    analyze_pcap(pcap_path, csv_path)


if __name__ == "__main__":
    main()
