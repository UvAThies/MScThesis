#!/usr/bin/env python3
import sys
from collections import Counter

if len(sys.argv) < 2:
    print(f"Usage: {sys.argv[0]} flows.txt [TOP_N]", file=sys.stderr)
    sys.exit(1)

fname = sys.argv[1]
TOP_N = int(sys.argv[2]) if len(sys.argv) > 2 else 50

DNS_QNAME_COL = 45
DST_IP_COL = 17


def split_repeated_field(value):
    if not value:
        return []
    return [x.strip() for x in value.split(";") if x.strip()]


def normalize_name(name):
    if not name:
        return None
    name = name.strip().lower().rstrip(".")
    if name.startswith('"') and name.endswith('"') and len(name) > 2:
        name = name[1:-1]
    if not name or " " in name or "/" in name:
        return None
    return name


def normalize_ip(ip):
    if not ip:
        return None
    ip = ip.strip().strip('"')
    return ip if ip else None


name_counts = Counter()
dst_counts = Counter()
name_dst_counts = Counter()

with open(fname, "r", encoding="utf-8", errors="ignore") as f:
    for line in f:
        if line.startswith("#"):
            continue

        cols = line.rstrip("\n").split("\t")
        if len(cols) <= max(DNS_QNAME_COL, DST_IP_COL):
            continue

        dnsqname = cols[DNS_QNAME_COL]
        dst_ip = normalize_ip(cols[DST_IP_COL])

        queries = []
        for q in split_repeated_field(dnsqname):
            name = normalize_name(q)
            if name:
                queries.append(name)
                name_counts[name] += 1

        if dst_ip:
            dst_counts[dst_ip] += len(queries)
            for name in queries:
                name_dst_counts[(name, dst_ip)] += 1

print(f"Top {TOP_N} most queried DNS names:")
print("-----------------------------------")
for name, cnt in name_counts.most_common(TOP_N):
    print(f"{cnt:7d}  {name}")

print()
print(f"Top {TOP_N} destination resolver IPs:")
print("-----------------------------------")
for ip, cnt in dst_counts.most_common(TOP_N):
    print(f"{cnt:7d}  {ip}")

print()
print(f"Top {TOP_N} query name -> destination IP pairs:")
print("-----------------------------------------------")
for (name, ip), cnt in name_dst_counts.most_common(TOP_N):
    print(f"{cnt:7d}  {name:40s} -> {ip}")
