#!/usr/bin/env python3
import sys
from collections import defaultdict
from datetime import datetime, timezone

if len(sys.argv) != 2:
    print(f"Usage: {sys.argv[0]} flows.txt", file=sys.stderr)
    sys.exit(1)

fname = sys.argv[1]


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


def parse_day(ts):
    sec = ts.split(".")[0]
    return datetime.fromtimestamp(int(sec), tz=timezone.utc).strftime("%Y-%m-%d")


dns_names_per_day = defaultdict(set)
ssl_names_per_day = defaultdict(set)

with open(fname, "r", encoding="utf-8", errors="ignore") as f:
    for line in f:
        if line.startswith("#"):
            continue

        cols = line.rstrip("\n").split("\t")
        if len(cols) <= 131:
            continue

        try:
            day = parse_day(cols[3])
            dnsqname = cols[45]
            sslservername = cols[121]
            sslsubjectcn = cols[131]
        except Exception:
            continue

        # DNS names
        for q in split_repeated_field(dnsqname):
            name = normalize_name(q)
            if name:
                dns_names_per_day[day].add(name)

        # SSL names (SNI + certificate CN)
        for field in (sslservername, sslsubjectcn):
            for q in split_repeated_field(field):
                name = normalize_name(q)
                if name:
                    ssl_names_per_day[day].add(name)

days = sorted(set(dns_names_per_day.keys()) | set(ssl_names_per_day.keys()))

for day in days:
    ssl_only = sorted(ssl_names_per_day[day] - dns_names_per_day[day])
    if not ssl_only:
        continue

    print(day)
    for name in ssl_only:
        print(" ", name)
    print()
