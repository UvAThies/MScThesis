#!/usr/bin/env python3
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone

import matplotlib.pyplot as plt
import numpy as np

if len(sys.argv) != 2:
    print(f"Usage: {sys.argv[0]} flows.txt", file=sys.stderr)
    sys.exit(1)

fname = sys.argv[1]

# -------------------------------------------------------------------
# Period boundaries for the two experiments
# -------------------------------------------------------------------
BASELINE_START = datetime(2026, 5, 8, 0, 0)
BASELINE_END = datetime(2026, 5, 10, 23, 59, 59)

EARNAPP_START = datetime(2026, 5, 11, 0, 0)
EARNAPP_END = datetime(2026, 5, 28, 23, 59, 59)

GAP_START = datetime(2026, 5, 29, 0, 0)
GAP_END = datetime(2026, 5, 31, 23, 59, 59)

PAWNS_START = datetime(2026, 6, 1, 0, 0)
PAWNS_END = datetime(2026, 6, 19, 23, 59, 59)

IP_DESCRIPTIONS = {
    "195.121.114.12": "KPN Google cache",
    "195.121.114.13": "KPN Google cache",
    "195.121.114.14": "KPN Google cache",
    "195.121.114.15": "KPN Google cache",
    "195.121.114.16": "KPN Google cache",
    "95.179.156.61": "Bright Data infrastructure (rDNS: 95-179-156-61.lum-int.io. \\& CN=*.luminatinet.com)",
    "64.225.66.88": "Bright Data infrastructure (CN=*.luminatinet.com)",
    "79.170.100.7": "Bol.com infrastructure (CN=assets.s-bol.com)",
    "2a02:a47f:e003:12::d": "Google infrastructure (CN=*.googlevideo.com)",
    "74.125.100.138": "Google infrastructure (CN=*.c.docs.google.com)",
    "193.228.193.166": "Pawns.app infrastructure (CN=relay.pawns.app)",
    "151.101.206.172": "Fastly CDN infrastructure",
    "216.239.34.223": "Google infrastructure",
    "151.101.205.237": "Fastly CDN infrastructure",
    "151.101.206.186": "Fastly CDN infrastructure",
    "151.101.37.237": "Fastly CDN infrastructure",
    "151.101.38.186": "Fastly CDN infrastructure",
    "142.250.157.113": "Google infrastructure",
    "178.156.140.194": "Pawns.app infrastructure (CN=bootstrap.pawns.app)",
    "188.34.138.146": "Pawns.app infrastructure (CN=bootstrap.pawns.app)",
    "172.217.26.227": "Google infrastructure",
    "142.250.207.35": "Google infrastructure",
    "142.251.220.142": "Google infrastructure",
}

TEST_LINE = "192.168.98.6"
TEST_LINE_v6 = ""


def add_period_annotations(ax):
    ax.axvspan(BASELINE_START, BASELINE_END, color="lightgrey", alpha=0.3)
    ax.axvspan(GAP_START, GAP_END, color="gainsboro", alpha=0.3)

    y_top = ax.get_ylim()[1] if ax.get_ylim()[1] > 0 else 1

    events = [
        (EARNAPP_START, "EarnApp start", "tab:blue"),
        (PAWNS_START, "PawnsApp start", "tab:green"),
    ]
    for dt, label, color in events:
        ax.axvline(dt, color=color, linestyle="--", linewidth=1.5)
        ax.text(
            dt,
            y_top * 0.95,
            label,
            color=color,
            rotation=90,
            va="top",
            ha="right",
            fontsize=8,
        )


IGNORE_TLDS = {
    "local",
    "home",
    "arpa",
    "desktop-3v0rsbr<1c>",
}

dns_queries_per_day = defaultdict(int)
tls_flows_per_day = defaultdict(int)
bytes_per_day = defaultdict(int)
bytes_up_per_day = defaultdict(int)
bytes_down_per_day = defaultdict(int)
l4_proto_packets = defaultdict(int)

dns_names_per_day = defaultdict(set)
combined_names_per_day = defaultdict(set)

dns_tlds_per_day = defaultdict(list)
sni_tlds_per_day = defaultdict(list)

earnapp_ip_bytes = defaultdict(int)
pawns_ip_bytes = defaultdict(int)


def split_repeated_field(value):
    if not value:
        return []
    return [x.strip() for x in value.split(";") if x.strip()]


def normalize_name(name):
    if not name:
        return None
    name = name.strip().lower().rstrip(".")
    if not name or " " in name or "/" in name:
        return None
    return name[1:-1]


def get_tld(name):
    parts = name.split(".")
    if parts and parts[-1]:
        return parts[-1]
    return None


def format_tld_label(tld):
    return f".{tld}"


def parse_day(ts):
    sec = ts.split(".")[0]
    return datetime.fromtimestamp(int(sec), tz=timezone.utc).strftime("%Y-%m-%d")


def in_range(day_str, start_dt, end_dt):
    day_dt = datetime.strptime(day_str, "%Y-%m-%d")
    return start_dt <= day_dt <= end_dt


def write_latex_table(f, title, ip_bytes, top_n=10):
    top = sorted(ip_bytes.items(), key=lambda x: x[1], reverse=True)[:top_n]

    f.write(f"% {title}\n")
    f.write("\\begin{tabular}{lll}\n")
    f.write("\\toprule\n")
    f.write("Address & Description & Data (GB) \\\\\n")
    f.write("\\midrule\n")
    for ip, b in top:
        desc = IP_DESCRIPTIONS.get(ip, "")
        gb = b / (1024**3)
        f.write(f"{ip} & {desc} & {gb:.2f} \\\\\n")
    f.write("\\bottomrule\n")
    f.write("\\end{tabular}\n\n")


with open(fname, "r", encoding="utf-8", errors="ignore") as f:
    for line in f:
        if line.startswith("#"):
            continue

        cols = line.rstrip("\n").split("\t")
        if len(cols) < 132:
            continue

        try:
            day = parse_day(cols[3])
            src_ip = cols[13]
            dsc = cols[15]
            dst_ip = cols[17]

            l4proto = cols[21]
            dstPort = cols[20]

            pktsSnt = int(cols[22] or 0)
            pktsRcvd = int(cols[23] or 0)

            l7BytesSnt = int(cols[25] or 0)
            l7BytesRcvd = int(cols[26] or 0)

            dnsqname = cols[45]
            sslservername = cols[121]
            sslsubjectcn = cols[131]
        except Exception:
            continue

        dns_queries_per_day[day] += len(split_repeated_field(dnsqname))

        if dstPort == "443":
            tls_flows_per_day[day] += l7BytesSnt + l7BytesRcvd

        total_bytes = l7BytesSnt + l7BytesRcvd

        bytes_per_day[day] += total_bytes
        bytes_up_per_day[day] += l7BytesSnt
        bytes_down_per_day[day] += l7BytesRcvd

        l4_proto_packets[l4proto] += pktsSnt + pktsRcvd

        where_to_write = None
        if in_range(day, EARNAPP_START, EARNAPP_END):
            where_to_write = earnapp_ip_bytes

        if in_range(day, PAWNS_START, PAWNS_END):
            where_to_write = pawns_ip_bytes

        if where_to_write is not None:
            if src_ip == TEST_LINE or src_ip == TEST_LINE_v6:
                where_to_write[dst_ip] += total_bytes
            elif dst_ip == TEST_LINE or dst_ip == TEST_LINE_v6:
                where_to_write[src_ip] += total_bytes

        for q in split_repeated_field(dnsqname):
            name = normalize_name(q)

            if name:
                dns_names_per_day[day].add(name)
                combined_names_per_day[day].add(name)

                tld = get_tld(name)
                if tld and tld not in IGNORE_TLDS:
                    dns_tlds_per_day[day].append(tld)

        for q in split_repeated_field(sslservername):
            name = normalize_name(q)

            if name:
                combined_names_per_day[day].add(name)

                tld = get_tld(name)
                if tld and tld not in IGNORE_TLDS:
                    sni_tlds_per_day[day].append(tld)

        for q in split_repeated_field(sslsubjectcn):
            name = normalize_name(q)
            if name:
                combined_names_per_day[day].add(name)

days = sorted(set(dns_queries_per_day) | set(tls_flows_per_day) | set(bytes_per_day))
x_days = [datetime.strptime(d, "%Y-%m-%d") for d in days]

dns_query_values = [dns_queries_per_day[d] for d in days]
tls_values = [tls_flows_per_day[d] / (1024**3) for d in days]
traffic_values = [bytes_per_day[d] / (1024**3) for d in days]
ratio_values = [
    (bytes_down_per_day[d] / bytes_up_per_day[d]) if bytes_up_per_day[d] > 0 else 0
    for d in days
]

unique_dns_names_values = [len(dns_names_per_day[d]) for d in days]
unique_dns_plus_ssl_names_values = [len(combined_names_per_day[d]) for d in days]

# DNS graph
plt.figure(figsize=(11, 6))
plt.plot(x_days, dns_query_values, marker="o", label="DNS queries")
plt.plot(x_days, unique_dns_names_values, marker="s", label="Unique DNS names")
plt.plot(
    x_days, unique_dns_plus_ssl_names_values, marker="^", label="Unique DNS + SSL names"
)
add_period_annotations(plt.gca())
plt.title("DNS-related activity over time")
plt.xlabel("Day")
plt.ylabel("Count")
plt.xticks(rotation=45)
plt.grid(True, alpha=0.3, which="both")
plt.legend()
plt.tight_layout()
plt.savefig("output/dns_activity_over_time.png", dpi=300, bbox_inches="tight")
plt.close()

# HTTPS traffic graph
plt.figure(figsize=(10, 5))
plt.plot(x_days, tls_values, marker="o", color="orange")
add_period_annotations(plt.gca())
plt.title("Port 443 (HTTPS) traffic over time")
plt.xlabel("Day")
plt.ylabel("Traffic to port 443 (GB)")
plt.xticks(rotation=45)
plt.grid(True, alpha=0.3)
plt.tight_layout()
plt.savefig("output/tls_flows_over_time.png", dpi=300, bbox_inches="tight")
plt.close()

# Traffic + upload/download ratio
fig, ax1 = plt.subplots(figsize=(10, 5))
ax1.plot(x_days, traffic_values, marker="o", color="green", label="Traffic volume")
ax1.set_xlabel("Day")
ax1.set_ylabel("Traffic (GB)", color="green")
ax1.tick_params(axis="y", labelcolor="green")
ax1.grid(True, alpha=0.3)

add_period_annotations(ax1)

ax2 = ax1.twinx()
ax2.plot(
    x_days,
    ratio_values,
    marker="s",
    linestyle="--",
    color="purple",
    label="Download/Upload ratio",
)
ax2.set_ylabel("Download/Upload ratio", color="purple")
ax2.tick_params(axis="y", labelcolor="purple")

plt.title("Traffic volume and download/upload ratio over time")
fig.autofmt_xdate()
fig.tight_layout()
plt.savefig("output/traffic_and_ratio_over_time.png", dpi=300, bbox_inches="tight")
plt.close()


def plot_tld_distribution(tlds_per_day, title, outfile):
    before_counter = Counter()
    after_counter = Counter()
    before_days = 0
    after_days = 0

    for d in days:
        day_dt = datetime.strptime(d, "%Y-%m-%d")
        if day_dt < EARNAPP_START:
            before_counter.update(tlds_per_day[d])
            before_days += 1
        else:
            after_counter.update(tlds_per_day[d])
            after_days += 1

    top_before = [t for t, _ in before_counter.most_common(10)]
    top_after = [t for t, _ in after_counter.most_common(10)]
    top_tlds = list(dict.fromkeys(top_before + top_after))[:12]

    before_values = [
        (before_counter[t] / before_days) if before_days > 0 else 0 for t in top_tlds
    ]
    after_values = [
        (after_counter[t] / after_days) if after_days > 0 else 0 for t in top_tlds
    ]

    labels = [format_tld_label(t) for t in top_tlds]

    x = np.arange(len(top_tlds))
    width = 0.38

    fig = plt.figure(figsize=(12, 6))
    plt.bar(x - width / 2, before_values, width, label="Before RESIP")
    plt.bar(x + width / 2, after_values, width, label="After RESIP")
    plt.xticks(x, labels, rotation=45)
    plt.ylabel("Average requests per day")
    plt.yscale("log")

    plt.title(title)
    plt.legend()
    plt.tight_layout()
    plt.savefig(outfile, dpi=300, bbox_inches="tight")
    plt.close()


plot_tld_distribution(
    dns_tlds_per_day,
    "Top requested DNS TLDs before and after RESIP activation (normalized per day)",
    "output/dns_tld_distribution_before_after.png",
)

plot_tld_distribution(
    sni_tlds_per_day,
    "Top requested SNI TLDs before and after RESIP activation (normalized per day)",
    "output/sni_tld_distribution_before_after.png",
)

with open("output/top_talkers_tables.tex", "w", encoding="utf-8") as f:
    write_latex_table(f, "EarnApp top talkers", earnapp_ip_bytes, top_n=10)
    write_latex_table(f, "PawnsApp top talkers", pawns_ip_bytes, top_n=10)

print("Saved:")
print(" - dns_activity_over_time.png")
print(" - tls_flows_over_time.png")
print(" - traffic_and_ratio_over_time.png")
print(" - protocol_distribution_pie.png")
print(" - dns_tld_distribution_before_after.png")
print(" - sni_tld_distribution_before_after.png")
print(" - top_talkers_tables.tex")
