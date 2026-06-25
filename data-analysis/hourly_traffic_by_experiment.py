#!/usr/bin/env python3
import sys
from collections import defaultdict
from datetime import datetime, timezone

import matplotlib.pyplot as plt

# -------------------------------------------------------------------
# Period boundaries for the two experiments
# -------------------------------------------------------------------
BASELINE_START = datetime(2026, 5, 1, 0, 0, tzinfo=timezone.utc)
BASELINE_END = datetime(2026, 5, 10, 23, 59, 59, tzinfo=timezone.utc)

EARNAPP_START = datetime(2026, 5, 11, 0, 0, tzinfo=timezone.utc)
EARNAPP_END = datetime(2026, 5, 28, 23, 59, 59, tzinfo=timezone.utc)

GAP_START = datetime(2026, 5, 29, 0, 0, tzinfo=timezone.utc)
GAP_END = datetime(2026, 5, 31, 23, 59, 59, tzinfo=timezone.utc)

PAWNS_START = datetime(2026, 6, 1, 0, 0, tzinfo=timezone.utc)
PAWNS_END = datetime(2026, 6, 17, 23, 59, 59, tzinfo=timezone.utc)

CATEGORY_LABELS = {
    "baseline": "Baseline",
    "earnapp": "EarnApp",
    "gap": "Gap",
    "pawns": "PawnsApp",
}


def get_category(dt: datetime):
    """Return category ID based on timestamp dt, or None if outside all windows."""
    if BASELINE_START <= dt <= BASELINE_END:
        return "baseline"
    if EARNAPP_START <= dt <= EARNAPP_END:
        return "earnapp"
    if GAP_START <= dt <= GAP_END:
        return "gap"
    if PAWNS_START <= dt <= PAWNS_END:
        return "pawns"
    return None


def main():
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} flows.txt", file=sys.stderr)
        sys.exit(1)

    fname = sys.argv[1]

    bytes_per_hour = {
        "baseline": defaultdict(int),
        "earnapp": defaultdict(int),
        "gap": defaultdict(int),
        "pawns": defaultdict(int),
    }

    total_bytes = {
        "baseline": 0,
        "earnapp": 0,
        "gap": 0,
        "pawns": 0,
    }

    with open(fname, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            if line.startswith("#"):
                continue

            cols = line.rstrip("\n").split("\t")
            if len(cols) < 27:
                continue

            try:
                timefirst = cols[3]
                l7BytesSnt = int(cols[25] or 0)
                l7BytesRcvd = int(cols[26] or 0)
            except Exception:
                continue

            try:
                sec = int(timefirst.split(".")[0])
                dt = datetime.fromtimestamp(sec, tz=timezone.utc)
                hour = dt.hour
            except Exception:
                continue

            cat = get_category(dt)
            if cat is None:
                continue

            traffic_bytes = l7BytesSnt + l7BytesRcvd
            bytes_per_hour[cat][hour] += traffic_bytes
            total_bytes[cat] += traffic_bytes

    def plot_category(cat_id: str, title_suffix: str, out_fname: str):
        """Create bar plot of per-hour traffic (GB) for a single category."""
        hours = list(range(24))
        values_gb = [bytes_per_hour[cat_id][h] / (1024**3) for h in hours]

        plt.figure(figsize=(10, 5))
        plt.bar(hours, values_gb, color="tab:blue")
        plt.xticks(hours)
        plt.xlabel("Hour of day (UTC)")
        plt.ylabel("Traffic (GB)")
        plt.title(f"Amount of data per hour of the day – {title_suffix}")
        plt.grid(True, axis="y", alpha=0.3)
        plt.tight_layout()
        plt.savefig(out_fname, dpi=300, bbox_inches="tight")
        plt.close()
        print(f"Saved: {out_fname}")

    plot_category("earnapp", "EarnApp period", "output/traffic_per_hour_earnapp.png")
    plot_category("pawns", "PawnsApp period", "output/traffic_per_hour_pawns.png")

    with open("output/data_usage_summary.txt", "w", encoding="utf-8") as out:
        for cat_id in ["baseline", "earnapp", "gap", "pawns"]:
            label = CATEGORY_LABELS[cat_id]
            tb = total_bytes[cat_id]
            gb = tb / (1024**3)
            mb = tb / (1024**2)
            # One line per category; tweak format as you like
            out.write(f"{label}: {gb:.3f} GB ({mb:.1f} MB)\n")

    print("Saved: data_usage_summary.txt")


if __name__ == "__main__":
    main()
