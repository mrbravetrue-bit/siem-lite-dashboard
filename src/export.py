"""
export.py
Reads events/alerts from SQLite and exports a single JSON file the static
dashboard (dashboard/index.html) fetches and renders. Keeping the dashboard
purely static (no backend needed to view it) makes the repo trivial to
demo via GitHub Pages or just opening index.html locally.
"""
import json
import os
from collections import Counter
from storage import get_connection

OUT_PATH = os.path.join(os.path.dirname(__file__), "..", "dashboard", "data.json")


def build_export():
    conn = get_connection()
    events = [dict(r) for r in conn.execute("SELECT * FROM events ORDER BY timestamp")]
    alerts = [dict(r) for r in conn.execute("SELECT * FROM alerts ORDER BY timestamp")]
    conn.close()

    severity_counts = Counter(a["severity"] for a in alerts)
    type_counts = Counter(a["type"] for a in alerts)
    ip_counts = Counter(a["ip"] for a in alerts)
    source_counts = Counter(e["source"] for e in events)

    # Events per hour bucket (for a timeline chart)
    timeline = Counter()
    for e in events:
        hour_bucket = e["timestamp"][:13]  # YYYY-MM-DDTHH
        timeline[hour_bucket] += 1
    timeline_sorted = sorted(timeline.items())

    payload = {
        "generated_at": events[-1]["timestamp"] if events else None,
        "totals": {
            "events": len(events),
            "alerts": len(alerts),
            "unique_ips": len({e["ip"] for e in events}),
        },
        "severity_counts": dict(severity_counts),
        "type_counts": dict(type_counts),
        "top_offending_ips": ip_counts.most_common(10),
        "source_counts": dict(source_counts),
        "timeline": timeline_sorted,
        "alerts": alerts[::-1],  # newest first for the live feed
    }

    with open(OUT_PATH, "w") as f:
        json.dump(payload, f, indent=2)
    print(f"Exported dashboard data -> {OUT_PATH}")
    print(f"  events={len(events)} alerts={len(alerts)} unique_ips={payload['totals']['unique_ips']}")


if __name__ == "__main__":
    build_export()
