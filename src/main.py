"""
main.py
Orchestrates the full SIEM-lite pipeline:
    1. Parse raw logs -> normalized events
    2. Run detection rules -> alerts
    3. Persist events + alerts to SQLite
    4. Export a JSON summary for the dashboard

Usage:
    python3 main.py
"""
import os
import parser
import detector
import storage
import export

DATA_DIR = os.path.join(os.path.dirname(__file__), "..", "data")


def main():
    print("[*] SIEM-lite pipeline starting...")

    auth_path = os.path.join(DATA_DIR, "sample_auth.log")
    access_path = os.path.join(DATA_DIR, "sample_access.log")

    events = []
    events += parser.parse_file(auth_path, source="ssh")
    events += parser.parse_file(access_path, source="nginx")
    events.sort(key=lambda e: e["timestamp"])
    print(f"[*] Parsed {len(events)} normalized events "
          f"({sum(1 for e in events if e['source']=='ssh')} ssh, "
          f"{sum(1 for e in events if e['source']=='nginx')} nginx)")

    alerts = detector.run_all_detections(events)
    print(f"[*] Detection engine raised {len(alerts)} alert(s):")
    for a in alerts:
        print(f"    [{a['severity']:8}] {a['type']:15} {a['ip']:16} {a['message']}")

    print("[*] Persisting to SQLite (db/siem.db)...")
    storage.init_db()
    storage.save_events(events)
    storage.save_alerts(alerts)

    print("[*] Exporting dashboard data...")
    export.build_export()

    print("[+] Done. Open dashboard/index.html in a browser to view results.")


if __name__ == "__main__":
    main()
