"""
detector.py
Rule-based detection engine. Takes normalized events (from parser.py) and
produces a list of alerts. Each rule is intentionally simple and documented
so it's easy to extend with new detections.
"""
import datetime
from collections import defaultdict

# --- Tunable thresholds -----------------------------------------------
BRUTE_FORCE_THRESHOLD = 5      # failed logins...
BRUTE_FORCE_WINDOW = 60        # ...within this many seconds -> alert
SCAN_THRESHOLD = 10            # distinct paths hit...
SCAN_WINDOW = 30               # ...within this many seconds -> alert
FLOOD_THRESHOLD = 20           # requests to same path...
FLOOD_WINDOW = 60              # ...within this many seconds -> alert
# ------------------------------------------------------------------------


def _severity(count, low, med, high):
    if count >= high:
        return "CRITICAL"
    if count >= med:
        return "HIGH"
    if count >= low:
        return "MEDIUM"
    return "LOW"


def detect_brute_force(events):
    """Sliding-window count of failed SSH logins per source IP."""
    alerts = []
    failed = sorted(
        [e for e in events if e["event_type"] == "login_failed"],
        key=lambda e: e["timestamp"],
    )
    by_ip = defaultdict(list)
    for e in failed:
        by_ip[e["ip"]].append(e["timestamp"])

    for ip, times in by_ip.items():
        window_start = 0
        for i in range(len(times)):
            while (times[i] - times[window_start]).total_seconds() > BRUTE_FORCE_WINDOW:
                window_start += 1
            count = i - window_start + 1
            if count == BRUTE_FORCE_THRESHOLD:  # fire once per burst
                alerts.append({
                    "type": "BRUTE_FORCE",
                    "ip": ip,
                    "timestamp": times[i],
                    "severity": _severity(len(times), 5, 15, 30),
                    "message": f"{len(times)} failed SSH logins from {ip} "
                               f"({count} within {BRUTE_FORCE_WINDOW}s window)",
                })
    return alerts


def detect_endpoint_scan(events):
    """Flags an IP hitting many distinct HTTP paths in a short window (recon/scanning)."""
    alerts = []
    http = sorted(
        [e for e in events if e["event_type"] == "http_request"],
        key=lambda e: e["timestamp"],
    )
    by_ip = defaultdict(list)
    for e in http:
        by_ip[e["ip"]].append(e)

    for ip, evts in by_ip.items():
        window_start = 0
        seen_paths = {}
        for i in range(len(evts)):
            while (evts[i]["timestamp"] - evts[window_start]["timestamp"]).total_seconds() > SCAN_WINDOW:
                window_start += 1
            window_events = evts[window_start:i + 1]
            distinct_paths = len({e["detail"].split(" ")[1] for e in window_events})
            if distinct_paths == SCAN_THRESHOLD and ip not in seen_paths:
                seen_paths[ip] = True
                alerts.append({
                    "type": "ENDPOINT_SCAN",
                    "ip": ip,
                    "timestamp": evts[i]["timestamp"],
                    "severity": _severity(distinct_paths, 10, 25, 40),
                    "message": f"{ip} probed {distinct_paths}+ distinct endpoints within {SCAN_WINDOW}s "
                               f"(recon/scanning behavior)",
                })
    return alerts


def detect_request_flood(events):
    """Flags sustained high-rate requests to a single path from one IP."""
    alerts = []
    http = sorted(
        [e for e in events if e["event_type"] == "http_request"],
        key=lambda e: e["timestamp"],
    )
    by_key = defaultdict(list)
    for e in http:
        path = e["detail"].split(" ")[1]
        by_key[(e["ip"], path)].append(e["timestamp"])

    for (ip, path), times in by_key.items():
        window_start = 0
        fired = False
        for i in range(len(times)):
            while (times[i] - times[window_start]).total_seconds() > FLOOD_WINDOW:
                window_start += 1
            count = i - window_start + 1
            if count >= FLOOD_THRESHOLD and not fired:
                fired = True
                alerts.append({
                    "type": "REQUEST_FLOOD",
                    "ip": ip,
                    "timestamp": times[i],
                    "severity": _severity(len(times), 20, 40, 60),
                    "message": f"{ip} sent {len(times)} requests to {path} "
                               f"(sustained flood, possible credential stuffing/DoS)",
                })
    return alerts


def run_all_detections(events):
    alerts = []
    alerts.extend(detect_brute_force(events))
    alerts.extend(detect_endpoint_scan(events))
    alerts.extend(detect_request_flood(events))
    alerts.sort(key=lambda a: a["timestamp"])
    return alerts
