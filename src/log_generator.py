"""
log_generator.py
Generates synthetic auth.log (SSH) and nginx access.log data with embedded
attack patterns (brute force, port/endpoint scanning, request-rate anomalies)
so the SIEM-lite pipeline can be demoed without needing a live server.

Usage:
    python3 log_generator.py
"""
import random
import datetime
import os

OUT_DIR = os.path.join(os.path.dirname(__file__), "..", "data")
os.makedirs(OUT_DIR, exist_ok=True)

NORMAL_IPS = ["203.0.113.10", "198.51.100.22", "192.0.2.44", "10.0.0.5"]
ATTACKER_IPS = ["45.155.205.12", "185.220.101.7", "91.240.118.33"]
USERS = ["root", "admin", "deploy", "ubuntu", "postgres", "www-data"]
ENDPOINTS = [
    "/", "/login", "/dashboard", "/api/users", "/wp-admin", "/.env",
    "/admin", "/config.php", "/api/v1/orders", "/backup.zip", "/phpmyadmin",
    "/api/v1/token", "/.git/config", "/robots.txt", "/uploads/",
]

START = datetime.datetime(2026, 7, 10, 0, 0, 0)


def ts(offset_seconds):
    return START + datetime.timedelta(seconds=offset_seconds)


def fmt_syslog(t):
    return t.strftime("%b %d %H:%M:%S")


def fmt_nginx(t):
    return t.strftime("%d/%b/%Y:%H:%M:%S +0000")


def generate_auth_log():
    lines = []
    t = 0
    # Normal successful logins scattered through the day
    for _ in range(40):
        t += random.randint(30, 600)
        ip = random.choice(NORMAL_IPS)
        user = random.choice(USERS[:2])
        lines.append(f"{fmt_syslog(ts(t))} host sshd[{random.randint(1000,9999)}]: "
                      f"Accepted password for {user} from {ip} port {random.randint(30000,60000)} ssh2")

    # Brute force burst from one attacker IP: many failed logins in a tight window
    attacker = ATTACKER_IPS[0]
    burst_start = 5000
    for i in range(35):
        t = burst_start + i * random.randint(1, 3)
        user = random.choice(USERS)
        lines.append(f"{fmt_syslog(ts(t))} host sshd[{random.randint(1000,9999)}]: "
                      f"Failed password for invalid user {user} from {attacker} port {random.randint(30000,60000)} ssh2")

    # A second, slower brute force attempt from another IP (lower severity)
    attacker2 = ATTACKER_IPS[1]
    burst_start2 = 20000
    for i in range(8):
        t = burst_start2 + i * random.randint(5, 15)
        user = random.choice(USERS)
        lines.append(f"{fmt_syslog(ts(t))} host sshd[{random.randint(1000,9999)}]: "
                      f"Failed password for invalid user {user} from {attacker2} port {random.randint(30000,60000)} ssh2")

    lines.sort()
    with open(os.path.join(OUT_DIR, "sample_auth.log"), "w") as f:
        f.write("\n".join(lines) + "\n")
    print(f"Wrote {len(lines)} lines to data/sample_auth.log")


def generate_access_log():
    lines = []
    t = 0
    # Normal browsing traffic
    for _ in range(120):
        t += random.randint(5, 90)
        ip = random.choice(NORMAL_IPS)
        path = random.choice(["/", "/dashboard", "/api/v1/orders", "/login"])
        status = random.choice([200, 200, 200, 304, 404])
        lines.append(
            f'{ip} - - [{fmt_nginx(ts(t))}] "GET {path} HTTP/1.1" {status} {random.randint(200,5000)} '
            f'"-" "Mozilla/5.0"'
        )

    # Endpoint/path scan: attacker hammers many distinct sensitive paths fast
    scanner = ATTACKER_IPS[2]
    scan_start = 12000
    for i, path in enumerate(ENDPOINTS * 3):
        t = scan_start + i * random.randint(1, 2)
        lines.append(
            f'{scanner} - - [{fmt_nginx(ts(t))}] "GET {path} HTTP/1.1" 404 {random.randint(150,400)} '
            f'"-" "python-requests/2.31"'
        )

    # Request-rate anomaly: single IP flooding one endpoint (credential stuffing / DoS-ish)
    flooder = ATTACKER_IPS[0]
    flood_start = 30000
    for i in range(60):
        t = flood_start + i  # ~1 req/sec sustained
        lines.append(
            f'{flooder} - - [{fmt_nginx(ts(t))}] "POST /login HTTP/1.1" 401 312 '
            f'"-" "curl/8.1.2"'
        )

    lines.sort(key=lambda l: l.split("[")[1].split("]")[0])
    with open(os.path.join(OUT_DIR, "sample_access.log"), "w") as f:
        f.write("\n".join(lines) + "\n")
    print(f"Wrote {len(lines)} lines to data/sample_access.log")


if __name__ == "__main__":
    random.seed(42)
    generate_auth_log()
    generate_access_log()
