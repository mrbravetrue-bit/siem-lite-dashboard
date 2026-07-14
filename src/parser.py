"""
parser.py
Parses raw log lines (SSH auth.log, nginx access.log) into a normalized
event schema so the detection engine doesn't need to know log formats.

Normalized event dict:
    {
        "timestamp": datetime,
        "source": "ssh" | "nginx",
        "ip": str,
        "event_type": "login_success" | "login_failed" | "http_request",
        "detail": str,       # user, path, status code, etc.
        "raw": str
    }
"""
import re
import datetime

_SSH_RE = re.compile(
    r"^(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+\S+\s+sshd\[\d+\]:\s+"
    r"(?P<result>Accepted|Failed)\s+password for (invalid user )?(?P<user>\S+) from (?P<ip>[\d.]+)"
)

_NGINX_RE = re.compile(
    r'^(?P<ip>[\d.]+)\s+\S+\s+\S+\s+\[(?P<datetime>[^\]]+)\]\s+'
    r'"(?P<method>\w+)\s+(?P<path>\S+)\s+HTTP/[\d.]+"\s+(?P<status>\d+)\s+(?P<size>\d+)'
)

_MONTHS = {m: i + 1 for i, m in enumerate(
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"])}

_YEAR_ASSUMED = 2026


def parse_ssh_line(line):
    m = _SSH_RE.match(line.strip())
    if not m:
        return None
    d = m.groupdict()
    month = _MONTHS[d["month"]]
    hh, mm, ss = map(int, d["time"].split(":"))
    timestamp = datetime.datetime(_YEAR_ASSUMED, month, int(d["day"]), hh, mm, ss)
    event_type = "login_success" if d["result"] == "Accepted" else "login_failed"
    return {
        "timestamp": timestamp,
        "source": "ssh",
        "ip": d["ip"],
        "event_type": event_type,
        "detail": f"user={d['user']}",
        "raw": line.strip(),
    }


def parse_nginx_line(line):
    m = _NGINX_RE.match(line.strip())
    if not m:
        return None
    d = m.groupdict()
    timestamp = datetime.datetime.strptime(d["datetime"].split(" ")[0], "%d/%b/%Y:%H:%M:%S")
    return {
        "timestamp": timestamp,
        "source": "nginx",
        "ip": d["ip"],
        "event_type": "http_request",
        "detail": f"{d['method']} {d['path']} -> {d['status']}",
        "raw": line.strip(),
    }


def parse_file(path, source):
    parser_fn = parse_ssh_line if source == "ssh" else parse_nginx_line
    events = []
    with open(path) as f:
        for line in f:
            if not line.strip():
                continue
            evt = parser_fn(line)
            if evt:
                events.append(evt)
    return events
