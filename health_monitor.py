#!/usr/bin/env python3
"""Linux system health monitor for learning and local administration practice.

Reports CPU, memory, disk usage, selected service status, and suspicious log patterns.
Uses standard Linux command-line tools and writes timestamped records to a local log.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

DEFAULT_LOG = Path.home() / ".local" / "log" / "linux-health-monitor.log"
DEFAULT_SERVICES = ["ssh", "cron"]
SUSPICIOUS_PATTERNS = {
    "authentication failure": re.compile(r"authentication failure|failed password|invalid user", re.I),
    "privilege escalation": re.compile(r"sudo:.*(authentication failure|incorrect password|command not allowed)", re.I),
    "account lockout": re.compile(r"account .* locked|too many authentication failures", re.I),
}


def run_command(args: list[str], timeout: int = 8) -> tuple[int, str, str]:
    """Run a command safely without a shell; return exit code, stdout, stderr."""
    try:
        result = subprocess.run(args, capture_output=True, text=True, timeout=timeout, check=False)
        return result.returncode, result.stdout.strip(), result.stderr.strip()
    except FileNotFoundError:
        return 127, "", f"Command not found: {args[0]}"
    except subprocess.TimeoutExpired:
        return 124, "", f"Command timed out: {' '.join(args)}"


def cpu_usage(interval: float = 0.25) -> dict[str, Any]:
    """Estimate CPU busy percentage from /proc/stat over a short interval."""
    def sample() -> tuple[int, int] | None:
        try:
            with open("/proc/stat", encoding="utf-8") as f:
                fields = f.readline().split()
            if not fields or fields[0] != "cpu":
                return None
            values = [int(value) for value in fields[1:]]
            idle = values[3] + (values[4] if len(values) > 4 else 0)
            return sum(values), idle
        except (OSError, ValueError):
            return None

    first = sample()
    if first is None:
        return {"available": False, "warning": "Could not read /proc/stat"}
    time.sleep(max(0.05, min(interval, 2.0)))
    second = sample()
    if second is None:
        return {"available": False, "warning": "Could not read /proc/stat"}
    total_delta = second[0] - first[0]
    idle_delta = second[1] - first[1]
    if total_delta <= 0:
        return {"available": False, "warning": "Invalid CPU counters"}
    return {"available": True, "usage_percent": round((1 - idle_delta / total_delta) * 100, 1)}


def memory_usage() -> dict[str, Any]:
    """Read MemTotal and MemAvailable from /proc/meminfo."""
    values: dict[str, int] = {}
    try:
        with open("/proc/meminfo", encoding="utf-8") as f:
            for line in f:
                key, _, rest = line.partition(":")
                if key in {"MemTotal", "MemAvailable", "MemFree", "Buffers", "Cached"}:
                    match = re.search(r"(\d+)", rest)
                    if match:
                        values[key] = int(match.group(1))  # kB
    except OSError as exc:
        return {"available": False, "warning": str(exc)}

    total = values.get("MemTotal")
    available = values.get("MemAvailable")
    if not total or available is None:
        return {"available": False, "warning": "MemTotal or MemAvailable missing"}
    used_percent = (total - available) / total * 100
    return {
        "available": True,
        "total_mb": round(total / 1024),
        "available_mb": round(available / 1024),
        "used_percent": round(used_percent, 1),
    }


def disk_usage(path: str) -> dict[str, Any]:
    try:
        usage = shutil.disk_usage(path)
        used_percent = usage.used / usage.total * 100 if usage.total else 0.0
        return {
            "available": True,
            "path": path,
            "total_gb": round(usage.total / (1024 ** 3), 2),
            "used_gb": round(usage.used / (1024 ** 3), 2),
            "free_gb": round(usage.free / (1024 ** 3), 2),
            "used_percent": round(used_percent, 1),
        }
    except OSError as exc:
        return {"available": False, "path": path, "warning": str(exc)}


def service_status(service: str) -> dict[str, Any]:
    """Check a service using systemctl when available; do not change its state."""
    if shutil.which("systemctl") is None:
        return {"service": service, "status": "unknown", "detail": "systemctl unavailable"}
    code, output, error = run_command(["systemctl", "is-active", service], timeout=5)
    status = output or ("unknown" if code == 127 else "inactive")
    detail = error if error else None
    return {"service": service, "status": status, "detail": detail}


def suspicious_log_scan(lines: int = 250) -> dict[str, Any]:
    """Scan recent readable system journal entries; never modify logs."""
    if shutil.which("journalctl") is None:
        return {"available": False, "warning": "journalctl not installed; log scan skipped", "matches": []}
    code, output, error = run_command(
        ["journalctl", "--no-pager", "-n", str(max(1, min(lines, 2000))), "--output=short-iso"],
        timeout=10,
    )
    if code != 0:
        return {
            "available": False,
            "warning": error or "Could not read system journal (permissions may be restricted)",
            "matches": [],
        }
    matches: list[dict[str, str]] = []
    for line in output.splitlines():
        for label, pattern in SUSPICIOUS_PATTERNS.items():
            if pattern.search(line):
                # Keep original journal line for local review; do not treat a match as proof of an attack.
                matches.append({"category": label, "entry": line[:500]})
                break
    return {"available": True, "entries_scanned": len(output.splitlines()), "match_count": len(matches), "matches": matches}


def make_report(args: argparse.Namespace) -> dict[str, Any]:
    report: dict[str, Any] = {
        "timestamp": dt.datetime.now().astimezone().isoformat(timespec="seconds"),
        "hostname": os.uname().nodename if hasattr(os, "uname") else "unknown",
        "platform": sys.platform,
        "checks": {},
        "warnings": [],
    }
    checks = report["checks"]
    checks["cpu"] = cpu_usage()
    checks["memory"] = memory_usage()
    checks["disk"] = disk_usage(args.disk_path)
    checks["services"] = [service_status(s) for s in args.services]
    checks["suspicious_logs"] = suspicious_log_scan(args.log_lines) if args.scan_logs else {
        "available": False, "warning": "Log scan disabled", "matches": []
    }

    cpu = checks["cpu"]
    if cpu.get("available") and cpu["usage_percent"] >= args.cpu_threshold:
        report["warnings"].append(f"High CPU usage: {cpu['usage_percent']}% (threshold {args.cpu_threshold}%)")
    mem = checks["memory"]
    if mem.get("available") and mem["used_percent"] >= args.memory_threshold:
        report["warnings"].append(f"High memory usage: {mem['used_percent']}% (threshold {args.memory_threshold}%)")
    disk = checks["disk"]
    if disk.get("available") and disk["used_percent"] >= args.disk_threshold:
        report["warnings"].append(f"Low disk space: {disk['used_percent']}% used (threshold {args.disk_threshold}%)")
    for service in checks["services"]:
        if service["status"] not in {"active", "unknown"}:
            report["warnings"].append(f"Service {service['service']} is {service['status']}")
    logs = checks["suspicious_logs"]
    if logs.get("match_count", 0):
        report["warnings"].append(f"Found {logs['match_count']} log entries matching suspicious patterns; review context manually")
    return report


def append_log(path: Path, report: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(report, sort_keys=True) + "\n")


def print_report(report: dict[str, Any]) -> None:
    checks = report["checks"]
    print("=" * 64)
    print("LINUX SYSTEM HEALTH REPORT")
    print(f"Host: {report['hostname']}  |  Time: {report['timestamp']}")
    print("=" * 64)
    cpu = checks["cpu"]
    print(f"CPU:    {cpu.get('usage_percent', 'N/A')}% used" if cpu.get("available") else f"CPU:    {cpu.get('warning', 'unavailable')}")
    mem = checks["memory"]
    if mem.get("available"):
        print(f"Memory: {mem['used_percent']}% used ({mem['available_mb']} MB available / {mem['total_mb']} MB total)")
    else:
        print(f"Memory: {mem.get('warning', 'unavailable')}")
    disk = checks["disk"]
    if disk.get("available"):
        print(f"Disk:   {disk['used_percent']}% used on {disk['path']} ({disk['free_gb']} GB free / {disk['total_gb']} GB total)")
    else:
        print(f"Disk:   {disk.get('warning', 'unavailable')}")
    print("\nServices:")
    for service in checks["services"]:
        print(f"  - {service['service']}: {service['status']}")
    logs = checks["suspicious_logs"]
    print("\nLog scan:")
    if logs.get("available"):
        print(f"  Scanned {logs['entries_scanned']} journal entries; pattern matches: {logs['match_count']}")
        for match in logs["matches"][:5]:
            print(f"  - [{match['category']}] {match['entry']}")
        if len(logs["matches"]) > 5:
            print(f"  ... and {len(logs['matches']) - 5} more matches (see JSON log)")
    else:
        print(f"  {logs.get('warning', 'unavailable')}")
    print("\nWarnings:")
    if report["warnings"]:
        for warning in report["warnings"]:
            print(f"  [WARNING] {warning}")
    else:
        print("  No threshold warnings detected.")
    print("=" * 64)


def positive_percent(value: str) -> float:
    try:
        number = float(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be a number from 0 to 100") from exc
    if not 0 <= number <= 100:
        raise argparse.ArgumentTypeError("must be between 0 and 100")
    return number


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Report local Linux health and write a timestamped JSONL log.")
    parser.add_argument("--disk-path", default="/", help="Filesystem path to inspect (default: /)")
    parser.add_argument("--cpu-threshold", type=positive_percent, default=85.0, help="CPU warning threshold in percent")
    parser.add_argument("--memory-threshold", type=positive_percent, default=85.0, help="Memory warning threshold in percent")
    parser.add_argument("--disk-threshold", type=positive_percent, default=85.0, help="Disk warning threshold in percent")
    parser.add_argument("--services", nargs="*", default=DEFAULT_SERVICES, help="Systemd service names to check (default: ssh cron)")
    parser.add_argument("--log-lines", type=int, default=250, help="Recent journal entries to inspect (max 2000)")
    parser.add_argument("--no-log-scan", dest="scan_logs", action="store_false", help="Skip journal scanning")
    parser.add_argument("--log-file", type=Path, default=DEFAULT_LOG, help=f"JSONL output log (default: {DEFAULT_LOG})")
    parser.add_argument("--json", action="store_true", help="Print full report as JSON instead of the human-readable summary")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.log_lines < 1:
        print("Error: --log-lines must be at least 1", file=sys.stderr)
        return 2
    report = make_report(args)
    try:
        append_log(args.log_file, report)
    except OSError as exc:
        print(f"Warning: could not write log file {args.log_file}: {exc}", file=sys.stderr)
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print_report(report)
        print(f"Timestamped report appended to: {args.log_file}")
    return 1 if report["warnings"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
