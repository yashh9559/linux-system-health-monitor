# Linux System Health Monitor

A beginner-friendly Python system administration project for Linux. It collects a local health snapshot, checks configurable thresholds, reviews recent system-journal entries for a small set of authentication-related patterns, checks selected systemd services, and writes timestamped JSON Lines (`.jsonl`) reports.

> **Safety and scope:** This is a monitoring-only tool. It does not stop services, delete files, change permissions, or block accounts. A pattern match is only a reason to review the surrounding event; it is not proof of malicious activity. Journal access and service names vary by Linux distribution and permissions. WSL may not run systemd or expose a full system journal, in which case those checks can report that they are unavailable.

## Features

- CPU usage estimate from `/proc/stat`
- Memory usage from `/proc/meminfo`
- Filesystem capacity and free space using Python's `shutil.disk_usage`
- Read-only `systemctl is-active` checks for selected services
- Read-only scan of recent `journalctl` entries for authentication-failure patterns
- Configurable CPU, memory, and disk warning thresholds
- Timestamped JSONL history and human-readable or JSON output
- No third-party Python dependencies

## Requirements

- Linux (tested design target: Ubuntu/Debian; WSL is fine for CPU/memory/disk checks)
- Python 3.10 or newer recommended
- Optional: `systemctl` and `journalctl` for service and journal checks

## Run it

```bash
chmod +x health_monitor.py
python3 health_monitor.py
```

The default log is `~/.local/log/linux-health-monitor.log`. Each line is a complete JSON report, making it easy to parse later.

### Examples

```bash
# Make warnings more sensitive
python3 health_monitor.py --cpu-threshold 70 --memory-threshold 80 --disk-threshold 75

# Check common services (service names depend on your distro)
python3 health_monitor.py --services ssh cron

# Skip journal scanning if it is unavailable in your WSL environment
python3 health_monitor.py --no-log-scan

# Print a machine-readable JSON report
python3 health_monitor.py --json

# Inspect a mounted filesystem or another path
python3 health_monitor.py --disk-path /mnt/c

# Write logs to a project-local file while testing
python3 health_monitor.py --log-file ./reports/health-history.jsonl
```

Exit codes: `0` means no threshold warning was found, `1` means one or more warnings were detected, and `2` means invalid CLI input. An unavailable check is reported separately and is not automatically treated as a failure.

## What it checks

| Area | Method | Notes |
|---|---|---|
| CPU | Delta of Linux CPU counters in `/proc/stat` | Brief sampling interval; approximate instantaneous utilisation |
| Memory | `MemTotal` and `MemAvailable` in `/proc/meminfo` | Available memory is preferable to simply subtracting `MemFree` |
| Disk | `shutil.disk_usage(path)` | Reports total, used, and free capacity |
| Services | `systemctl is-active SERVICE` | Read-only; no service changes |
| Logs | Recent lines from `journalctl` | Best-effort pattern scan; requires journal access |

## Run tests

```bash
python3 -m unittest discover -s tests -v
```

## Next improvements

- Add rotating log files to cap log growth
- Add unit tests for threshold evaluation and mocked system command results
- Add a Bash wrapper and a `systemd` timer for scheduled runs on a host with systemd
- Export Prometheus-style metrics or send email alerts (with safe credential handling)
- Add distribution-specific service profiles and structured severity levels

## Repository attribution

This is an original starter implementation written for learning and portfolio development, not a copy of the reference repository. Compare ideas with the reference, keep this code understandable, and document the changes you personally make.
