#!/usr/bin/env python3
"""
Integration test: connect via openconnect_pexpect.py, hold for HOLD_SECONDS,
disconnect, and verify the expected output.

Run from the repo root:
    python3 test_connection.py
"""
import subprocess
import sys
import re
from pathlib import Path

SCRIPT_DIR  = Path(__file__).parent
SCRIPT      = SCRIPT_DIR / "openconnect_pexpect.py"
LOG_FILE    = SCRIPT_DIR / "test_connection.log"
HOLD_SECONDS = 20

EXPECTED = [
    ("credentials retrieved",  r"\[INFO\] Retrieved AD password"),
    ("TOTP retrieved",         r"\[INFO\] Retrieved TOTP code"),
    ("AD password sent",       r"\[INPUT\] AD password"),
    ("TOTP code sent",         r"\[INPUT\] TOTP code"),
    ("tunnel established",     r"\[INFO\] VPN tunnel established"),
    ("DNS servers set",        r"\[SUCCESS\] Set VPN DNS servers"),
    ("domains configured",     r"\[SUCCESS\] Set \d+ routing/search domains"),
    ("disconnect handled",     r"\[DISCONNECT\]"),
    ("cleanup completed",      r"\[INFO\] VPN cleanup completed"),
]

UNEXPECTED = [
    ("ioctl error",            r"Inappropriate ioctl for device"),
    ("login failed",           r"\[ERROR\] Login failed"),
    ("password expired",       r"PASSWORD EXPIRED"),
]


def strip_ansi(text):
    return re.sub(r'\x1b\[[0-9;]*m', '', text)


def run():
    print(f"Running VPN connection test (hold for {HOLD_SECONDS}s) ...")
    print(f"Log: {LOG_FILE}\n")

    subprocess.run(
        ["script", "-q", "-e", "-c",
         f"timeout {HOLD_SECONDS} python3 {SCRIPT}",
         str(LOG_FILE)],
        capture_output=True,
        text=True,
    )

    raw = LOG_FILE.read_text(errors="replace")
    output = strip_ansi(raw)

    print("--- captured output ---")
    print(output)
    print("--- end output ---\n")

    failures = []

    for label, pattern in EXPECTED:
        if re.search(pattern, output):
            print(f"  PASS  {label}")
        else:
            print(f"  FAIL  {label}  (pattern not found: {pattern})")
            failures.append(label)

    for label, pattern in UNEXPECTED:
        if re.search(pattern, output):
            print(f"  FAIL  {label}  (unexpected pattern found: {pattern})")
            failures.append(label)
        else:
            print(f"  PASS  no {label}")

    print()
    if failures:
        print(f"FAILED ({len(failures)} checks): {', '.join(failures)}")
        sys.exit(1)
    else:
        print("All checks passed.")


if __name__ == "__main__":
    run()
