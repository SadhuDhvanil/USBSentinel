#!/usr/bin/env python3
"""
USBSentinel Monitor — main daemon
Listens for udev USB block device events.
On plug-in: fingerprints device, checks policy,
runs full analysis, quarantines threats, notifies user.
"""

import pyudev
import logging
import os
import sys
import json
import time

# Make sure we can import from project root
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.device_fingerprint import get_device_info, fingerprint_summary, resolve_mount
from core.policy_enforcer import check_policy, block_device
from core.sentinel_engine import run_analysis
from quarantine.quarantine_manager import quarantine_file
from notifier.notify import send_notification, terminal_alert


def load_settings(path="config/settings.json"):
    with open(path) as f:
        return json.load(f)


def setup_logging(log_path):
    os.makedirs(os.path.dirname(log_path), exist_ok=True)
    logging.basicConfig(
        filename=log_path,
        level=logging.INFO,
        format="%(asctime)s | %(levelname)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )
    # Also log to console
    console = logging.StreamHandler()
    console.setLevel(logging.INFO)
    console.setFormatter(logging.Formatter("%(asctime)s | %(levelname)s | %(message)s"))
    logging.getLogger().addHandler(console)


def handle_device(device):
    """Called by udev observer on every block device event."""
    if device.action != "add":
        return

    # Only care about partitions or disks (not loop/dm devices)
    devtype = device.get("DEVTYPE", "")
    devnode = device.device_node or ""

    if devtype not in ("partition", "disk"):
        return
    if not devnode.startswith("/dev/sd") and not devnode.startswith("/dev/vd"):
        return

    settings = load_settings()
    info     = get_device_info(device)

    logging.info(f"[MONITOR] USB event detected: {fingerprint_summary(info)}")
    terminal_alert(
        "USB Device Detected",
        fingerprint_summary(info),
        urgency="normal"
    )

    # ── Policy check ────────────────────────────────────────────
    policy = check_policy(info)

    if policy == "blocked":
        block_device(info["devnode"])
        send_notification(
            "USB BLOCKED",
            f"Device VID={info['vendor_id']} PID={info['product_id']} "
            f"is on the blocklist. Ejected automatically.",
            urgency="critical"
        )
        return

    if policy == "allowed":
        send_notification(
            "USB Allowed",
            f"Known safe device connected: {info['label']}",
            urgency="low"
        )
        logging.info(f"[MONITOR] Known device allowed: {fingerprint_summary(info)}")
        return

    # ── Unknown device — scan it ─────────────────────────────────
    send_notification(
        "Unknown USB — Scanning",
        "USBSentinel is analysing the device. Please wait...",
        urgency="normal"
    )

    # Wait for mount point to resolve
    mount = info.get("mount_point")
    if not mount or not os.path.isdir(mount):
        logging.info("[MONITOR] Waiting for mount point...")
        mount = resolve_mount(info["devnode"], retries=10, delay=2)
        info["mount_point"] = mount

    if not mount or not os.path.isdir(mount):
        logging.warning(
            f"[MONITOR] Could not resolve mount for {info['devnode']}. "
            f"Skipping file scan."
        )
        send_notification(
            "Scan Skipped",
            "Could not access USB filesystem. Device may be unformatted.",
            urgency="normal"
        )
        return

    logging.info(f"[MONITOR] Mount point resolved: {mount}")

    # ── Run full analysis ────────────────────────────────────────
    file_reports    = run_analysis(mount)
    quarantine_store = settings["quarantine_path"]
    threats_found   = []

    for report in file_reports:
        if report["verdict"] in ("SUSPICIOUS", "MALICIOUS"):
            dest = quarantine_file(
                src_path        = report["path"],
                quarantine_store = quarantine_store,
                reason          = " | ".join(report["reasons"]),
                file_hash       = report["hash"],
                verdict         = report["verdict"],
                score           = report["score"]
            )
            if dest:
                threats_found.append({
                    "filename": report["filename"],
                    "verdict":  report["verdict"],
                    "score":    report["score"],
                    "dest":     dest
                })

    # ── Notify result ────────────────────────────────────────────
    if threats_found:
        summary = "\n".join(
            f"  • {t['filename']} [{t['verdict']}] score={t['score']}"
            for t in threats_found
        )
        send_notification(
            f"{len(threats_found)} Threat(s) Quarantined",
            f"{summary}\n\nRun: python3 dashboard/sentinel_cli.py to review",
            urgency="critical"
        )
        logging.warning(
            f"[MONITOR] Scan complete. {len(threats_found)} threat(s) quarantined."
        )
    else:
        send_notification(
            "USB is Clean",
            f"Scanned {len(file_reports)} file(s). No threats detected.",
            urgency="low"
        )
        logging.info(
            f"[MONITOR] Scan complete. "
            f"{len(file_reports)} file(s) scanned. No threats."
        )


def main():
    settings = load_settings()
    setup_logging(settings["log_path"])

    terminal_alert(
        "USBSentinel Started",
        "Monitoring USB ports. Plug in a device to trigger analysis.",
        urgency="low"
    )
    logging.info("[MONITOR] USBSentinel daemon started")

    context  = pyudev.Context()
    monitor  = pyudev.Monitor.from_netlink(context)
    monitor.filter_by(subsystem="block")
    observer = pyudev.MonitorObserver(monitor, callback=handle_device)
    observer.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
        terminal_alert("USBSentinel Stopped", "Monitoring ended by user.", urgency="low")
        logging.info("[MONITOR] USBSentinel stopped by user")


if __name__ == "__main__":
    main()
