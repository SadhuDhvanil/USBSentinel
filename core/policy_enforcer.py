import json
import subprocess
import logging
import os


def load_json(path):
    with open(path) as f:
        return json.load(f)


def check_policy(device_info, config_dir="config"):
    """
    Compare device against allowlist and blocklist.
    Returns: 'allowed' | 'blocked' | 'unknown'
    """
    allowlist = load_json(os.path.join(config_dir, "allowlist.json"))["devices"]
    blocklist = load_json(os.path.join(config_dir, "blocklist.json"))["devices"]

    vid    = device_info["vendor_id"]
    pid    = device_info["product_id"]
    serial = device_info["serial"]

    # Check blocklist first
    for entry in blocklist:
        if entry["vendor_id"] == vid and entry["product_id"] == pid:
            logging.warning(f"[POLICY] Device on BLOCKLIST: {vid}:{pid}")
            return "blocked"

    # Check allowlist
    for entry in allowlist:
        if entry["vendor_id"] == vid and entry["product_id"] == pid:
            # If a serial is specified, it must match
            if "serial" not in entry or entry["serial"] == serial:
                logging.info(f"[POLICY] Device on ALLOWLIST: {vid}:{pid}")
                return "allowed"

    logging.info(f"[POLICY] Device UNKNOWN: {vid}:{pid}")
    return "unknown"


def block_device(devnode):
    """Unmount and power off the USB device."""
    try:
        subprocess.run(
            ["udisksctl", "unmount", "-b", devnode],
            check=False, capture_output=True
        )
        subprocess.run(
            ["udisksctl", "power-off", "-b", devnode],
            check=False, capture_output=True
        )
        logging.warning(f"[ENFORCER] Device blocked and ejected: {devnode}")
        return True
    except Exception as e:
        logging.error(f"[ENFORCER] Block failed for {devnode}: {e}")
        return False


def add_to_allowlist(device_info, config_dir="config"):
    """Add a device to the allowlist."""
    path = os.path.join(config_dir, "allowlist.json")
    data = load_json(path)
    entry = {
        "vendor_id":  device_info["vendor_id"],
        "product_id": device_info["product_id"],
        "serial":     device_info["serial"],
        "label":      device_info.get("label", "")
    }
    data["devices"].append(entry)
    with open(path, "w") as f:
        json.dump(data, f, indent=2)
    logging.info(f"[POLICY] Added to allowlist: {entry}")


def add_to_blocklist(device_info, config_dir="config"):
    """Add a device to the blocklist."""
    path = os.path.join(config_dir, "blocklist.json")
    data = load_json(path)
    entry = {
        "vendor_id":  device_info["vendor_id"],
        "product_id": device_info["product_id"],
        "label":      device_info.get("label", "")
    }
    data["devices"].append(entry)
    with open(path, "w") as f:
        json.dump(data, f, indent=2)
    logging.info(f"[POLICY] Added to blocklist: {entry}")
