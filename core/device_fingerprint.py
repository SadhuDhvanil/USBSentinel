import subprocess
import os
import time
import logging


def get_device_info(device):
    """
    Extract VendorID, ProductID, Serial, label and mount point
    from a udev device object.
    """
    info = {
        "vendor_id":   device.get("ID_VENDOR_ID", "unknown"),
        "product_id":  device.get("ID_MODEL_ID", "unknown"),
        "serial":      device.get("ID_SERIAL_SHORT", "unknown"),
        "label":       device.get("ID_FS_LABEL", "no-label"),
        "devnode":     device.device_node or "",
        "devtype":     device.get("DEVTYPE", ""),
        "mount_point": None
    }
    info["mount_point"] = resolve_mount(info["devnode"])
    return info


def resolve_mount(devnode, retries=8, delay=1.5):
    """
    Try to find the mount point of a device node.
    Retries several times because mounting takes a moment after plug-in.
    """
    if not devnode:
        return None

    for attempt in range(retries):
        # Method 1: check /proc/mounts directly
        try:
            with open("/proc/mounts") as f:
                for line in f:
                    parts = line.split()
                    if len(parts) >= 2 and parts[0] == devnode:
                        return parts[1]
        except Exception:
            pass

        # Method 2: udisksctl
        try:
            out = subprocess.check_output(
                ["udisksctl", "info", "-b", devnode],
                stderr=subprocess.DEVNULL
            ).decode()
            for line in out.splitlines():
                if "MountPoints" in line:
                    mp = line.split(":", 1)[-1].strip()
                    if mp and os.path.isdir(mp):
                        return mp
        except Exception:
            pass

        # Method 3: lsblk
        try:
            out = subprocess.check_output(
                ["lsblk", "-o", "NAME,MOUNTPOINT", "-J"],
                stderr=subprocess.DEVNULL
            ).decode()
            import json
            data = json.loads(out)
            devname = os.path.basename(devnode)
            for bd in data.get("blockdevices", []):
                if bd.get("name") == devname and bd.get("mountpoint"):
                    return bd["mountpoint"]
                for child in bd.get("children", []):
                    if child.get("name") == devname and child.get("mountpoint"):
                        return child["mountpoint"]
        except Exception:
            pass

        logging.debug(f"Mount not found yet for {devnode}, attempt {attempt+1}/{retries}")
        time.sleep(delay)

    return None


def fingerprint_summary(info):
    """Return a readable one-line summary of the device."""
    return (
        f"VID={info['vendor_id']} PID={info['product_id']} "
        f"Serial={info['serial']} Label={info['label']} "
        f"Node={info['devnode']} Mount={info['mount_point']}"
    )
