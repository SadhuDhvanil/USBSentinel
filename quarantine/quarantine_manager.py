import os
import shutil
import json
import logging
from datetime import datetime


def quarantine_file(src_path, quarantine_store, reason, file_hash, verdict, score):
    """
    Move a suspicious/malicious file to quarantine.
    - Strips all execute permissions
    - Writes a .meta.json alongside it
    - Returns the quarantine path or None on failure
    """
    os.makedirs(quarantine_store, mode=0o700, exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    fname     = os.path.basename(src_path)
    dest      = os.path.join(quarantine_store, f"{timestamp}_{fname}")
    meta_path = dest + ".meta.json"

    try:
        shutil.move(src_path, dest)

        # Strip all execute permissions, owner read/write only
        os.chmod(dest, 0o600)

        meta = {
            "original_path":    src_path,
            "quarantine_path":  dest,
            "filename":         fname,
            "hash":             file_hash,
            "verdict":          verdict,
            "score":            score,
            "reason":           reason,
            "timestamp":        timestamp,
            "status":           "quarantined"
            # status can be updated to: allowed / denied
        }

        with open(meta_path, "w") as f:
            json.dump(meta, f, indent=2)

        logging.warning(
            f"[QUARANTINE] {fname} moved to quarantine | "
            f"verdict={verdict} score={score}"
        )
        return dest

    except Exception as e:
        logging.error(f"[QUARANTINE] Failed to quarantine {src_path}: {e}")
        return None


def list_quarantine(quarantine_store):
    """Return list of all quarantine metadata records."""
    items = []
    if not os.path.isdir(quarantine_store):
        return items
    for fname in sorted(os.listdir(quarantine_store)):
        if fname.endswith(".meta.json"):
            fpath = os.path.join(quarantine_store, fname)
            try:
                with open(fpath) as f:
                    items.append(json.load(f))
            except Exception:
                pass
    return items


def update_status(quarantine_path, new_status):
    """Update the status field in a quarantine metadata file."""
    meta_path = quarantine_path + ".meta.json"
    try:
        with open(meta_path) as f:
            meta = json.load(f)
        meta["status"]          = new_status
        meta["decision_time"]   = datetime.now().strftime("%Y%m%d_%H%M%S")
        with open(meta_path, "w") as f:
            json.dump(meta, f, indent=2)
        logging.info(f"[QUARANTINE] Status updated to '{new_status}' for {meta['filename']}")
        return True
    except Exception as e:
        logging.error(f"[QUARANTINE] Status update failed: {e}")
        return False


def delete_from_quarantine(quarantine_path):
    """Permanently delete a quarantined file and its metadata."""
    meta_path = quarantine_path + ".meta.json"
    try:
        if os.path.exists(quarantine_path):
            os.remove(quarantine_path)
        if os.path.exists(meta_path):
            os.remove(meta_path)
        logging.info(f"[QUARANTINE] Permanently deleted: {quarantine_path}")
        return True
    except Exception as e:
        logging.error(f"[QUARANTINE] Delete failed: {e}")
        return False
