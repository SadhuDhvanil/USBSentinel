import os
import hashlib
import logging

try:
    import yara
    YARA_AVAILABLE = True
except ImportError:
    YARA_AVAILABLE = False
    logging.warning("[SCANNER] yara-python not available")

# Known malicious SHA256 hashes (extend this list or load from a file)
KNOWN_BAD_HASHES = {
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",  # example
}


def load_yara_rules(rules_path="rules/malware.yar"):
    if not YARA_AVAILABLE:
        return None
    try:
        rules = yara.compile(filepath=rules_path)
        logging.info("[SCANNER] YARA rules loaded successfully")
        return rules
    except Exception as e:
        logging.error(f"[SCANNER] YARA compile error: {e}")
        return None


def hash_file(path):
    """Return SHA256 hash of a file."""
    sha256 = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                sha256.update(chunk)
        return sha256.hexdigest()
    except PermissionError:
        logging.warning(f"[SCANNER] Permission denied: {path}")
        return None
    except Exception as e:
        logging.error(f"[SCANNER] Hash error for {path}: {e}")
        return None


def scan_file(path, yara_rules):
    """
    Scan a single file.
    Returns dict with hash, yara hits, and known-bad flag.
    """
    result = {
        "path": path,
        "hash": None,
        "yara_hits": [],
        "hash_known_bad": False,
        "scan_error": None
    }

    # Hash check
    result["hash"] = hash_file(path)
    if result["hash"] and result["hash"] in KNOWN_BAD_HASHES:
        result["hash_known_bad"] = True
        logging.warning(f"[SCANNER] Known bad hash: {path}")

    # YARA scan
    if yara_rules:
        try:
            matches = yara_rules.match(path, timeout=30)
            result["yara_hits"] = [
                {"rule": m.rule, "tags": m.tags} for m in matches
            ]
            if result["yara_hits"]:
                logging.warning(
                    f"[SCANNER] YARA hit on {path}: "
                    f"{[h['rule'] for h in result['yara_hits']]}"
                )
        except yara.TimeoutError:
            result["scan_error"] = "YARA timeout"
        except Exception as e:
            result["scan_error"] = str(e)
            logging.debug(f"[SCANNER] YARA error on {path}: {e}")

    return result


def scan_directory(mount_point, yara_rules, extensions=None):
    """
    Walk an entire USB mount point and scan every file.
    Returns list of scan results.
    """
    results = []
    total = 0
    skipped = 0

    for root, dirs, files in os.walk(mount_point):
        # Skip hidden system directories
        dirs[:] = [d for d in dirs if not d.startswith('.')]

        for fname in files:
            fpath = os.path.join(root, fname)

            # Extension filter
            if extensions:
                if not any(fname.lower().endswith(ext) for ext in extensions):
                    skipped += 1
                    continue

            total += 1
            result = scan_file(fpath, yara_rules)
            results.append(result)

    logging.info(f"[SCANNER] Scanned {total} files, skipped {skipped} (extension filter)")
    return results
