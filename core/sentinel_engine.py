import json
import logging
import os
from core.file_scanner import load_yara_rules, scan_file
from core.entropy_check import check_high_entropy, entropy_label
from core.threat_scorer import score_file


def load_settings(path="config/settings.json"):
    with open(path) as f:
        return json.load(f)


def run_analysis(mount_point):
    """
    Full USBSentinel analysis pipeline on a mounted USB.
    Returns list of file report dicts.
    """
    settings  = load_settings()
    yara_rules = load_yara_rules()
    extensions = settings.get("scan_extensions", [])

    file_reports = []
    total_files  = 0
    threats      = 0

    logging.info(f"[ENGINE] Starting analysis on: {mount_point}")

    for root, dirs, files in os.walk(mount_point):
        dirs[:] = [d for d in dirs if not d.startswith('.')]

        for fname in files:
            fpath = os.path.join(root, fname)

            # Extension filter
            if extensions:
                if not any(fname.lower().endswith(ext) for ext in extensions):
                    continue

            total_files += 1

            # Run all checks
            scan         = scan_file(fpath, yara_rules)
            entropy_flag, entropy_val = check_high_entropy(fpath)
            score, verdict, reasons  = score_file(scan, entropy_flag, entropy_val)

            report = {
                "path":         fpath,
                "filename":     fname,
                "hash":         scan["hash"],
                "yara_hits":    scan["yara_hits"],
                "entropy":      entropy_val,
                "entropy_label": entropy_label(entropy_val),
                "score":        score,
                "verdict":      verdict,
                "reasons":      reasons,
                "scan_error":   scan.get("scan_error")
            }

            file_reports.append(report)

            if verdict in ("SUSPICIOUS", "MALICIOUS"):
                threats += 1

            logging.info(
                f"[ENGINE] {verdict} | score={score} | {fname}"
            )

    logging.info(
        f"[ENGINE] Analysis complete. "
        f"Files scanned: {total_files} | Threats found: {threats}"
    )

    return file_reports
