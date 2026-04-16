import logging


def score_file(scan_result, entropy_flag, entropy_value=0.0, clamav_hit=False):
    """
    Calculate a risk score (0-100) based on multiple signals.

    Scoring weights:
    - Known bad hash:     +60
    - Each YARA hit:      +25 (max 2 hits counted = +50)
    - High entropy:       +20
    - ClamAV detection:   +50
    - Suspicious ext:     +10

    Verdict thresholds (from settings.json):
    - CLEAN:      score < 40
    - SUSPICIOUS: score 40-69
    - MALICIOUS:  score >= 70
    """
    score = 0
    reasons = []

    if scan_result.get("hash_known_bad"):
        score += 60
        reasons.append("known malicious hash")

    yara_hits = scan_result.get("yara_hits", [])
    if yara_hits:
        hit_score = min(len(yara_hits), 2) * 25
        score += hit_score
        reasons.append(f"YARA rules matched: {[h['rule'] for h in yara_hits]}")

    if entropy_flag:
        score += 20
        reasons.append(f"high entropy ({entropy_value})")

    if clamav_hit:
        score += 50
        reasons.append("ClamAV signature match")

    # Cap at 100
    score = min(score, 100)

    # Verdict
    if score >= 70:
        verdict = "MALICIOUS"
    elif score >= 40:
        verdict = "SUSPICIOUS"
    else:
        verdict = "CLEAN"

    if verdict != "CLEAN":
        logging.warning(
            f"[SCORER] {verdict} | score={score} | "
            f"file={scan_result.get('path', '?')} | reasons={reasons}"
        )

    return score, verdict, reasons
