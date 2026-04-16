import math
import os
import logging


def file_entropy(path):
    """
    Calculate Shannon entropy of a file.
    Scale: 0 (perfectly uniform) to 8 (maximum randomness).
    Values above 7.2 typically indicate packed, encrypted,
    or compressed content — common in malware.
    """
    try:
        with open(path, "rb") as f:
            data = f.read()

        if not data:
            return 0.0

        # Count byte frequency
        freq = [0] * 256
        for byte in data:
            freq[byte] += 1

        length = len(data)
        entropy = 0.0
        for count in freq:
            if count > 0:
                p = count / length
                entropy -= p * math.log2(p)

        return round(entropy, 4)

    except PermissionError:
        logging.warning(f"[ENTROPY] Permission denied: {path}")
        return 0.0
    except Exception as e:
        logging.error(f"[ENTROPY] Error reading {path}: {e}")
        return 0.0


def check_high_entropy(path, threshold=7.2):
    """Returns True if file entropy exceeds threshold."""
    entropy = file_entropy(path)
    if entropy >= threshold:
        logging.warning(
            f"[ENTROPY] High entropy detected: {path} "
            f"(entropy={entropy}, threshold={threshold})"
        )
        return True, entropy
    return False, entropy


def entropy_label(entropy_value):
    """Return a human-readable label for an entropy value."""
    if entropy_value >= 7.5:
        return "VERY HIGH — likely encrypted/packed"
    elif entropy_value >= 7.2:
        return "HIGH — possibly obfuscated"
    elif entropy_value >= 6.0:
        return "MODERATE — compressed data"
    else:
        return "NORMAL"
