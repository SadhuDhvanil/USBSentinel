import subprocess
import logging
import os


def send_notification(title, message, urgency="critical"):
    """
    Send desktop notification via libnotify.
    urgency: low | normal | critical
    """
    try:
        # Try notify-send (requires a desktop session)
        subprocess.run([
            "notify-send",
            f"--urgency={urgency}",
            "--icon=dialog-warning",
            f"USBSentinel — {title}",
            message
        ], check=False, capture_output=True)
    except FileNotFoundError:
        pass  # notify-send not available, fallback to terminal
    except Exception as e:
        logging.debug(f"[NOTIFY] Desktop notification failed: {e}")

    # Always print to terminal regardless
    terminal_alert(title, message, urgency)


def terminal_alert(title, message, urgency="normal"):
    """Colorized terminal output."""
    colors = {
        "critical": "\033[91m",   # red
        "normal":   "\033[93m",   # yellow
        "low":      "\033[92m",   # green
    }
    reset = "\033[0m"
    color = colors.get(urgency, "\033[93m")

    border = "=" * 55
    print(f"\n{color}{border}")
    print(f"  USBSentinel | {title}")
    print(f"  {message}")
    print(f"{border}{reset}\n")


def log_event(message, level="info"):
    """Log to audit log."""
    getattr(logging, level, logging.info)(f"[EVENT] {message}")
