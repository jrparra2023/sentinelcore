"""
SentinelCore — notifications/notifier.py
Sends desktop and/or email notifications when alerts fire.

Desktop: uses `notify-send` (Linux) — works on Kali with libnotify.
Email:   uses smtplib with STARTTLS (Gmail App Passwords supported).

Configuration is read from config.yaml:
  notifications:
    min_severity: "HIGH"
    desktop:
      enabled: true
    email:
      enabled: false
      smtp_host: "smtp.gmail.com"
      ...
"""

import smtplib
import subprocess
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# Severity order for threshold comparison
_SEV_ORDER = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}

# Urgency mapping for notify-send
_URGENCY = {"LOW": "low", "MEDIUM": "normal", "HIGH": "normal", "CRITICAL": "critical"}


def _meets_threshold(severity: str, min_severity: str) -> bool:
    return _SEV_ORDER.get(severity, 0) >= _SEV_ORDER.get(min_severity, 2)


# ── Desktop ───────────────────────────────────────────────────────────────────

def send_desktop(title: str, body: str, severity: str = "HIGH") -> bool:
    """
    Send a desktop notification via notify-send (Linux).
    Returns True if successful.
    """
    urgency = _URGENCY.get(severity, "normal")
    icon    = "dialog-warning" if severity in ("HIGH", "CRITICAL") else "dialog-information"
    try:
        subprocess.run(
            ["notify-send", "--urgency", urgency, "--icon", icon, title, body],
            check=True, capture_output=True, timeout=5,
        )
        return True
    except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
        return False


# ── Email ─────────────────────────────────────────────────────────────────────

def send_email(
    subject: str,
    body: str,
    smtp_host: str,
    smtp_port: int,
    smtp_user: str,
    smtp_password: str,
    from_addr: str,
    to_addr: str,
) -> bool:
    """
    Send an email notification via SMTP with STARTTLS.
    Returns True if successful.
    """
    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"]    = from_addr
        msg["To"]      = to_addr
        msg.attach(MIMEText(body, "plain"))

        with smtplib.SMTP(smtp_host, smtp_port, timeout=10) as server:
            server.ehlo()
            server.starttls()
            server.login(smtp_user, smtp_password)
            server.sendmail(from_addr, [to_addr], msg.as_string())
        return True
    except Exception as e:
        print(f"[Notifier] Email failed: {e}")
        return False


# ── Main dispatcher ───────────────────────────────────────────────────────────

def notify_alert(alert: dict, cfg=None) -> dict:
    """
    Send notifications for a fired alert based on config.
    alert: dict with keys rule_name, severity, description, src_ip
    cfg:   SentinelConfig (loads from config.yaml if None)

    Returns dict with notification results.
    """
    if cfg is None:
        from config import cfg as _cfg
        cfg = _cfg

    severity    = alert.get("severity", "LOW")
    rule_name   = alert.get("rule_name", "unknown")
    description = alert.get("description", "")
    src_ip      = alert.get("src_ip", "unknown")
    min_sev     = cfg.notifications.min_severity

    results = {"desktop": False, "email": False, "skipped": False}

    if not _meets_threshold(severity, min_sev):
        results["skipped"] = True
        return results

    title = f"[{severity}] SentinelCore — {rule_name.replace('_', ' ').title()}"
    body  = f"Rule   : {rule_name}\nIP     : {src_ip}\nDetail : {description}"

    # Desktop
    if cfg.notifications.desktop.enabled:
        results["desktop"] = send_desktop(title, body, severity)

    # Email
    ec = cfg.notifications.email
    if ec.enabled and ec.smtp_user and ec.smtp_password:
        results["email"] = send_email(
            subject=title,
            body=body,
            smtp_host=ec.smtp_host,
            smtp_port=ec.smtp_port,
            smtp_user=ec.smtp_user,
            smtp_password=ec.smtp_password,
            from_addr=ec.from_addr or ec.smtp_user,
            to_addr=ec.to_addr,
        )

    return results


def notify_batch(alerts: list[dict], cfg=None) -> int:
    """
    Notify for a list of alerts. Returns count of notifications sent.
    Only fires for alerts meeting the min_severity threshold.
    """
    if cfg is None:
        from config import cfg as _cfg
        cfg = _cfg

    sent = 0
    for alert in alerts:
        result = notify_alert(alert, cfg)
        if not result.get("skipped") and (result.get("desktop") or result.get("email")):
            sent += 1
    return sent
