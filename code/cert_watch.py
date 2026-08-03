#!/usr/bin/env python3
import os
import socket
import ssl
import smtplib
from dataclasses import dataclass
from datetime import datetime, timezone
from email.message import EmailMessage
from typing import Optional, List

import requests


@dataclass
class Target:
    name: str           # label for alerts
    host: str           # IP or DNS
    port: int = 443
    sni: Optional[str] = None  # hostname for IIS/SNI bindings (recommended)


def fetch_cert_expiry_utc(host: str, port: int, sni: Optional[str]) -> datetime:
    """
    Connect via TLS and return the expiry time (UTC) of the presented certificate.
    """
    ctx = ssl.create_default_context()
    server_name = sni or host  # SNI if provided, else host

    with socket.create_connection((host, port), timeout=10) as sock:
        with ctx.wrap_socket(sock, server_hostname=server_name) as ssock:
            cert = ssock.getpeercert()
            not_after = cert["notAfter"]  # e.g. 'Jun 12 23:59:59 2026 GMT'
            dt = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
            return dt.replace(tzinfo=timezone.utc)


def days_left(expiry_utc: datetime) -> int:
    now = datetime.now(timezone.utc)
    return int((expiry_utc - now).total_seconds() // 86400)


def format_report(findings: list[dict]) -> str:
    lines = ["Certificate Expiry Report", ""]
    for f in findings:
        if f["status"] == "OK":
            lines.append(f'✅ {f["name"]}: {f["days_left"]} days left (exp {f["expiry"]}) [{f["endpoint"]}]')
        else:
            lines.append(f'❌ {f["name"]}: {f["error"]} [{f["endpoint"]}]')
    return "\n".join(lines)


def send_email(subject: str, body: str) -> None:
    """
    Env vars required:
      SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASS, EMAIL_FROM, EMAIL_TO
    """
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = os.environ["EMAIL_FROM"]
    msg["To"] = os.environ["EMAIL_TO"]
    msg.set_content(body)

    host = os.environ["SMTP_HOST"]
    port = int(os.environ.get("SMTP_PORT", "587"))
    user = os.environ.get("SMTP_USER")
    pwd = os.environ.get("SMTP_PASS")

    with smtplib.SMTP(host, port, timeout=20) as s:
        s.starttls()
        if user and pwd:
            s.login(user, pwd)
        s.send_message(msg)


def send_webex_incoming_webhook(body_markdown: str) -> None:
    """
    Uses a Webex 'Incoming Webhook' URL (easiest).
    Env var required: WEBEX_WEBHOOK_URL
    Payload can be 'text' or 'markdown'.  :contentReference[oaicite:0]{index=0}
    """
    url = os.environ["WEBEX_WEBHOOK_URL"]
    r = requests.post(url, json={"markdown": body_markdown}, timeout=20)
    r.raise_for_status()


def send_webex_messages_api(body_markdown: str) -> None:
    """
    Uses Webex Messages API (bot token / user token).
    Env vars required: WEBEX_ACCESS_TOKEN, WEBEX_ROOM_ID
    API docs: create message endpoint. :contentReference[oaicite:1]{index=1}
    """
    token = os.environ["WEBEX_ACCESS_TOKEN"]
    room_id = os.environ["WEBEX_ROOM_ID"]
    r = requests.post(
        "https://webexapis.com/v1/messages",
        headers={"Authorization": f"Bearer {token}"},
        json={"roomId": room_id, "markdown": body_markdown},
        timeout=20,
    )
    r.raise_for_status()


def main(targets: List[Target], warn_days: int = 30) -> int:
    findings = []
    alert_needed = False

    for t in targets:
        endpoint = f"{t.host}:{t.port}" + (f" (SNI {t.sni})" if t.sni else "")
        try:
            expiry = fetch_cert_expiry_utc(t.host, t.port, t.sni)
            left = days_left(expiry)
            status = "OK"
            if left <= warn_days:
                alert_needed = True
                status = "WARN"
            findings.append(
                {
                    "name": t.name,
                    "endpoint": endpoint,
                    "status": "OK" if status == "OK" else "OK",  # keep emoji formatting simple
                    "days_left": left,
                    "expiry": expiry.isoformat(),
                }
            )
            if status == "WARN":
                # mark as alert-worthy
                findings[-1]["status"] = "WARN"
        except Exception as e:
            alert_needed = True
            findings.append({"name": t.name, "endpoint": endpoint, "status": "ERR", "error": str(e)})

    # Build message
    # Separate WARN/ERR from OK for readability
    ordered = []
    for f in findings:
        if f.get("status") in ("WARN", "ERR"):
            ordered.append(f)
    for f in findings:
        if f.get("status") == "OK":
            ordered.append(f)

    report = format_report(ordered)

    # If you want always-notify, set ALWAYS_NOTIFY=1
    always = os.environ.get("ALWAYS_NOTIFY", "0") == "1"
    if alert_needed or always:
        subject = f"[CERT] Alerts (threshold {warn_days}d)"
        # Choose notifier(s)
        if os.environ.get("EMAIL_TO"):
            send_email(subject, report)
        if os.environ.get("WEBEX_WEBHOOK_URL"):
            send_webex_incoming_webhook("**" + subject + "**\n\n" + report.replace("\n", "\n"))
        elif os.environ.get("WEBEX_ACCESS_TOKEN") and os.environ.get("WEBEX_ROOM_ID"):
            send_webex_messages_api("**" + subject + "**\n\n" + report.replace("\n", "\n"))
        print(report)
        return 2

    print("All certs OK.")
    return 0


if __name__ == "__main__":
    # Add SNI hostnames for IIS bindings whenever possible.
    TARGETS = [
        # environment 1
        Target("e1 (server-ip) - description", "server-ip", port-number, sni=None)

        # environment 2
        Target("e2 (server-ip) - description", "server-ip", port-number, sni=None)

        # environment 3
        Target("e3 (server-ip) - description", "server-ip", port-number, sni=None)
    ]

    raise SystemExit(main(TARGETS, warn_days=int(os.environ.get("WARN_DAYS", "30"))))
