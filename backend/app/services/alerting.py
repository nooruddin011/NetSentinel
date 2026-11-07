"""Email alerts (optional). Disabled unless SMTP_HOST and ALERT_EMAIL_TO are configured."""
from __future__ import annotations

import logging
import smtplib
import threading
from email.message import EmailMessage

from app.branding import APP_NAME
from app.models.attacks import SEVERITY_ORDER

log = logging.getLogger(__name__)


def _clean(value) -> str:
    return str(value).replace("\r", " ").replace("\n", " ")[:200]  # no header injection


class EmailNotifier:
    def __init__(self, settings, send_fn=None):
        self.s = settings
        self._send_fn = send_fn or self._smtp_send

    @property
    def enabled(self) -> bool:
        return bool(self.s.smtp_host and self.s.alert_email_to)

    def _qualifies(self, severity: str) -> bool:
        order = {s: i for i, s in enumerate(SEVERITY_ORDER)}
        return order.get(severity, 0) >= order.get(self.s.alert_email_min_severity, 2)

    def build(self, alert: dict) -> EmailMessage:
        msg = EmailMessage()
        msg["Subject"] = _clean(f"[{APP_NAME}] {alert['severity']} {alert['attack_type']} from {alert.get('src_ip')}")
        msg["From"] = _clean(self.s.alert_email_from)
        msg["To"] = ", ".join(_clean(a) for a in self.s.alert_email_to)
        msg.set_content(
            f"Severity: {alert['severity']} (risk {alert.get('risk_score')})\nAttack: {alert['attack_type']}\n"
            f"Source: {alert.get('src_ip')}  ->  Target: {alert.get('dst_ip')}\n"
            f"Confidence: {round(100 * float(alert.get('confidence', 0)), 1)}%\n"
            f"Detected by: {', '.join(alert.get('sources', []))}\n\nOpen the {APP_NAME} dashboard to review and mitigate.")
        return msg

    def _smtp_send(self, msg: EmailMessage):
        with smtplib.SMTP(self.s.smtp_host, self.s.smtp_port, timeout=10) as smtp:
            if self.s.smtp_use_tls:
                smtp.starttls()
            if self.s.smtp_user:
                smtp.login(self.s.smtp_user, self.s.smtp_password)
            smtp.send_message(msg)

    def notify(self, alert: dict, blocking: bool = False) -> bool:
        if not self.enabled or not self._qualifies(alert.get("severity", "")):
            return False
        msg = self.build(alert)

        def _run():
            try:
                self._send_fn(msg)
            except Exception as exc:  # never let an SMTP problem affect detection
                log.warning("Alert email failed: %s", exc)

        if blocking:
            _run()
        else:
            threading.Thread(target=_run, daemon=True).start()
        return True
