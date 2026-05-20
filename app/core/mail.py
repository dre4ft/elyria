# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Elyria

"""
Mail service abstraction — placeholder implementation.

To plug a real mail provider (SendGrid, Mailgun, SMTP, etc.), replace the
send_verification_code() implementation below.

Usage:
    from core.mail import send_verification_code
    success = send_verification_code(email="user@example.com", code="A1B2C3D4")
"""

from core.logging import get_logger
from core.audit import info as audit_info

logger = get_logger(__name__)


def send_verification_code(email: str, code: str) -> bool:
    """
    Send a verification code to the given email address.

    PLACEHOLDER: logs the code to the audit log and returns True.
    Replace with actual mail provider integration (SMTP, SendGrid, etc.)
    """
    logger.info(f"[MAIL PLACEHOLDER] Verification code for {email}: {code}")
    audit_info("mail.verification_code", email=email, code=code)
    return True
