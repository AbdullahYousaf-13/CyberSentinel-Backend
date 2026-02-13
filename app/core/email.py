import logging
import smtplib
from email.message import EmailMessage

from app.core.config import Settings

logger = logging.getLogger(__name__)


def send_email(settings: Settings, to_email: str, subject: str, body: str) -> None:
    if not settings.smtp_host:
        logger.info(
            "SMTP not configured. Email to %s with subject '%s':\n%s",
            to_email,
            subject,
            body,
        )
        return

    message = EmailMessage()
    message["From"] = settings.email_from
    message["To"] = to_email
    message["Subject"] = subject
    message.set_content(body)

    if settings.smtp_use_ssl:
        smtp_client = smtplib.SMTP_SSL(settings.smtp_host, settings.smtp_port)
    else:
        smtp_client = smtplib.SMTP(settings.smtp_host, settings.smtp_port)

    try:
        if settings.smtp_use_tls and not settings.smtp_use_ssl:
            smtp_client.starttls()
        if settings.smtp_user and settings.smtp_password:
            smtp_client.login(settings.smtp_user, settings.smtp_password)
        smtp_client.send_message(message)
    finally:
        smtp_client.quit()
