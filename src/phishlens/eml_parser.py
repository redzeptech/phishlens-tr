"""
PhishLens TR - .eml dosya ayrıştırıcı.

E-posta dosyasından metin, gönderici ve IP bilgisi çıkarır.
"""

import re
from email import policy
from email.parser import BytesParser
from email.utils import parseaddr


def parse_eml(content: bytes) -> dict:
    """Eml içeriğini ayrıştırır."""
    msg = BytesParser(policy=policy.default).parsebytes(content)

    body = _extract_body(msg)
    subject = msg.get("Subject", "") or ""
    from_header = msg.get("From", "") or ""

    sender_email, sender_domain = _parse_sender(from_header)
    received_ips = _extract_received_ips(msg)
    sender_ip = received_ips[0] if received_ips else None
    has_dkim = "DKIM-Signature" in msg or "dkim-signature" in str(msg.keys()).lower()

    return {
        "body": body,
        "subject": subject,
        "sender_email": sender_email,
        "sender_domain": sender_domain,
        "sender_ip": sender_ip,
        "received_ips": received_ips,
        "has_dkim": has_dkim,
        "from_header": from_header,
    }


def _extract_body(msg) -> str:
    body_parts = []
    if msg.is_multipart():
        for part in msg.walk():
            ctype = part.get_content_type()
            if ctype == "text/plain":
                try:
                    payload = part.get_content()
                    body_parts.append(payload if isinstance(payload, str) else str(payload))
                except Exception:
                    pass
            elif ctype == "text/html" and not body_parts:
                try:
                    payload = part.get_content()
                    body_parts.append(_strip_html(payload) if isinstance(payload, str) else _strip_html(str(payload)))
                except Exception:
                    pass
    else:
        try:
            payload = msg.get_content()
            if isinstance(payload, str):
                body_parts.append(
                    _strip_html(payload) if "text/html" in msg.get_content_type() else payload
                )
            else:
                body_parts.append(str(payload))
        except Exception:
            pass
    return "\n".join(body_parts) if body_parts else ""


def _strip_html(html: str) -> str:
    return re.sub(r"<[^>]+>", " ", html).replace("&nbsp;", " ")


def _parse_sender(from_header: str) -> tuple[str | None, str | None]:
    _, addr = parseaddr(from_header)
    if not addr or "@" not in addr:
        return None, None
    email = addr.strip().lower()
    domain = email.split("@")[-1] if "@" in email else None
    return email, domain


def _extract_received_ips(msg) -> list[str]:
    ips = []
    ip_pattern = re.compile(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b")
    for received in msg.get_all("Received", []) or []:
        if isinstance(received, str):
            found = ip_pattern.findall(received)
            for ip in found:
                if ip not in ips:
                    ips.append(ip)
    return ips
