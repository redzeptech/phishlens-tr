"""
PhishLens TR - E-posta kimlik doğrulama (SPF, DKIM, DMARC).

Gönderici domain için DNS kayıtlarını kontrol eder.
"""

from typing import Any

try:
    import dns.resolver
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False


def check_spf(domain: str) -> dict[str, Any]:
    """Domain için SPF kaydı kontrol eder."""
    result = {"ok": False, "record": None, "error": None, "score_added": 0}
    if not DNS_AVAILABLE:
        result["error"] = "dnspython yüklü değil (pip install dnspython)"
        result["score_added"] = 2
        return result
    if not domain:
        result["error"] = "Domain boş"
        result["score_added"] = 2
        return result
    try:
        answers = dns.resolver.resolve(domain, "TXT")
        for rdata in answers:
            for txt in rdata.strings:
                txt_str = txt.decode("utf-8") if isinstance(txt, bytes) else str(txt)
                if "v=spf1" in txt_str.lower():
                    result["ok"] = True
                    result["record"] = txt_str[:200]
                    return result
        result["error"] = "SPF kaydı bulunamadı"
        result["score_added"] = 3
    except dns.resolver.NXDOMAIN:
        result["error"] = "Domain mevcut değil"
        result["score_added"] = 3
    except dns.resolver.NoAnswer:
        result["error"] = "SPF kaydı yok"
        result["score_added"] = 3
    except Exception as e:
        result["error"] = str(e)
        result["score_added"] = 2
    return result


def check_dmarc(domain: str) -> dict[str, Any]:
    """Domain için DMARC kaydı kontrol eder."""
    result = {"ok": False, "record": None, "error": None, "score_added": 0}
    if not DNS_AVAILABLE:
        result["error"] = "dnspython yüklü değil"
        result["score_added"] = 2
        return result
    if not domain:
        result["error"] = "Domain boş"
        result["score_added"] = 2
        return result
    dmarc_domain = f"_dmarc.{domain}"
    try:
        answers = dns.resolver.resolve(dmarc_domain, "TXT")
        for rdata in answers:
            for txt in rdata.strings:
                txt_str = txt.decode("utf-8") if isinstance(txt, bytes) else str(txt)
                if "DMARC1" in txt_str or "dmarc" in txt_str.lower():
                    result["ok"] = True
                    result["record"] = txt_str[:200]
                    return result
        result["error"] = "DMARC kaydı geçersiz"
        result["score_added"] = 2
    except dns.resolver.NXDOMAIN:
        result["error"] = "DMARC kaydı yok"
        result["score_added"] = 3
    except dns.resolver.NoAnswer:
        result["error"] = "DMARC kaydı yok"
        result["score_added"] = 3
    except Exception as e:
        result["error"] = str(e)
        result["score_added"] = 2
    return result


def analyze_email_auth(eml_data: dict) -> dict[str, Any]:
    """Eml verisi için SPF/DKIM/DMARC analizi yapar."""
    domain = eml_data.get("sender_domain")
    has_dkim = eml_data.get("has_dkim", False)

    spf = check_spf(domain) if domain else {"ok": False, "score_added": 3}
    dmarc = check_dmarc(domain) if domain else {"ok": False, "score_added": 3}

    score_added = spf.get("score_added", 0) + dmarc.get("score_added", 0)
    if not has_dkim:
        score_added += 1

    details = []
    if not spf.get("ok"):
        details.append(f"SPF: {spf.get('error', 'Hatalı')}")
    if not dmarc.get("ok"):
        details.append(f"DMARC: {dmarc.get('error', 'Hatalı')}")
    if not has_dkim:
        details.append("DKIM: İmza yok")

    return {
        "spf": spf,
        "dmarc": dmarc,
        "dkim_present": has_dkim,
        "sender_ip": eml_data.get("sender_ip"),
        "sender_domain": domain,
        "score_added": score_added,
        "details": details,
    }
