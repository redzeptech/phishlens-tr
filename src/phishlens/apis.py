"""
PhishLens TR - Harici API entegrasyonları.

VirusTotal ve AbuseIPDB API'leri ile URL/IP tehdit analizi.
API anahtarları .env dosyasından okunur.
"""

import base64
import socket
import time
from typing import Any

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

from phishlens.rules import extract_domain

VT_MALICIOUS_SCORE = 5
VT_SUSPICIOUS_SCORE = 3
ABUSEIPDB_SCORE_PER_10 = 2


def _get_env_keys() -> dict[str, str | None]:
    from os import getenv
    try:
        from dotenv import load_dotenv
        load_dotenv()
    except ImportError:
        pass
    return {
        "virustotal": getenv("VIRUSTOTAL_API_KEY"),
        "abuseipdb": getenv("ABUSEIPDB_API_KEY"),
    }


def _resolve_domain_to_ip(domain: str) -> str | None:
    try:
        return socket.gethostbyname(domain)
    except (socket.gaierror, socket.timeout, OSError):
        return None


def check_virustotal(url: str, api_key: str | None) -> dict[str, Any]:
    """VirusTotal API v3 ile URL taraması yapar."""
    result = {
        "success": False,
        "malicious": 0,
        "suspicious": 0,
        "harmless": 0,
        "undetected": 0,
        "score_added": 0,
        "error": None,
    }
    if not REQUESTS_AVAILABLE:
        result["error"] = "requests kütüphanesi yüklü değil (pip install requests)"
        return result
    if not api_key:
        result["error"] = "VIRUSTOTAL_API_KEY .env dosyasında tanımlı değil"
        return result
    headers = {"x-apikey": api_key, "Content-Type": "application/x-www-form-urlencoded"}
    try:
        url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
        report_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
        resp = requests.get(report_url, headers={"x-apikey": api_key}, timeout=15)
        data = None
        if resp.status_code == 200:
            data = resp.json()
        elif resp.status_code == 404:
            scan_resp = requests.post(
                "https://www.virustotal.com/api/v3/urls",
                headers=headers,
                data={"url": url},
                timeout=15,
            )
            if scan_resp.status_code in (200, 201):
                scan_data = scan_resp.json()
                analysis_id = scan_data.get("data", {}).get("id")
                if analysis_id:
                    time.sleep(3)
                    analysis_resp = requests.get(
                        f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
                        headers={"x-apikey": api_key},
                        timeout=15,
                    )
                    if analysis_resp.status_code == 200:
                        data = analysis_resp.json()
            else:
                result["error"] = f"VirusTotal tarama hatası: {scan_resp.status_code}"
                return result
        else:
            result["error"] = f"VirusTotal API hatası: {resp.status_code}"
            return result
        if data:
            stats = (
                data.get("data", {}).get("attributes", {}).get("last_analysis_stats")
                or data.get("data", {}).get("attributes", {}).get("stats")
                or {}
            )
            result["malicious"] = stats.get("malicious", 0)
            result["suspicious"] = stats.get("suspicious", 0)
            result["harmless"] = stats.get("harmless", 0)
            result["undetected"] = stats.get("undetected", 0)
            result["success"] = True
            if result["malicious"] > 0:
                result["score_added"] = VT_MALICIOUS_SCORE * min(result["malicious"], 3)
            elif result["suspicious"] > 0:
                result["score_added"] = VT_SUSPICIOUS_SCORE * min(result["suspicious"], 2)
    except requests.RequestException as e:
        result["error"] = f"VirusTotal bağlantı hatası: {e}"
    except (KeyError, TypeError) as e:
        result["error"] = f"VirusTotal yanıt ayrıştırma hatası: {e}"
    return result


def check_abuseipdb(domain_or_ip: str, api_key: str | None) -> dict[str, Any]:
    """AbuseIPDB API v2 ile IP veya domain kontrolü yapar."""
    result = {"success": False, "abuse_confidence": 0, "score_added": 0, "error": None}
    if not REQUESTS_AVAILABLE:
        result["error"] = "requests kütüphanesi yüklü değil (pip install requests)"
        return result
    if not api_key:
        result["error"] = "ABUSEIPDB_API_KEY .env dosyasında tanımlı değil"
        return result
    check_target = domain_or_ip
    if not all(c.isdigit() or c == "." for c in domain_or_ip):
        ip = _resolve_domain_to_ip(domain_or_ip)
        if not ip:
            result["error"] = f"Domain IP'ye çözümlenemedi: {domain_or_ip}"
            return result
        check_target = ip
    try:
        resp = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": api_key, "Accept": "application/json"},
            params={"ipAddress": check_target, "maxAgeInDays": 90},
            timeout=15,
        )
        if resp.status_code == 200:
            data = resp.json()
            result["abuse_confidence"] = data.get("data", {}).get("abuseConfidenceScore", 0)
            result["success"] = True
            if result["abuse_confidence"] >= 25:
                result["score_added"] = (result["abuse_confidence"] // 10) * ABUSEIPDB_SCORE_PER_10
        else:
            result["error"] = f"AbuseIPDB API hatası: {resp.status_code}"
    except requests.RequestException as e:
        result["error"] = f"AbuseIPDB bağlantı hatası: {e}"
    except (KeyError, TypeError) as e:
        result["error"] = f"AbuseIPDB yanıt ayrıştırma hatası: {e}"
    return result


def scan_urls_with_apis(
    urls: list[str],
    vt_key: str | None = None,
    abuse_key: str | None = None,
) -> dict[str, dict[str, Any]]:
    """URL listesini VirusTotal ve AbuseIPDB ile tarar."""
    keys = _get_env_keys()
    vt_key = vt_key or keys["virustotal"]
    abuse_key = abuse_key or keys["abuseipdb"]
    results = {}
    for url in urls:
        url_results = {"virustotal": {}, "abuseipdb": {}, "score_added": 0}
        vt_result = check_virustotal(url, vt_key)
        url_results["virustotal"] = vt_result
        url_results["score_added"] += vt_result.get("score_added", 0)
        domain = extract_domain(url)
        if domain:
            abuse_result = check_abuseipdb(domain, abuse_key)
            url_results["abuseipdb"] = abuse_result
            url_results["score_added"] += abuse_result.get("score_added", 0)
        results[url] = url_results
    return results
