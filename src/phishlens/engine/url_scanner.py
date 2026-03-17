"""
PhishLens TR - URL analiz mantığı.

URL çıkarma, domain benzerliği, heuristic kontroller.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse

from phishlens.data import load_keywords


def _get_keywords() -> dict[str, Any]:
    kw = load_keywords()
    return {
        "suspicious_tlds": kw.get("suspicious_tlds", []),
        "known_domains": kw.get("known_legitimate_domains", []),
    }


def extract_urls(text: str) -> list[str]:
    return re.findall(r"(https?://\S+|www\.\S+)", text, re.IGNORECASE)


def extract_domain(url: str) -> str | None:
    try:
        url_lower = url.lower().strip()
        if not url_lower.startswith(("http://", "https://", "www.")):
            url_lower = "https://" + url_lower
        parsed = urlparse(url_lower)
        netloc = parsed.netloc or parsed.path
        if netloc.startswith("www."):
            netloc = netloc[4:]
        return netloc if netloc else None
    except Exception:
        return None


def _levenshtein(s1: str, s2: str) -> int:
    if len(s1) < len(s2):
        return _levenshtein(s2, s1)
    if len(s2) == 0:
        return len(s1)
    prev = list(range(len(s2) + 1))
    for i, c1 in enumerate(s1):
        curr = [i + 1]
        for j, c2 in enumerate(s2):
            cost = 0 if c1 == c2 else 1
            curr.append(min(prev[j + 1] + 1, curr[j] + 1, prev[j] + cost))
        prev = curr
    return prev[-1]


def check_domain_similarity(
    domain: str,
    known_domains: list[str] | None = None,
    max_distance: int = 2,
    min_length: int = 6,
) -> list[tuple[str, int, float]]:
    if known_domains is None:
        known_domains = _get_keywords()["known_domains"]
    domain = domain.lower().strip()
    if len(domain) < min_length:
        return []
    matches = []
    for known in known_domains:
        known = known.lower()
        dist = _levenshtein(domain, known)
        if 0 < dist <= max_distance:
            max_len = max(len(domain), len(known))
            similarity = 1 - (dist / max_len)
            matches.append((known, dist, similarity))
    return sorted(matches, key=lambda x: x[1])


HOMOGRAPH_SUBSTITUTIONS = {
    "0": "o", "1": "l", "3": "e", "4": "a", "5": "s",
    "6": "g", "8": "b", "9": "g", "@": "a",
}
HOMOGRAPH_PATTERN = re.compile(r"(?:[a-z]*[0-9@]+[a-z]*)+", re.IGNORECASE)
RANDOM_SEQUENCE = re.compile(r"[a-z0-9]{4,}(?=[^a-z0-9]|$)", re.IGNORECASE)
URL_LENGTH_SUSPICIOUS, URL_LENGTH_HIGH_RISK = 75, 120
SUBDOMAIN_SUSPICIOUS, SUBDOMAIN_HIGH_RISK = 3, 5


@dataclass
class HeuristicResult:
    rule: str
    score: int
    detail: str
    url: str = ""


@dataclass
class UrlHeuristicReport:
    url: str
    total_score: int = 0
    findings: list[HeuristicResult] = field(default_factory=list)

    def to_hits_dict(self) -> dict[str, Any]:
        return {
            "homograph": [f.detail for f in self.findings if f.rule == "homograph"],
            "at_symbol": [f.detail for f in self.findings if f.rule == "at_symbol"],
            "subdomain_count": [f.detail for f in self.findings if f.rule == "subdomain"],
            "suspicious_tld": [f.detail for f in self.findings if f.rule == "tld"],
            "url_length": [f.detail for f in self.findings if f.rule == "url_length"],
            "random_chars": [f.detail for f in self.findings if f.rule == "random_chars"],
        }


def _normalize_homograph(domain: str) -> str:
    result = domain.lower()
    for num, letter in HOMOGRAPH_SUBSTITUTIONS.items():
        result = result.replace(num, letter)
    return result


def _has_homograph_attack(domain: str, known_domains: list[str]) -> tuple[bool, str]:
    domain_lower = domain.lower()
    if HOMOGRAPH_PATTERN.search(domain_lower):
        normalized = _normalize_homograph(domain_lower)
        for known in known_domains:
            known_base = known.split(".")[0]
            norm_base = normalized.split(".")[0]
            if len(norm_base) >= 4 and known_base in norm_base:
                return True, f"Homograph: {domain} ~ {known}"
            if norm_base == known_base:
                return True, f"Homograph: {domain} ~ {known}"
        if re.search(r"[a-z][0-9]{2,}[a-z]|[a-z][0-9][a-z][0-9]", domain_lower):
            return True, f"Homograph benzeri: {domain} (harf-sayı karışımı)"
    return False, ""


def _check_at_symbol(url: str) -> tuple[bool, str]:
    if "@" in url:
        return True, f"URL'de @ sembolü: {url[:80]}{'...' if len(url) > 80 else ''}"
    return False, ""


def _count_subdomains(domain: str) -> int:
    if not domain:
        return 0
    parts = [p for p in domain.lower().split(".") if p and p != "www"]
    return max(0, len(parts) - 1)


def _check_subdomain_count(domain: str) -> tuple[bool, int, str]:
    count = _count_subdomains(domain)
    if count >= SUBDOMAIN_HIGH_RISK:
        return True, count, f"Çok fazla subdomain ({count}): {domain}"
    if count >= SUBDOMAIN_SUSPICIOUS:
        return True, count, f"Fazla subdomain ({count}): {domain}"
    return False, count, ""


def _check_suspicious_tld(url: str, tlds: list[str]) -> tuple[bool, str]:
    url_lower = url.lower()
    for tld in tlds:
        if tld in url_lower:
            return True, f"Şüpheli TLD: {tld}"
    return False, ""


def _check_url_length(url: str) -> tuple[bool, str]:
    length = len(url)
    if length >= URL_LENGTH_HIGH_RISK:
        return True, f"Çok uzun URL ({length} karakter)"
    if length >= URL_LENGTH_SUSPICIOUS:
        return True, f"Uzun URL ({length} karakter)"
    return False, ""


def _check_random_chars(domain: str) -> tuple[bool, str]:
    if not domain or len(domain) < 4:
        return False, ""
    host = domain.split("/")[0].split("?")[0].lower()
    digit_count = sum(1 for c in host if c.isdigit())
    alpha_count = sum(1 for c in host if c.isalpha())
    total = digit_count + alpha_count
    if total >= 6 and digit_count / total >= 0.4:
        return True, f"Yüksek rakam oranı: {host[:50]}"
    for match in RANDOM_SEQUENCE.finditer(host):
        chunk = match.group(0)
        if len(chunk) >= 6:
            vowels = sum(1 for c in chunk if c in "aeiou")
            if vowels == 0 or (len(chunk) >= 8 and vowels <= 1):
                return True, f"Anlamsız karakter dizisi: {chunk}"
    return False, ""


def analyze_url_heuristics(url: str) -> UrlHeuristicReport:
    kw = _get_keywords()
    tlds = kw["suspicious_tlds"]
    known_domains = kw["known_domains"]
    report = UrlHeuristicReport(url=url)

    found, detail = _check_at_symbol(url)
    if found:
        report.findings.append(HeuristicResult("at_symbol", 4, detail, url))
        report.total_score += 4

    found, detail = _check_suspicious_tld(url, tlds)
    if found:
        report.findings.append(HeuristicResult("tld", 3, detail, url))
        report.total_score += 3

    found, detail = _check_url_length(url)
    if found:
        score = 2 if "Çok uzun" in detail else 1
        report.findings.append(HeuristicResult("url_length", score, detail, url))
        report.total_score += score

    domain = extract_domain(url)
    if domain:
        found, detail = _has_homograph_attack(domain, known_domains)
        if found:
            report.findings.append(HeuristicResult("homograph", 4, detail, url))
            report.total_score += 4
        found, count, detail = _check_subdomain_count(domain)
        if found:
            score = 3 if count >= SUBDOMAIN_HIGH_RISK else 2
            report.findings.append(HeuristicResult("subdomain", score, detail, url))
            report.total_score += score
        found, detail = _check_random_chars(domain)
        if found:
            report.findings.append(HeuristicResult("random_chars", 2, detail, url))
            report.total_score += 2

    return report


def analyze_urls_heuristics(urls: list[str]) -> tuple[int, dict[str, Any]]:
    total_score = 0
    merged_hits: dict[str, list[str]] = {
        "homograph": [], "at_symbol": [], "subdomain_count": [],
        "suspicious_tld": [], "url_length": [], "random_chars": [],
    }
    for url in urls:
        report = analyze_url_heuristics(url)
        total_score += report.total_score
        for k, v in report.to_hits_dict().items():
            if k in merged_hits and v:
                merged_hits[k].extend(v)
    for k in merged_hits:
        merged_hits[k] = list(dict.fromkeys(merged_hits[k]))
    return total_score, merged_hits
