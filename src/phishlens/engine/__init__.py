"""PhishLens TR - Analiz motoru."""

from phishlens.engine.url_scanner import (
    extract_urls,
    extract_domain,
    check_domain_similarity,
    analyze_urls_heuristics,
)
from phishlens.engine.text_scanner import (
    apply_regex_rules,
    analyze_text,
    compute_emotion_risk_score,
)
from phishlens.engine.api_integrator import scan_urls_with_apis
from phishlens.engine.threat_feeds import ThreatFeedManager, is_url_malicious

__all__ = [
    "extract_urls",
    "extract_domain",
    "check_domain_similarity",
    "analyze_urls_heuristics",
    "apply_regex_rules",
    "analyze_text",
    "compute_emotion_risk_score",
    "scan_urls_with_apis",
    "ThreatFeedManager",
    "is_url_malicious",
]
