"""
PhishLens TR - Merkezi tarayıcı sınıfı.

Tüm analiz yöntemleri Scanner altında toplanır.
"""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any, TypedDict

from phishlens.rules import (
    SUSPICIOUS_WORDS,
    SUSPICIOUS_TLDS,
    OFFICIAL_TERMS,
    extract_domain,
    extract_urls,
    check_domain_similarity,
    apply_regex_rules,
)
from phishlens.apis import scan_urls_with_apis
from phishlens.url_heuristics import analyze_urls_heuristics
from phishlens.emotion_risk import compute_emotion_risk_score
from phishlens.llm_analysis import is_in_llm_trigger_zone, get_llm_analysis
from phishlens.eml_parser import parse_eml
from phishlens.email_auth import analyze_email_auth

# Proje kökü (src/phishlens/scanner.py -> parents[2])
_PROJECT_ROOT = Path(__file__).resolve().parents[2]


class ScanResult(TypedDict, total=False):
    """Tarama sonucu yapısı."""

    risk: str
    score: int
    hits: dict[str, Any]
    eml_metadata: dict[str, Any]
    email_auth: dict[str, Any]
    llm_analysis: dict[str, Any]


class Scanner:
    """Phishing analiz tarayıcısı.

    Tüm analiz yöntemleri (metin, URL, metadata) bu sınıf altında toplanır.
    """

    def __init__(
        self,
        use_api: bool = True,
        use_llm: bool = False,
        llm_provider: str = "auto",
    ) -> None:
        """Scanner örneği oluşturur.

        Args:
            use_api: VirusTotal/AbuseIPDB API çağrıları yapılsın mı.
            use_llm: %50-%70 risk bandında LLM analizi kullanılsın mı.
            llm_provider: "openai", "ollama" veya "auto".
        """
        self.use_api: bool = use_api
        self.use_llm: bool = use_llm
        self.llm_provider: str = llm_provider

    def _init_hits(self) -> dict[str, Any]:
        """Boş hits yapısı döner."""
        return {
            "words": [], "official": [], "tlds": [], "urls": [],
            "regex": [], "domain_similarity": [], "api_results": {},
            "email_auth": [], "url_heuristics": {}, "emotion_risk": {},
        }

    @staticmethod
    def _compute_risk(score: int) -> str:
        """Skora göre risk seviyesi döner (DÜŞÜK/ORTA/YÜKSEK)."""
        if score >= 9:
            return "YÜKSEK"
        if score >= 5:
            return "ORTA"
        return "DÜŞÜK"

    def _serialize_for_json(self, obj: Any) -> Any:
        """Nesneyi JSON'a yazılabilir formata dönüştürür (tuple -> list vb.)."""
        if isinstance(obj, tuple):
            return list(self._serialize_for_json(x) for x in obj)
        if isinstance(obj, dict):
            return {str(k): self._serialize_for_json(v) for k, v in obj.items()}
        if isinstance(obj, list):
            return [self._serialize_for_json(x) for x in obj]
        return obj

    def save_result_to_log(self, result: ScanResult) -> None:
        """Analiz sonucunu logs/analysis_history.jsonl dosyasına ekler."""
        log_dir = _PROJECT_ROOT / "logs"
        log_dir.mkdir(parents=True, exist_ok=True)
        log_path = log_dir / "analysis_history.jsonl"

        hits = result.get("hits", {})
        urls = hits.get("urls", []) or []

        detected_rules: dict[str, Any] = {}
        for key in ("words", "official", "tlds", "regex", "domain_similarity",
                    "url_heuristics", "email_auth"):
            val = hits.get(key)
            if val:
                detected_rules[key] = self._serialize_for_json(val)

        brands: list[str] = []
        domain_sim = hits.get("domain_similarity", []) or []
        for item in domain_sim:
            if isinstance(item, (list, tuple)) and len(item) >= 2:
                known = item[1]
                if isinstance(known, str):
                    brand = known.split(".")[0].replace("_", " ").title()
                    if brand and brand not in brands:
                        brands.append(brand)
        official_map = {"ptt": "PTT", "edevlet": "E-Devlet", "e-devlet": "E-Devlet",
                        "banka": "Banka", "vergi": "Vergi", "kargo": "Kargo", "icra": "İcra"}
        for term in hits.get("official", []) or []:
            if isinstance(term, str):
                brand = official_map.get(term.lower(), term.title())
                if brand and brand not in brands:
                    brands.append(brand)

        entry = {
            "timestamp": datetime.now().isoformat(),
            "urls": urls,
            "risk_score": result.get("score", 0),
            "risk_level": result.get("risk", "DÜŞÜK"),
            "detected_rules": detected_rules,
            "brand": brands,
        }

        with open(log_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")

    def analyze_content(self, text: str) -> tuple[int, dict[str, Any]]:
        """Metin içeriği analizi: şüpheli kelimeler, regex, duygu skoru.

        Args:
            text: Analiz edilecek metin.

        Returns:
            (skor, hits) - hits: words, official, regex, emotion_risk.
        """
        t = text.lower()
        score = 0
        hits: dict[str, Any] = {"words": [], "official": [], "regex": []}

        for w in SUSPICIOUS_WORDS:
            if w in t:
                score += 2
                hits["words"].append(w)

        for term in OFFICIAL_TERMS:
            if term in t:
                score += 2
                hits["official"].append(term)

        regex_score, regex_hits = apply_regex_rules(text)
        score += regex_score
        hits["regex"] = regex_hits

        emotion_result = compute_emotion_risk_score(text)
        hits["emotion_risk"] = emotion_result.to_dict()
        if emotion_result.score >= 70:
            score += 3
        elif emotion_result.score >= 50:
            score += 2
        elif emotion_result.score >= 30:
            score += 1

        return score, hits

    def analyze_url(self, urls: list[str]) -> tuple[int, dict[str, Any]]:
        """URL analizi: TLD, domain benzerliği, heuristikler, API.

        Args:
            urls: Analiz edilecek URL listesi.

        Returns:
            (skor, hits) - hits: tlds, urls, domain_similarity, url_heuristics, api_results.
        """
        score = 0
        hits: dict[str, Any] = {
            "tlds": [], "urls": [], "domain_similarity": [],
            "api_results": {}, "url_heuristics": {},
        }

        if not urls:
            return score, hits

        score += 2
        hits["urls"] = urls

        heur_score, heur_hits = analyze_urls_heuristics(urls)
        score += heur_score
        hits["url_heuristics"] = heur_hits

        for url in urls:
            for tld in SUSPICIOUS_TLDS:
                if tld in url:
                    score += 3
                    hits["tlds"].append(tld)

            domain = extract_domain(url)
            if domain:
                similar = check_domain_similarity(domain, max_distance=2)
                for known, dist, sim in similar:
                    score += 4
                    hits["domain_similarity"].append(
                        (domain, known, dist, f"%{sim * 100:.0f}")
                    )

        if urls and self.use_api:
            try:
                api_results = scan_urls_with_apis(urls)
                for url, res in api_results.items():
                    hits["api_results"][url] = res
                    score += res.get("score_added", 0)
            except Exception:
                pass

        return score, hits

    def analyze_metadata(self, eml_data: dict[str, Any]) -> tuple[int, dict[str, Any]]:
        """E-posta metadata analizi: SPF, DKIM, DMARC.

        Args:
            eml_data: eml_parser.parse_eml() çıktısı.

        Returns:
            (skor, auth_result) - auth_result: email_auth sözlüğü.
        """
        auth = analyze_email_auth(eml_data)
        score = auth.get("score_added", 0)
        return score, auth

    def scan(
        self,
        text: str,
        eml_data: dict[str, Any] | None = None,
    ) -> ScanResult:
        """Tüm analizleri çalıştırır ve birleştirir.

        Args:
            text: Analiz edilecek metin (e-posta gövdesi veya SMS).
            eml_data: Varsa SPF/DKIM/DMARC analizi eklenir.

        Returns:
            Birleşik tarama sonucu (risk, score, hits, ...).
        """
        hits = self._init_hits()
        total_score = 0

        content_score, content_hits = self.analyze_content(text)
        total_score += content_score
        hits["words"] = content_hits["words"]
        hits["official"] = content_hits["official"]
        hits["regex"] = content_hits["regex"]

        urls = extract_urls(text)
        url_score, url_hits = self.analyze_url(urls)
        total_score += url_score
        hits["tlds"] = url_hits["tlds"]
        hits["urls"] = url_hits["urls"]
        hits["domain_similarity"] = url_hits["domain_similarity"]
        hits["api_results"] = url_hits["api_results"]
        hits["url_heuristics"] = url_hits.get("url_heuristics", {})
        hits["emotion_risk"] = content_hits.get("emotion_risk", {})

        result: ScanResult = {
            "risk": self._compute_risk(total_score),
            "score": total_score,
            "hits": hits,
        }

        if eml_data:
            meta_score, auth = self.analyze_metadata(eml_data)
            total_score += meta_score
            result["email_auth"] = auth
            result["hits"]["email_auth"] = auth.get("details", [])
            result["score"] = total_score
            result["risk"] = self._compute_risk(total_score)

        if self.use_llm and is_in_llm_trigger_zone(total_score):
            try:
                llm_result = get_llm_analysis(
                    text, total_score, provider=self.llm_provider
                )
                result["llm_analysis"] = llm_result
            except Exception:
                result["llm_analysis"] = {
                    "success": False,
                    "error": "LLM çağrısı başarısız",
                }

        self.save_result_to_log(result)
        return result

    def scan_eml_file(self, path: str | Path) -> ScanResult:
        """Eml dosyasını tarar (parse + scan + metadata).

        Args:
            path: .eml dosya yolu.

        Returns:
            eml_metadata ve email_auth içeren tam sonuç.
        """
        path = Path(path)
        if not path.exists():
            raise FileNotFoundError(f"Dosya bulunamadı: {path}")

        content = path.read_bytes()
        eml_data = parse_eml(content)
        body = eml_data.get("body", "") or ""

        result = self.scan(body, eml_data=eml_data)

        result["eml_metadata"] = {
            "sender_email": eml_data.get("sender_email"),
            "sender_domain": eml_data.get("sender_domain"),
            "sender_ip": eml_data.get("sender_ip"),
            "subject": eml_data.get("subject"),
            "body": body,
        }

        return result
