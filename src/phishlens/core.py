"""
PhishLens TR - Şüpheli mesaj metinleri için kural tabanlı risk analizi.

Eğitim amaçlı phishing tespit aracı.

Async geçiş planı: ASYNC_MIGRATION.md dosyasına bakınız.
"""

import argparse
from datetime import datetime
from pathlib import Path

from phishlens.db import save_analysis
from phishlens.scanner import Scanner


# --- Hata mesajları ---
class PhishLensError(Exception):
    """PhishLens uygulama hataları için temel sınıf.

    Tüm PhishLens özel istisnaları bu sınıftan türetilir.
    """

    pass


class ReportSaveError(PhishLensError):
    """Rapor dosyası kaydedilirken oluşan hatalar.

    OSError, PermissionError gibi dosya yazma hatalarında yükseltilir.
    """

    pass


def analyze_message(
    text: str,
    use_api: bool = True,
    use_llm: bool = False,
    llm_provider: str = "auto",
) -> dict:
    """Mesajı kural tabanlı analiz eder ve risk skoru döner.

    Kelime, regex, TLD, domain benzerliği ve opsiyonel API sonuçlarını
    birleştirerek toplam skor hesaplar. use_llm=True ve skor %50-%70
    bandındaysa LLM ile doğal dil açıklaması üretilir.

    Args:
        text: Analiz edilecek mesaj metni (SMS/e-posta içeriği).
        use_api: True ise URL'ler VirusTotal ve AbuseIPDB ile taranır.
        use_llm: True ve skor %50-%70 ise LLM (OpenAI/Ollama) ile analiz.
        llm_provider: "openai", "ollama" veya "auto".

    Returns:
        Analiz sonucu sözlüğü:
            - risk (str): "YÜKSEK" | "ORTA" | "DÜŞÜK"
            - score (int): Toplam risk skoru
            - hits (dict): Tetiklenen kurallar
            - llm_analysis (dict|None): LLM açıklaması (tetiklenirse)
    """
    scanner = Scanner(use_api=use_api, use_llm=use_llm, llm_provider=llm_provider)
    return scanner.scan(text)


def analyze_eml_file(
    path: str | Path,
    use_api: bool = True,
    use_llm: bool = False,
    llm_provider: str = "auto",
) -> dict:
    """Eml dosyasını analiz eder (metin + SPF/DKIM/DMARC).

    Args:
        path: .eml dosya yolu.
        use_api: VirusTotal/AbuseIPDB kullan.
        use_llm: LLM analizi.
        llm_provider: LLM sağlayıcı.

    Returns:
        analyze_message() ile aynı yapı + eml_metadata, email_auth.
    """
    scanner = Scanner(use_api=use_api, use_llm=use_llm, llm_provider=llm_provider)
    try:
        return scanner.scan_eml_file(path)
    except FileNotFoundError as e:
        raise PhishLensError(str(e)) from e


def format_report(text: str, result: dict) -> str:
    """Analiz sonucunu insan okunabilir rapor metnine dönüştürür.

    Args:
        text: Orijinal analiz edilen mesaj metni.
        result: analyze_message() fonksiyonunun döndürdüğü sonuç sözlüğü.

    Returns:
        Rapor metni (str). UTF-8 ile .txt dosyasına yazılabilir.
    """
    words = sorted(set(result["hits"]["words"]))
    official = sorted(set(result["hits"]["official"]))
    tlds = sorted(set(result["hits"]["tlds"]))
    urls = result["hits"]["urls"]
    regex_hits = result["hits"]["regex"]
    domain_sim = result["hits"]["domain_similarity"]
    api_results = result["hits"].get("api_results", {})
    url_heuristics = result["hits"].get("url_heuristics", {})

    lines = []
    lines.append("PhishLens TR - Mesaj Risk Analizi Raporu")
    lines.append(f"Tarih/Saat: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append("")
    lines.append("Girilen metin:")
    lines.append(text)
    lines.append("")
    lines.append("Sonuç:")
    lines.append(f"Risk: {result['risk']}")
    lines.append(f"Skor: {result['score']}")
    lines.append("")
    if words:
        lines.append("Tetikleyici ifadeler:")
        lines.append(", ".join(words))
        lines.append("")
    if official:
        lines.append("Resmi kurum/terim çağrışımı:")
        lines.append(", ".join(official))
        lines.append("")
    if regex_hits:
        unique_desc = sorted(set(h[0] for h in regex_hits))
        lines.append("Regex kuralları (banka/kargo):")
        lines.append("; ".join(unique_desc))
        lines.append("")
    if urls:
        lines.append("Bulunan bağlantılar:")
        lines.append(", ".join(urls))
        lines.append("")
    if domain_sim:
        seen = set()
        sim_strs = []
        for d, k, _, p in domain_sim:
            key = (d, k)
            if key not in seen:
                seen.add(key)
                sim_strs.append(f"{d} ~ {k} (benzerlik {p})")
        lines.append("Domain benzerliği (typosquatting):")
        lines.append("; ".join(sim_strs))
        lines.append("")
    if tlds:
        lines.append("Şüpheli uzantılar:")
        lines.append(", ".join(tlds))
        lines.append("")
    emotion_risk = result["hits"].get("emotion_risk", {})
    if emotion_risk and emotion_risk.get("score", 0) > 0:
        lines.append("Duygu ve Risk Skoru:")
        lines.append(
            f"  Skor: {emotion_risk.get('score', 0)} | "
            f"Anahtar kelime: {emotion_risk.get('keyword_count', 0)} | "
            f"Büyük harf oranı: %{emotion_risk.get('uppercase_ratio', 0) * 100:.1f}"
        )
        if emotion_risk.get("keywords_found"):
            lines.append("  Bulunan: " + ", ".join(emotion_risk["keywords_found"]))
        lines.append("")
    if url_heuristics:
        heur_parts = []
        for key, label in [
            ("homograph", "Homograph saldırısı"),
            ("at_symbol", "URL'de @ sembolü"),
            ("subdomain_count", "Fazla subdomain"),
            ("suspicious_tld", "Şüpheli TLD"),
            ("url_length", "Uzun URL"),
            ("random_chars", "Anlamsız karakter dizisi"),
        ]:
            vals = url_heuristics.get(key, [])
            if vals:
                heur_parts.append(f"{label}: {'; '.join(vals[:3])}{'...' if len(vals) > 3 else ''}")
        if heur_parts:
            lines.append("URL Heuristic bulguları:")
            lines.append(" | ".join(heur_parts))
            lines.append("")
    email_auth = result.get("email_auth")
    if email_auth and email_auth.get("details"):
        lines.append("E-posta kimlik doğrulama (SPF/DKIM/DMARC):")
        lines.append("; ".join(email_auth["details"]))
        if email_auth.get("sender_ip"):
            lines.append(f"Gönderici IP: {email_auth['sender_ip']}")
        lines.append("")
    if api_results:
        lines.append("API Tarama Sonuçları (VirusTotal / AbuseIPDB):")
        for url, res in api_results.items():
            vt = res.get("virustotal", {})
            abuse = res.get("abuseipdb", {})
            parts = []
            if vt.get("success"):
                m, s = vt.get("malicious", 0), vt.get("suspicious", 0)
                parts.append(f"VT: {m} malicious, {s} suspicious")
            elif vt.get("error"):
                parts.append(f"VT: {vt['error']}")
            if abuse.get("success"):
                conf = abuse.get("abuse_confidence", 0)
                parts.append(f"AbuseIPDB: %{conf} güven")
            elif abuse.get("error"):
                parts.append(f"AbuseIPDB: {abuse['error']}")
            if parts:
                lines.append(f"  {url}")
                lines.append("    " + " | ".join(parts))
        lines.append("")
    llm = result.get("llm_analysis")
    if llm and llm.get("success") and llm.get("explanation"):
        lines.append("AI Analizi (LLM):")
        lines.append(llm["explanation"])
        lines.append("")
    elif llm and llm.get("error"):
        lines.append("AI Analizi: " + llm["error"])
        lines.append("")
    return "\n".join(lines).strip() + "\n"


def default_report_filename() -> str:
    """Zaman damgalı varsayılan rapor dosya adı üretir.

    Returns:
        phishlens_report_YYYYMMDD_HHMMSS.txt formatında dosya adı.
    """
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    return f"phishlens_report_{ts}.txt"


def save_report(report_text: str, output_path: str | None) -> Path:
    """Raporu UTF-8 kodlamasıyla dosyaya yazar.

    Args:
        report_text: Kaydedilecek rapor metni.
        output_path: Hedef dosya yolu. None ise default_report_filename()
            kullanılır.

    Returns:
        Kaydedilen dosyanın pathlib.Path nesnesi.

    Raises:
        ReportSaveError: Dosya yazma başarısız olduğunda (izin, disk dolu vb.).
    """
    try:
        path = (
            Path(output_path)
            if output_path
            else Path(default_report_filename())
        )
        path.write_text(report_text, encoding="utf-8")
        return path
    except OSError as e:
        target = output_path or default_report_filename()
        raise ReportSaveError(
            f"Rapor dosyası kaydedilemedi: '{target}'. "
            f"Detay: {e.strerror}"
        ) from e


def parse_args() -> argparse.Namespace:
    """Komut satırı argümanlarını ayrıştırır.

    Returns:
        argparse.Namespace: output, no_prompt, no_api öznitelikleri.
    """
    p = argparse.ArgumentParser(
        description=(
            "PhishLens TR - Şüpheli mesaj metinleri için kural tabanlı "
            "risk analizi (eğitim amaçlı)."
        )
    )
    p.add_argument(
        "--output",
        "-o",
        help=(
            "Raporu kaydetmek için dosya adı (ör: rapor.txt). "
            "Verilmezse otomatik isim kullanılır."
        ),
        default=None,
    )
    p.add_argument(
        "--no-prompt",
        action="store_true",
        help=(
            "Rapor kaydı için soru sormaz (output verilmişse kaydeder, "
            "verilmemişse kaydetmez)."
        ),
    )
    p.add_argument(
        "--no-api",
        action="store_true",
        help="VirusTotal/AbuseIPDB API çağrılarını atla.",
    )
    p.add_argument(
        "--llm",
        action="store_true",
        help="%%50-%%70 risk bandında LLM (OpenAI/Ollama) ile AI açıklaması al.",
    )
    p.add_argument(
        "--no-history",
        action="store_true",
        help="Analiz geçmişini history.db'ye kaydetme.",
    )
    p.add_argument(
        "--file",
        "-f",
        metavar="PATH",
        help=".eml dosyasından analiz (SPF/DKIM/DMARC dahil).",
        default=None,
    )
    p.add_argument(
        "--no-log",
        action="store_true",
        help="Analiz raporunu logs/phishlens_YYYY-MM-DD.log dosyasına kaydetme.",
    )
    p.add_argument(
        "--stats",
        action="store_true",
        help="Analiz geçmişi istatistiklerini göster; diğer analiz süreçlerini çalıştırma.",
    )
    p.add_argument(
        "--export-pdf",
        action="store_true",
        help="Analiz geçmişini PDF rapor olarak reports/ klasörüne dışa aktar.",
    )
    return p.parse_args()


def _safe_input(prompt: str) -> str | None:
    """Kullanıcı girişini güvenli şekilde alır.

    KeyboardInterrupt ve EOFError yakalanır; None döner.

    Args:
        prompt: input() fonksiyonuna verilecek istem metni.

    Returns:
        Kullanıcının girdiği metin (strip edilmiş) veya None
        (Ctrl+C / EOF durumunda).
    """
    try:
        return input(prompt).strip()
    except KeyboardInterrupt:
        print("\n\nİşlem kullanıcı tarafından iptal edildi (Ctrl+C).")
        return None
    except EOFError:
        print("\n\nGiriş sonlandırıldı (EOF).")
        return None


def main() -> None:
    """Ana uygulama akışı.

    İnteraktif mesaj girişi veya .eml dosyası alır, analiz eder.
    """
    args = parse_args()

    if args.stats:
        from phishlens.utils.stats import show_statistics
        show_statistics()
        return

    if args.export_pdf:
        from phishlens.utils.exporter import export_stats_to_pdf
        path = export_stats_to_pdf()
        print(f"\nPDF rapor kaydedildi: {path.resolve()}")
        return

    if args.file:
        try:
            result = analyze_eml_file(
                args.file,
                use_api=not args.no_api,
                use_llm=args.llm,
            )
            meta = result.get("eml_metadata", {})
            text = meta.get("body", "") or meta.get("subject", "")
        except PhishLensError as e:
            print(f"\nHata: {e}")
            return
    else:
        print("PhishLens TR - Mesaj Risk Analizi")
        print("Bir SMS/e-posta metnini girin ve Enter'a basın.\n")

        text = _safe_input("> ")
        if text is None:
            return
        if not text:
            print("\nBoş metin girildi. Çıkılıyor.")
            return

        result = analyze_message(
            text,
            use_api=not args.no_api,
            use_llm=args.llm,
        )

    if not args.no_history:
        try:
            save_analysis(text[:5000], result)
        except Exception:
            pass

    print("\nSonuç")
    print("Risk:", result["risk"])
    print("Skor:", result["score"])
    auth = result.get("email_auth")
    if auth and auth.get("details"):
        print("E-posta auth:", "; ".join(auth["details"]))
    llm = result.get("llm_analysis")
    if llm and llm.get("success") and llm.get("explanation"):
        print("\n--- AI Analizi ---")
        print(llm["explanation"])

    report_text = format_report(text, result)

    # Tarih bazlı log dosyasına kaydet (--no-log ile devre dışı)
    if not args.no_log:
        try:
            from phishlens.utils.file_log import write_log_entry
            log_path = write_log_entry(report_text)
        except Exception:
            pass

    # Rapor kaydetme kararı
    should_save = False
    if args.output:
        should_save = True
    elif args.no_prompt:
        should_save = False
    else:
        ans = _safe_input(
            "\nRaporu .txt olarak kaydetmek ister misiniz? (e/h): "
        )
        if ans is None:
            return
        should_save = (ans or "").lower() in ("e", "evet", "y", "yes")

    if should_save:
        try:
            saved_path = save_report(report_text, args.output)
            print(f"Rapor kaydedildi: {saved_path.resolve()}")
        except ReportSaveError as e:
            print(f"\nHata: {e}")

    if not args.no_log:
        try:
            from phishlens.utils.file_log import get_today_log_path
            print(f"Log: {get_today_log_path().resolve()}")
        except Exception:
            pass


if __name__ == "__main__":
    main()
