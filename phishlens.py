import re
import argparse
from datetime import datetime
from pathlib import Path

SUSPICIOUS_WORDS = [
    "acil", "hemen", "son uyarı", "hesabınız kapatılacak",
    "kimlik doğrulama", "ödeme", "borç", "icra", "güncelle",
    "teslim edilemedi", "paket", "kargonuz", "şifreniz", "doğrulayın",
    "ceza", "bloke", "askıya alındı", "işleminiz", "onaylayın"
]

SUSPICIOUS_TLDS = [".xyz", ".top", ".click", ".online", ".site", ".icu", ".info"]

OFFICIAL_TERMS = ["ptt", "banka", "edevlet", "e-devlet", "vergi", "kargo", "icra"]


def extract_urls(text: str) -> list[str]:
    return re.findall(r"(https?://\S+|www\.\S+)", text.lower())


def analyze_message(text: str) -> dict:
    t = text.lower()
    score = 0
    hits = {"words": [], "official": [], "tlds": [], "urls": []}

    for w in SUSPICIOUS_WORDS:
        if w in t:
            score += 2
            hits["words"].append(w)

    for term in OFFICIAL_TERMS:
        if term in t:
            score += 2
            hits["official"].append(term)

    urls = extract_urls(text)
    if urls:
        score += 2
        hits["urls"] = urls
        for url in urls:
            for tld in SUSPICIOUS_TLDS:
                if tld in url:
                    score += 3
                    hits["tlds"].append(tld)

    if score >= 9:
        risk = "YÜKSEK"
    elif score >= 5:
        risk = "ORTA"
    else:
        risk = "DÜŞÜK"

    return {"risk": risk, "score": score, "hits": hits}


def format_report(text: str, result: dict) -> str:
    words = sorted(set(result["hits"]["words"]))
    official = sorted(set(result["hits"]["official"]))
    tlds = sorted(set(result["hits"]["tlds"]))
    urls = result["hits"]["urls"]

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
    if urls:
        lines.append("Bulunan bağlantılar:")
        lines.append(", ".join(urls))
        lines.append("")
    if tlds:
        lines.append("Şüpheli uzantılar:")
        lines.append(", ".join(tlds))
        lines.append("")
    return "\n".join(lines).strip() + "\n"


def default_report_filename() -> str:
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    return f"phishlens_report_{ts}.txt"


def save_report(report_text: str, output_path: str | None) -> Path:
    path = Path(output_path) if output_path else Path(default_report_filename())
    path.write_text(report_text, encoding="utf-8")
    return path


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="PhishLens TR - Şüpheli mesaj metinleri için kural tabanlı risk analizi (eğitim amaçlı)."
    )
    p.add_argument(
        "--output",
        "-o",
        help="Raporu kaydetmek için dosya adı (ör: rapor.txt). Verilmezse otomatik isim kullanılır.",
        default=None,
    )
    p.add_argument(
        "--no-prompt",
        action="store_true",
        help="Rapor kaydı için soru sormaz (output verilmişse kaydeder, verilmemişse kaydetmez).",
    )
    return p.parse_args()


def main() -> None:
    args = parse_args()

    print("PhishLens TR - Mesaj Risk Analizi")
    print("Bir SMS/e-posta metnini girin ve Enter'a basın.\n")

    text = input("> ").strip()
    if not text:
        print("\nBoş metin girildi. Çıkılıyor.")
        return

    result = analyze_message(text)

    print("\nSonuç")
    print("Risk:", result["risk"])
    print("Skor:", result["score"])

    report_text = format_report(text, result)

    # Rapor kaydetme kararı
    should_save = False
    if args.output:
        should_save = True
    elif args.no_prompt:
        should_save = False
    else:
        ans = input("\nRaporu .txt olarak kaydetmek ister misiniz? (e/h): ").strip().lower()
        should_save = ans in ("e", "evet", "y", "yes")

    if should_save:
        saved_path = save_report(report_text, args.output)
        print(f"Rapor kaydedildi: {saved_path.resolve()}")


if __name__ == "__main__":
    main()
