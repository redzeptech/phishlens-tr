import re

SUSPICIOUS_WORDS = [
    "acil", "hemen", "son uyarı", "hesabınız kapatılacak",
    "kimlik doğrulama", "ödeme", "borç", "icra", "güncelle",
    "teslim edilemedi", "paket", "kargonuz", "şifreniz", "doğrulayın"
]

SUSPICIOUS_TLDS = [".xyz", ".top", ".click", ".online", ".site", ".icu", ".info"]

OFFICIAL_TERMS = ["ptt", "banka", "edevlet", "e-devlet", "vergi", "kargo", "icra"]

def extract_urls(text: str) -> list[str]:
    # http(s)://... veya www....
    return re.findall(r'(https?://\S+|www\.\S+)', text.lower())

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

def main():
    print("PhishLens TR - Mesaj Risk Analizi")
    print("Bir SMS/e-posta metnini yapıştırın. Bitince Enter'a basın.\n")
    text = input("> ")

    result = analyze_message(text)
    print("\nSonuç")
    print("Risk:", result["risk"])
    print("Skor:", result["score"])

    if result["hits"]["words"]:
        print("\nTetikleyici ifadeler:", ", ".join(sorted(set(result["hits"]["words"]))))

    if result["hits"]["official"]:
        print("Resmi kurum/terim çağrışımı:", ", ".join(sorted(set(result["hits"]["official"]))))

    if result["hits"]["urls"]:
        print("Bulunan bağlantılar:", ", ".join(result["hits"]["urls"]))

    if result["hits"]["tlds"]:
        print("Şüpheli uzantılar:", ", ".join(sorted(set(result["hits"]["tlds"]))))

if __name__ == "__main__":
    main()
