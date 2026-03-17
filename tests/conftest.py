"""Pytest fixtures ve ortak test verileri."""

# --- Pozitif senaryolar (gerçek phishing örnekleri) ---
PHISHING_SAMPLES = {
    "banka_kart_bloke": (
        "Kartınız bloke edildi! Hemen https://garanti-dogrulama.xyz "
        "adresinden kimlik doğrulama yapın."
    ),
    "iban_dogrulama": (
        "IBAN doğrulama gerekiyor. Hesabınız askıya alınacak. "
        "Son 24 saat içinde https://banka-onay.top linkine gidin."
    ),
    "otp_talebi": (
        "OTP girin lütfen. Şifre sıfırlama için doğrulama kodu gönderin: "
        "www.phishing-site.click"
    ),
    "kargo_takip": (
        "Kargo gönderiniz yola çıktı. Takip no: 745566511323. "
        "Teslimat için https://kargo-odeme.online adresine gidin."
    ),
    "acil_sure_baskisi": (
        "Hesabınız kapatılacak! Son 48 saat içinde borç ödemeniz gerekiyor. "
        "Acil işleminizi onaylayın: https://icra-tahsilat.site"
    ),
    "typosquatting": (
        "Kartınız bloke. Doğrulama için https://go0gle.com/verify "
        "veya https://garanii.com.tr/link adresine gidin."
    ),
    "coklu_tehdit": (
        "ACİL! Kartınız askıya alındı. IBAN doğrulama ve kimlik doğrulama "
        "için son 24 saat içinde https://fake-banka.xyz/onay adresine gidin. "
        "Şifreniz ve ödemeniz gerekiyor."
    ),
}

# --- Negatif senaryolar (güvenli mesajlar) ---
SAFE_SAMPLES = {
    "normal_mesaj": "Merhaba, yarın saat 14'te buluşalım mı?",
    "bilgilendirme": "Garanti Bankası: Yeni kredi kartı teklifiniz hazır. "
    "Şubemize uğrayabilirsiniz.",
    "mevcut_url": "Toplantı notları: https://docs.google.com/document/d/abc123",
    "bos": "",
    "sadece_rakam": "12345 67890",
    "mevcut_domain": (
        "Trendyol kampanyası: https://www.trendyol.com/indirim "
        "Geçerli 1 hafta."
    ),
}
