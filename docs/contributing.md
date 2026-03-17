# Katkıda Bulunma

PhishLens-TR projesine katkı sağlamak için bu rehberi takip edin.

## Pull Request Kuralları

### 1. Branch oluşturma

Yeni bir özellik veya düzeltme için ayrı branch kullanın:

```bash
git checkout -b feature/yeni-ozellik
# veya
git checkout -b fix/hata-duzeltmesi
```

### 2. Commit mesajları

Anlamlı ve tutarlı commit mesajları yazın:

```
feat: Yeni regex kuralı eklendi
fix: URL heuristik hesaplama hatası düzeltildi
docs: Kurulum rehberi güncellendi
```

### 3. Kod standartları

- Python 3.10+ sözdizimini kullanın
- Mevcut kod stilini koruyun
- Gerekli yerlerde docstring ekleyin

### 4. Testler

Değişiklikleriniz için test yazın ve mevcut testlerin geçtiğinden emin olun:

```bash
pip install -e ".[dev]"
pytest tests/ -v
```

### 5. Pull Request açma

1. Değişikliklerinizi push edin: `git push origin feature/yeni-ozellik`
2. GitHub'da Pull Request açın
3. Açıklama alanında yaptığınız değişiklikleri özetleyin
4. İlgili issue varsa referans verin (örn: `Fixes #42`)

## Katkı Alanları

- Yeni regex kuralları (banka/kargo phishing)
- Bilinen domain listesi güncellemeleri
- Hata düzeltmeleri
- Dokümantasyon iyileştirmeleri
- Test kapsamı artırımı
