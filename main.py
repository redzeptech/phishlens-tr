"""
PhishLens TR - Giriş noktası.

CLI uygulamasını başlatır.
"""

import argparse
from pathlib import Path

# logs/ klasörünü kontrol et, yoksa oluştur
(Path(__file__).parent / "logs").mkdir(parents=True, exist_ok=True)

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--export-pdf",
        action="store_true",
        help="Analiz geçmişini PDF rapor olarak dışa aktar.",
    )
    args, _ = parser.parse_known_args()

    if args.export_pdf:
        from phishlens.utils.exporter import export_stats_to_pdf
        path = export_stats_to_pdf()
        print(f"Rapor başarıyla oluşturuldu: {path.resolve()}")
    else:
        from phishlens import main
        main()
