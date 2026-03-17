"""
PhishLens TR - Şüpheli mesaj metinleri için kural tabanlı risk analizi.

Eğitim amaçlı phishing tespit aracı.
"""

from phishlens.core import (
    PhishLensError,
    ReportSaveError,
    analyze_message,
    analyze_eml_file,
    format_report,
    default_report_filename,
    save_report,
    parse_args,
    main,
)

__all__ = [
    "PhishLensError",
    "ReportSaveError",
    "analyze_message",
    "analyze_eml_file",
    "format_report",
    "default_report_filename",
    "save_report",
    "parse_args",
    "main",
]
