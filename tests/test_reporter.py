"""reporter modülü testleri."""

from phishlens.reporter import print_analysis_report, scan_result_to_report_rows


class TestPrintAnalysisReport:
    """print_analysis_report fonksiyonu testleri."""

    def test_basic_call_no_error(self):
        """Çağrı hata vermeden tamamlanır."""
        rows = [
            {"kriter": "PhishTank Kaydı", "durum": "güvenli", "detay": "Listede yok", "risk_puani": 0},
            {"kriter": "URL Benzerliği", "durum": "tehlikeli", "detay": "go0gle.com ~ google.com", "risk_puani": 85},
        ]
        print_analysis_report(rows, "YÜKSEK", 85)

    def test_ascii_durum(self):
        """ASCII durum (guvenli, supheli) kabul edilir."""
        rows = [
            {"kriter": "Test", "durum": "guvenli", "detay": "OK", "risk_puani": 5},
        ]
        print_analysis_report(rows, "DÜŞÜK", 5)


class TestScanResultToReportRows:
    """scan_result_to_report_rows fonksiyonu testleri."""

    def test_empty_result(self):
        """Boş sonuç."""
        rows = scan_result_to_report_rows({"hits": {}, "risk": "DÜŞÜK", "score": 0})
        assert len(rows) >= 2
        assert any(r["kriter"] == "URL Benzerliği" for r in rows)
        assert any(r["kriter"] == "Türkçe Kelime Analizi" for r in rows)

    def test_with_hits(self):
        """Hits ile dolu sonuç."""
        result = {
            "hits": {
                "urls": ["https://fake.xyz"],
                "words": ["acil", "bloke"],
                "domain_similarity": [("go0gle.com", "google.com", 1, "%90")],
                "emotion_risk": {"score": 65, "keyword_count": 3},
            },
            "risk": "YÜKSEK",
            "score": 15,
        }
        rows = scan_result_to_report_rows(result)
        assert len(rows) >= 3
        url_row = next((r for r in rows if r["kriter"] == "URL Tespiti"), None)
        assert url_row is not None
        assert "fake.xyz" in url_row["detay"]
