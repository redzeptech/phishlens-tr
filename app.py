"""
PhishLens TR - Web Arayüzü

Streamlit ile modern phishing analiz arayüzü.
"""

import streamlit as st
import pandas as pd

from phishlens import analyze_message, analyze_eml_file, format_report
from phishlens.db import save_analysis, get_recent_analyses

# Sayfa yapılandırması
st.set_page_config(
    page_title="PhishLens TR",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Özel CSS - modern görünüm
st.markdown("""
<style>
    @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600&family=Outfit:wght@400;600;700&display=swap');
    
    .stApp {
        background: linear-gradient(135deg, #0f172a 0%, #1e293b 50%, #0f172a 100%);
    }
    
    .main-header {
        font-family: 'Outfit', sans-serif;
        font-size: 2.5rem;
        font-weight: 700;
        background: linear-gradient(90deg, #38bdf8, #818cf8, #c084fc);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        margin-bottom: 0.5rem;
    }
    
    .sub-header {
        color: #94a3b8;
        font-size: 1rem;
        margin-bottom: 2rem;
    }
    
    .risk-badge {
        display: inline-block;
        padding: 0.5rem 1.5rem;
        border-radius: 2rem;
        font-weight: 700;
        font-size: 1.25rem;
        margin: 0.5rem 0;
    }
    
    .risk-yuksek {
        background: linear-gradient(135deg, #dc2626 0%, #b91c1c 100%);
        color: white;
        box-shadow: 0 4px 15px rgba(220, 38, 38, 0.4);
    }
    
    .risk-orta {
        background: linear-gradient(135deg, #f59e0b 0%, #d97706 100%);
        color: white;
        box-shadow: 0 4px 15px rgba(245, 158, 11, 0.4);
    }
    
    .risk-dusuk {
        background: linear-gradient(135deg, #10b981 0%, #059669 100%);
        color: white;
        box-shadow: 0 4px 15px rgba(16, 185, 129, 0.4);
    }
    
    .metric-card {
        background: rgba(30, 41, 59, 0.8);
        border: 1px solid rgba(148, 163, 184, 0.2);
        border-radius: 1rem;
        padding: 1.25rem;
        margin: 0.5rem 0;
    }
    
    .hit-item {
        background: rgba(51, 65, 85, 0.6);
        border-radius: 0.5rem;
        padding: 0.5rem 1rem;
        margin: 0.25rem 0;
        font-family: 'JetBrains Mono', monospace;
        font-size: 0.9rem;
    }
    
    div[data-testid="stMetricValue"] {
        font-size: 2rem !important;
        font-weight: 700 !important;
    }
</style>
""", unsafe_allow_html=True)


def get_risk_class(risk: str) -> str:
    """Risk seviyesine göre CSS sınıfı döner."""
    return {
        "YÜKSEK": "risk-yuksek",
        "ORTA": "risk-orta",
        "DÜŞÜK": "risk-dusuk",
    }.get(risk, "risk-dusuk")


def render_risk_gauge(score: int, max_score: int = 25) -> None:
    """Risk skoru için görsel gauge çizer."""
    progress = min(score / max_score, 1.0)
    color = "#dc2626" if progress >= 0.6 else "#f59e0b" if progress >= 0.3 else "#10b981"
    st.markdown(
        f"""
        <div class="metric-card">
            <div style="display: flex; justify-content: space-between; margin-bottom: 0.5rem;">
                <span style="color: #94a3b8;">Risk Skoru</span>
                <span style="font-weight: 700; color: {color};">{score} / {max_score}</span>
            </div>
            <div style="background: #334155; border-radius: 1rem; height: 12px; overflow: hidden;">
                <div style="background: {color}; width: {progress * 100}%; height: 100%; border-radius: 1rem; transition: width 0.5s;"></div>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def render_rule_chart(hits: dict) -> None:
    """Kural eşleşmeleri için bar chart verisi hazırlar."""
    categories = []
    counts = []
    labels = {
        "words": "Tetikleyici ifadeler",
        "official": "Resmi kurum çağrışımı",
        "regex": "Regex kuralları",
        "tlds": "Şüpheli TLD'ler",
        "urls": "Bulunan URL'ler",
        "domain_similarity": "Domain benzerliği",
    }
    for key, label in labels.items():
        data = hits.get(key, [])
        if isinstance(data, dict):
            count = len(data)
        else:
            count = len(set(str(x) for x in data)) if data else 0
        if count > 0:
            categories.append(label)
            counts.append(count)
    if categories:
        df = pd.DataFrame({"Kategori": categories, "Eşleşme": counts})
        st.bar_chart(df.set_index("Kategori")["Eşleşme"], color="#38bdf8")


def main() -> None:
    st.markdown('<p class="main-header">🛡️ PhishLens TR</p>', unsafe_allow_html=True)
    st.markdown(
        '<p class="sub-header">Şüpheli SMS/e-posta metinleri için kural tabanlı risk analizi · Eğitim amaçlı</p>',
        unsafe_allow_html=True,
    )

    with st.sidebar:
        st.header("⚙️ Ayarlar")
        use_api = st.checkbox(
            "VirusTotal / AbuseIPDB API kullan",
            value=False,
            help="URL'leri harici API'lerle tarar (anahtar gerekir)",
        )
        use_llm = st.checkbox(
            "AI analizi (%50-%70 risk bandında)",
            value=False,
            help="Belirsiz riskte OpenAI veya Ollama ile doğal dil açıklaması",
        )
        save_history = st.checkbox(
            "Geçmişe kaydet",
            value=True,
            help="Analiz sonuçlarını history.db'ye kaydet",
        )
        st.divider()
        st.caption("API anahtarları .env dosyasından okunur.")

    if "msg_input" not in st.session_state:
        st.session_state["msg_input"] = ""

    st.markdown("**Metin girin veya .eml dosyası yükleyin**")

    uploaded = st.file_uploader(".eml dosyası", type=["eml"], label_visibility="collapsed")

    col1, col2, col3 = st.columns([1, 1, 2])
    with col2:
        if st.button("📋 Örnek Phishing", use_container_width=True):
            st.session_state["msg_input"] = (
                "ACİL! Kartınız bloke edildi. IBAN doğrulama için son 24 saat içinde "
                "https://fake-banka.xyz/onay adresine gidin. OTP girin."
            )
            st.rerun()

    text = st.text_area(
        "Mesaj metnini girin",
        placeholder="Örn: Kartınız bloke edildi! Hemen https://garanti-dogrulama.xyz adresinden doğrulama yapın...",
        height=120,
        label_visibility="collapsed",
        key="msg_input",
    )

    col1, col2, _ = st.columns([1, 1, 2])
    with col1:
        analyze_btn = st.button("🔍 Analiz Et", type="primary", use_container_width=True)

    if analyze_btn and (text or uploaded):
        with st.spinner("Analiz ediliyor..."):
            if uploaded:
                import tempfile
                with tempfile.NamedTemporaryFile(suffix=".eml", delete=False) as tmp:
                    tmp.write(uploaded.getvalue())
                    tmp_path = tmp.name
                try:
                    result = analyze_eml_file(
                        tmp_path,
                        use_api=use_api,
                        use_llm=use_llm,
                    )
                    meta = result.get("eml_metadata", {})
                    text = meta.get("body", "") or meta.get("subject", "")
                finally:
                    import os
                    try:
                        os.unlink(tmp_path)
                    except Exception:
                        pass
            else:
                result = analyze_message(
                    text.strip(),
                    use_api=use_api,
                    use_llm=use_llm,
                )
        if save_history:
            try:
                save_analysis(text.strip(), result)
            except Exception:
                pass

        risk = result["risk"]
        score = result["score"]
        hits = result["hits"]

        st.divider()
        st.subheader("📊 Analiz Sonucu")

        col_a, col_b, col_c = st.columns([1, 1, 2])
        with col_a:
            st.markdown(
                f'<span class="risk-badge {get_risk_class(risk)}">{risk}</span>',
                unsafe_allow_html=True,
            )
        with col_b:
            st.metric("Skor", score)

        st.markdown("#### Risk Seviyesi")
        render_risk_gauge(score)

        if any(hits.get(k) for k in ["words", "official", "regex", "tlds", "urls", "domain_similarity"]):
            st.markdown("#### Kural Eşleşmeleri")
            render_rule_chart(hits)

        st.markdown("#### Detaylı Bulgular")

        details = [
            ("Tetikleyici ifadeler", hits.get("words", []), "⚠️"),
            ("Resmi kurum çağrışımı", hits.get("official", []), "🏛️"),
            ("Regex kuralları (banka/kargo)", [h[1] for h in hits.get("regex", [])], "📋"),
            ("Şüpheli TLD'ler", hits.get("tlds", []), "🔗"),
            ("Bulunan URL'ler", hits.get("urls", []), "🌐"),
            ("Domain benzerliği (typosquatting)", [f"{d} ~ {k}" for d, k, _, _ in hits.get("domain_similarity", [])], "🎭"),
        ]
        url_heur = hits.get("url_heuristics", {})
        for key, label in [
            ("homograph", "Homograph saldırısı"),
            ("at_symbol", "URL'de @ sembolü"),
            ("subdomain_count", "Fazla subdomain"),
            ("url_length", "Uzun URL"),
            ("random_chars", "Anlamsız karakter dizisi"),
        ]:
            vals = url_heur.get(key, [])
            if vals:
                details.append((label, vals, "🔍"))

        for title, items, icon in details:
            unique_items = sorted(set(str(x) for x in items)) if items else []
            if unique_items:
                with st.expander(f"{icon} {title} ({len(unique_items)})", expanded=True):
                    for item in unique_items:
                        st.markdown(f'<div class="hit-item">{item}</div>', unsafe_allow_html=True)

        email_auth = result.get("email_auth")
        if email_auth and email_auth.get("details"):
            st.markdown("#### 📧 E-posta Kimlik Doğrulama")
            st.warning("; ".join(email_auth["details"]))
            if email_auth.get("sender_ip"):
                st.caption(f"Gönderici IP: {email_auth['sender_ip']}")
            if email_auth.get("sender_domain"):
                st.caption(f"Gönderici domain: {email_auth['sender_domain']}")

        llm = result.get("llm_analysis")
        if llm:
            if llm.get("success") and llm.get("explanation"):
                st.markdown("#### 🤖 AI Analizi")
                st.info(llm["explanation"])
            elif llm.get("error"):
                st.warning(f"AI analizi: {llm['error']}")

        api_results = hits.get("api_results", {})
        if api_results:
            with st.expander("🔌 API Tarama Sonuçları", expanded=True):
                for url, res in api_results.items():
                    vt = res.get("virustotal", {})
                    abuse = res.get("abuseipdb", {})
                    st.caption(url)
                    if vt.get("success"):
                        st.write(f"VirusTotal: {vt.get('malicious', 0)} malicious, {vt.get('suspicious', 0)} suspicious")
                    elif vt.get("error"):
                        st.warning(vt["error"])
                    if abuse.get("success"):
                        st.write(f"AbuseIPDB: %{abuse.get('abuse_confidence', 0)} güven")
                    elif abuse.get("error"):
                        st.warning(abuse["error"])
                    st.divider()

        with st.expander("📜 Son Analizler", expanded=False):
            try:
                recent = get_recent_analyses(limit=10)
                if recent:
                    for r in recent:
                        st.caption(f"{r['created_at'][:19]} · {r['risk']} ({r['score']})")
                        st.text(r["text"][:100] + ("..." if len(r["text"]) > 100 else ""))
                        st.divider()
                else:
                    st.caption("Henüz kayıt yok.")
            except Exception:
                st.caption("Geçmiş yüklenemedi.")

        report_text = format_report(text, result)
        st.download_button(
            "📥 Raporu İndir (.txt)",
            report_text,
            file_name="phishlens_raporu.txt",
            mime="text/plain",
        )

    elif analyze_btn and not text and not uploaded:
        st.warning("Lütfen metin girin veya .eml dosyası yükleyin.")


if __name__ == "__main__":
    main()
