# PhishLens TR - Optimize edilmiş çok aşamalı build
FROM python:3.12-slim as builder

WORKDIR /build

# Bağımlılıkları ayrı katmanda yükle (cache için)
COPY requirements.txt .
RUN pip install --no-cache-dir --user -r requirements.txt

# --- Production image ---
FROM python:3.12-slim

WORKDIR /app

# Sistem bağımlılıkları (minimal)
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Builder'dan paketleri kopyala
COPY --from=builder /root/.local /root/.local
ENV PATH=/root/.local/bin:$PATH

# Uygulama dosyaları
COPY phishlens.py rules.py apis.py llm_analysis.py db.py app.py .
COPY eml_parser.py email_auth.py .
COPY .streamlit .streamlit

# Varsayılan .env.example (kullanıcı volume ile override edebilir)
COPY .env.example .

# Streamlit port
EXPOSE 8501

# Sağlık kontrolü
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8501/_stcore/health || exit 1

# Varsayılan: Streamlit web arayüzü
CMD ["streamlit", "run", "app.py", "--server.port=8501", "--server.address=0.0.0.0"]
