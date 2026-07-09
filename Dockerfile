FROM python:3.11-slim

LABEL org.opencontainers.image.title="StelarStrike"
LABEL org.opencontainers.image.description="Modular, AI-assisted web vulnerability orchestration framework"

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt pyproject.toml ./
RUN pip install --no-cache-dir -r requirements.txt

COPY . .
RUN pip install --no-cache-dir -e .

RUN useradd --create-home stelar && chown -R stelar:stelar /app
USER stelar

ENV STELAR_CONFIG_PATH=/app/config/config.yaml
ENV STELAR_REPORT_DIR=/app/reports

ENTRYPOINT ["stelarstrike"]
CMD ["--help"]
