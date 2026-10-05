FROM ubuntu:24.04

ENV PYTHONUNBUFFERED=1
WORKDIR /app
ENV PYTHONPATH=/app

RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 \
    libbpf1 \
    libelf1 \
    zlib1g \
    libzstd1 \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY . /app

EXPOSE 8000

CMD ["python3", "monitoring/metrics_exporter.py"]
