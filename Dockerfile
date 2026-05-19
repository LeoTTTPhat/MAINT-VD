FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /workspace

RUN apt-get update \
    && apt-get install -y --no-install-recommends git build-essential curl \
    && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir \
    numpy \
    pandas \
    scipy \
    scikit-learn \
    tqdm \
    requests \
    transformers \
    torch

COPY scripts ./scripts
COPY artifact_manifest.tsv ./artifact_manifest.tsv

CMD ["python", "scripts/conduct_detector_aging.py", "--help"]
