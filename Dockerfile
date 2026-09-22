FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PATH="/root/.foundry/bin:$PATH"

WORKDIR /app

# Runtime packages used by Slither, solc-select and Foundry/Anvil.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
       bash \
       ca-certificates \
       curl \
       git \
       build-essential \
       libffi-dev \
       libssl-dev \
    && rm -rf /var/lib/apt/lists/*

COPY . .

RUN python -m pip install --upgrade pip setuptools wheel \
    && pip install --no-cache-dir -e ".[production]" \
    && pip install --no-cache-dir slither-analyzer solc-select \
    && curl -L https://foundry.paradigm.xyz | bash \
    && /root/.foundry/bin/foundryup

# Keep a compiler available for the repository's documented Solidity workflows.
RUN solc-select install 0.8.20 \
    && solc-select use 0.8.20

RUN mkdir -p /app/artifacts

EXPOSE 8787

CMD ["sh", "-c", "python -m smartrisk.unified serve --host 0.0.0.0 --port ${PORT:-8787}"]
