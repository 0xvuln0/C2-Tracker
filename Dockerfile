FROM python:3.11-slim

LABEL maintainer="0xvuln0 <imtiredalwayshe@gmail.com>"
LABEL description="C2 Server Tracker - Monitor connections and identify C2 infrastructure"

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    python3-dev \
    libyara-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy dependency files first (Docker layer caching)
COPY pyproject.toml ./

# Install Python dependencies
RUN pip install --no-cache-dir -e ".[dev]" 2>/dev/null || \
    pip install --no-cache-dir \
    psutil>=5.9.0 \
    shodan>=1.28.0 \
    censys>=2.2.0 \
    rich>=13.0.0 \
    requests>=2.31.0 \
    python-dotenv>=1.0.0 \
    yara-python>=4.3.0

# Copy project files
COPY . .

# Create data directory for output
RUN mkdir -p /app/data /app/output

ENTRYPOINT ["python3", "cli.py"]
CMD ["--help"]
