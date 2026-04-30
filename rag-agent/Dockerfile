# Dockerfile for RAG Agent
FROM python:3.11-slim

# Install system dependencies including PostgreSQL client
RUN apt-get update && apt-get install -y \
    ffmpeg \
    build-essential \
    gcc \
    postgresql-client \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Install UV package manager
RUN pip install --no-cache-dir uv

# Copy dependency files
COPY pyproject.toml uv.lock* ./

# Install Python dependencies
RUN uv sync --frozen || uv sync

# Install Playwright browsers for crawl4ai
RUN uv run python -m playwright install --with-deps chromium

# Copy application code
COPY . .

# Set environment variables
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import asyncpg; import sys; sys.exit(0)"

# Run the Web App
CMD ["uv", "run", "python", "web_app.py", "--host", "0.0.0.0", "--port", "8000"]