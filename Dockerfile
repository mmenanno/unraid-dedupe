# Stage 1: Build rmlint
FROM python:3.11-slim AS builder

# Install build dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    make \
    scons \
    gettext \
    git \
    libelf-dev \
    libglib2.0-dev \
    libjson-glib-dev \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

# Clone and build rmlint
RUN git clone https://github.com/sahib/rmlint.git /tmp/rmlint \
    && cd /tmp/rmlint \
    && scons config \
    && scons install

# Stage 2: Final runtime image
FROM python:3.11-slim

# Install only runtime dependencies
RUN apt-get update && apt-get install -y \
    libelf1 \
    libglib2.0-0 \
    libjson-glib-1.0-0 \
    && rm -rf /var/lib/apt/lists/*

# Copy rmlint binary and libraries from builder
COPY --from=builder /usr/local/bin/rmlint /usr/local/bin/rmlint

# Set working directory
WORKDIR /app

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY app/ /app/
COPY config/dedupe_config.yaml /app/config/dedupe_config.yaml

# Create data directories with proper permissions
RUN mkdir -p /data/config /data/reports /data/logs \
    && chmod -R 755 /data

# Expose Flask port
EXPOSE 5000

# Set environment variables
ENV PYTHONUNBUFFERED=1
ENV FLASK_APP=web_ui.py

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import requests; requests.get('http://localhost:5000/health')" || exit 1

# Run the application
CMD ["python", "web_ui.py"]

