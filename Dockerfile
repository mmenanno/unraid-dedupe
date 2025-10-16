# Stage 1: Build rmlint
FROM python:3.11-slim AS builder

# Install build dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    g++ \
    make \
    scons \
    gettext \
    git \
    libelf-dev \
    libglib2.0-dev \
    libjson-glib-dev \
    libblkid-dev \
    python3-dev \
    python3-sphinx \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

# Clone and build rmlint
RUN git clone https://github.com/sahib/rmlint.git /tmp/rmlint \
    && cd /tmp/rmlint \
    && scons config --prefix=/usr/local --without-gui \
    && scons install --prefix=/usr/local \
    && ldconfig

# Stage 2: Build Tailwind CSS
FROM alpine:latest AS tailwind-builder

# Install curl to download Tailwind CLI
RUN apk add --no-cache curl

# Download Tailwind standalone CLI (Linux x64)
RUN curl -sLO https://github.com/tailwindlabs/tailwindcss/releases/latest/download/tailwindcss-linux-x64 \
    && chmod +x tailwindcss-linux-x64 \
    && mv tailwindcss-linux-x64 /usr/local/bin/tailwindcss

# Set working directory
WORKDIR /build

# Copy source files needed for Tailwind
COPY tailwind.config.js .
COPY app/static/tailwind.src.css ./app/static/
COPY app/templates/ ./app/templates/

# Build Tailwind CSS (minified for production)
RUN tailwindcss -i ./app/static/tailwind.src.css -o ./app/static/tailwind.generated.css --minify

# Stage 3: Final runtime image
FROM python:3.11-slim

# Install only runtime dependencies
RUN apt-get update && apt-get install -y \
    libelf1 \
    libglib2.0-0 \
    libjson-glib-1.0-0 \
    libblkid1 \
    && rm -rf /var/lib/apt/lists/*

# Copy rmlint binary from builder
COPY --from=builder /usr/local/bin/rmlint /usr/local/bin/rmlint

# Set working directory
WORKDIR /app

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY app/ /app/
COPY config/dedupe_config.yaml /app/config/dedupe_config.yaml
COPY gunicorn.conf.py /app/gunicorn.conf.py
COPY VERSION /app/VERSION

# Copy generated Tailwind CSS from builder
COPY --from=tailwind-builder /build/app/static/tailwind.generated.css /app/static/tailwind.generated.css

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

# Run the application with Gunicorn (production WSGI server)
CMD ["gunicorn", "--config", "gunicorn.conf.py", "web_ui:app"]

