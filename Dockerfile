# Use Python 3.11 slim image for better async performance
FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    openssl \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for better caching
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY ds_auth_v2.py .

# Create directories for secrets and keys
RUN mkdir -p /run/secrets /keys /mnt/logs /mnt/config /mnt/datasets

# Create a non-root user and grant read access to /keys
RUN useradd --create-home --shell /bin/bash ds-auth && \
    chown -R ds-auth:ds-auth /app /mnt/logs /mnt/config /mnt/datasets && \
    chown root:ds-auth /keys && \
    chmod 750 /keys

# Note: Stay as root user to read Docker secrets from /run/secrets/
# Docker secrets are mounted as root:root with 444 permissions

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:7000/health || exit 1

# Expose port
EXPOSE 7000

# Run the application
CMD ["python3", "ds_auth_v2.py"]
