# ==============================================================================
# Production Dockerfile for PyReviewer (Optimized for Render Deployment)
# Multi-stage, non-root user, lightweight, instant startup
# ==============================================================================

FROM python:3.12-slim AS runner

WORKDIR /app

# Prevent Python from writing .pyc files and enable unbuffered logging
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PORT=8080

# Install git and ca-certificates for GitHub codebase scanning
RUN apt-get update && \
    apt-get install -y --no-install-recommends git ca-certificates && \
    rm -rf /var/lib/apt/lists/*

# Create non-root unprivileged service user for security
RUN groupadd -g 10001 appuser && \
    useradd -u 10001 -g appuser -s /bin/bash -m appuser

# Copy application source code
COPY --chown=appuser:appuser . .

USER appuser

EXPOSE 8080

# Healthcheck for container orchestrators (Render / Kubernetes / Docker)
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD python3 -c "import urllib.request, os; urllib.request.urlopen('http://localhost:' + os.environ.get('PORT', '8080') + '/healthz')" || exit 1

# Start high-performance server
CMD ["python3", "server.py"]
