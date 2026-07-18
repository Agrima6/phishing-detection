FROM python:3.12-slim

WORKDIR /app

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY config.py .
COPY app.py .
COPY auth_clerk.py .
COPY phishing_campaign_service.py .
COPY gemini_service.py .
COPY static/ static/
COPY landing_page/ landing_page/

# Copy service account if present (optional – can be set via env var instead)
COPY service_account.jso[n] .

EXPOSE 8000

# Run with gunicorn for production. A single worker is used because the
# SQLite backend serializes writes at the file level - multiple worker
# processes fighting over the same DB file would just cause "database is
# locked" errors instead of adding real concurrency.
CMD ["gunicorn", "--bind", "0.0.0.0:8000", "--workers", "1", "--timeout", "300", "--graceful-timeout", "30", "--worker-tmp-dir", "/dev/shm", "app:app"]
