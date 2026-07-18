FROM python:3.12-slim

# Install ODBC Driver 18 for SQL Server
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
       curl apt-transport-https gnupg2 \
    && curl -fsSL https://packages.microsoft.com/keys/microsoft.asc | gpg --dearmor -o /usr/share/keyrings/microsoft-prod.gpg \
    && echo "deb [signed-by=/usr/share/keyrings/microsoft-prod.gpg] https://packages.microsoft.com/debian/12/prod bookworm main" > /etc/apt/sources.list.d/mssql-release.list \
    && apt-get update \
    && ACCEPT_EULA=Y apt-get install -y --no-install-recommends msodbcsql18 unixodbc-dev \
    && apt-get purge -y --auto-remove curl apt-transport-https gnupg2 \
    && rm -rf /var/lib/apt/lists/* \
    # Fail the build loudly (instead of failing at runtime) if a stale/corrupted
    # build-cache layer ever leaves odbcinst.ini pointing at a driver file that
    # doesn't actually exist on disk.
    && ls /opt/microsoft/msodbcsql18/lib64/libmsodbcsql-*.so.*

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

# Run with gunicorn for production
CMD ["gunicorn", "--bind", "0.0.0.0:8000", "--workers", "4", "--timeout", "300", "--graceful-timeout", "30", "--worker-tmp-dir", "/dev/shm", "app:app"]
