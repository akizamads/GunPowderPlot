FROM python:3.11-slim

WORKDIR /app

# Install system dependencies for network tools
RUN apt-get update && apt-get install -y \
    nmap \
    curl \
    dnsutils \
    net-tools \
    && rm -rf /var/lib/apt/lists/*

# Copy application files
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY scanner.py .
COPY web_scanner.py .
COPY crypto_scanner.py .
COPY auth_scanner.py .
COPY misconfig_scanner.py .
COPY dependency_scanner.py .
COPY sqli_exploiter.py .
COPY bruteforce_exploiter.py .
COPY payload_generator.py .
COPY post_exploiter.py .
COPY msf_integration.py .
COPY waf_bypass.py .
COPY exploit_orchestrator.py .
COPY reporter.py .
COPY platform_core.py .
COPY c2_module.py .
COPY global_scan.py .
COPY cli.py .
COPY main.py .
COPY smoke_check.py .
COPY core/ ./core/
COPY modules/ ./modules/
COPY tests/ ./tests/

# Create non-root user and give ownership of the app dir
RUN useradd -m -u 1000 scanner && mkdir -p /app/reports && chown -R scanner:scanner /app
USER scanner

ENTRYPOINT ["python", "main.py"]
