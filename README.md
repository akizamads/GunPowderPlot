# GunPowderPlot — VULNSCAN PRO

An offensive security toolkit: 16 modules for reconnaissance, web/TLS/credential
assessment, CVE checks, exploitation, WAF evasion, C2 and a **global country scan** that
finds and probes the public web surface of every country automatically.

> ⚠️ **Authorized use only.** Run this against systems you own or have written permission
> to test. Unauthorized scanning or exploitation is illegal. Read [SECURITY.md](SECURITY.md)
> before you clone, fork or run anything.

## Highlights

| Area | What you get |
|------|--------------|
| Recon | Port scanning, DNS, service fingerprinting, SSL/TLS |
| Web | SQLi, XSS, CSRF, misconfiguration, security headers |
| Crypto | Weak algorithms, TLS versions, weak ciphers |
| Credentials | Default-credential checks and brute-force (SSH, FTP, MySQL, PostgreSQL) |
| Supply chain | CVE matching against `requirements.txt` / `package.json` |
| Exploitation | SQLi exploiter, payload generator, auto-exploit orchestrator, WAF bypass |
| Post-exploitation | System/user/process/credential enumeration, C2 console |
| **Global** | **Every country's public IPv4 blocks, sampled and probed — [GLOBAL_SCAN.md](GLOBAL_SCAN.md)** |

## Quick start

```bash
git clone https://github.com/akizamads/GunPowderPlot.git
cd GunPowderPlot
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

python main.py --list                  # interactive console + module table
python cli.py --help                   # scriptable commands
python smoke_check.py                  # environment check
python -m unittest discover -s tests   # offline test suite
```

`nmap`, `curl` and `dnsutils` are used by the network modules:
`sudo apt install -y nmap curl dnsutils`.

## Two entry points

- **`main.py`** — the interactive console (also the Docker entrypoint):
  `python main.py`, `python main.py --list`, `python main.py --module 16 --countries PH --save`.
- **`cli.py`** — scriptable subcommands:

```bash
python cli.py scan -t example.com --port 80,443      # recon
python cli.py web-scan -t example.com                # SQLi / XSS
python cli.py crypto-scan -t example.com             # TLS policy
python cli.py auth-scan -t mysql:10.0.0.5            # default creds
python cli.py dependency-scan --manifest requirements.txt
python cli.py global-scan -c PH,ID,JP --samples 2    # countries
```

## The global scan, in one paragraph

Module 16 (`python cli.py global-scan`) starts from the 249 ISO country codes, downloads
each country's delegated IPv4 blocks from a public prefix report, picks the largest few,
takes **one sample address per block**, confirms the country with an RDAP lookup, and then
does a TCP handshake on 80/8443/443/8080 plus a TLS certificate peek. No address sweeps,
no payloads, no credentials. Antarctica and similar territories with no delegated blocks
report `no-prefix-data` rather than guessing. Full flags, limits and the JSON schema are
in [GLOBAL_SCAN.md](GLOBAL_SCAN.md).

```bash
python cli.py global-scan --samples 1 -o reports/global.json   # all countries
```

## Docker

```bash
docker build -t vuln-scanner .
docker run -it --rm vuln-scanner                      # interactive console
docker run --rm vuln-scanner python cli.py --help     # scripted commands
```

The image runs as the non-root user `scanner`; compose with test services:
`docker compose up -d`.

## Documentation

- [GLOBAL_SCAN.md](GLOBAL_SCAN.md) — the country scan: pipeline, flags, limits, schema
- [ADVANCED_FEATURES.md](ADVANCED_FEATURES.md) — detection modules and commands
- [EXPLOIT_TOOLS.md](EXPLOIT_TOOLS.md) — exploitation, payloads, brute-force
- [ORCHESTRATION_GUIDE.md](ORCHESTRATION_GUIDE.md) — auto-exploit, WAF bypass, Metasploit
- [SECURITY.md](SECURITY.md) — authorized use, secrets, branch protection, verification
- [BUILD_SUMMARY.md](BUILD_SUMMARY.md), [README_FINAL.md](README_FINAL.md) — feature summary

## Repository layout

```
main.py              interactive console (Docker entrypoint)
cli.py               scriptable CLI
global_scan.py       country -> prefixes -> sample -> probe engine (module 16)
scanner.py           core recon engine
*_scanner.py         web / crypto / auth / misconfig / dependency modules
core/                banner, prompts, menu engine, report export
modules/             16 numbered modules used by the console
tests/               offline unit tests
```

## License

MIT — see [LICENSE](LICENSE).
