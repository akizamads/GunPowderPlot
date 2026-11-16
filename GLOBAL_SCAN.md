# 🌍 Global Country Scan (module 16 / `global-scan`)

Finds and probes the **public web surface of every country** automatically, without you
typing a single hostname. It resolves which address blocks belong to each country, picks
one representative host per block and checks which web ports answer.

> ⚠️ **Authorized use only.** This touches third-party public hosts. Use it for research
> on your own authorized scope, with low `--samples`, or not at all. See
> [SECURITY.md](SECURITY.md).

## How the "automatic" part works

```
country list (249 ISO codes)
        │
        ▼
ipverse/country-ip-blocks  ──►  country/<cc>/ipv4-aggregated.txt
        │                        (public IPv4 blocks delegated to that country)
        ▼
largest N prefixes per country  ──►  one sample address each
        │
        ▼
RDAP lookup (rdap.org)  ──►  reject the sample if the record says another country
        │
        ▼
TCP connect on 80 / 8443 / 443 / 8080  +  TLS certificate peek
        │
        ▼
JSON report: per-country status, samples, reachable hosts
```

Nothing is brute-forced: no IP sweep, no payloads, no credentials. One address per
prefix, four TCP handshakes, one TLS handshake.

## Usage

```bash
# Interactive menu
python main.py                 # pick [16] Global Country Scan

# One country
python cli.py global-scan -c PH

# Several countries (repeatable or comma-separated)
python cli.py global-scan -c PH,ID,JP -c SG

# The whole world, one prefix per country, saved to JSON
python cli.py global-scan --samples 1 -o reports/global.json

# Offline / reproducible run from a local CIDR file
python cli.py global-scan -c PH --prefix-source data/ph-prefixes.txt
```

| Flag | Meaning |
|------|---------|
| `-c, --country` | ISO 3166-1 alpha-2 code, repeatable or comma-separated. Omit = all 249 |
| `--samples` | Prefixes inspected per country (1–20, default 5) |
| `--prefix-source` | Use a local file (`one CIDR per line`) instead of downloading |
| `--workers` | Parallel country probes (max 8) |
| `-o, --output` | Write the JSON report to a file |

Through `main.py`:

```bash
python main.py --module 16 --countries PH,ID --samples 2 --save
```

## What you get

```
   PH  Philippines                       2 sample(s) 1 reachable
   ID  Indonesia                         2 sample(s) 0 reachable
   AQ  Antarctica                        no-prefix-data
[+] 2 countries with data, 1 reachable hosts, 18.4s
```

Per country in the JSON: `status` (`ok`, `no-prefix-data`, `no-samples`, `error`),
`prefixes`, `samples`, `reachable_hosts`, and for each sample `ip`, `prefix`,
`reported_country`, `open_ports` and the TLS `version`/`subject` when a TLS port answers.

## Reality check — please read

- **"All countries" is not "all IPs".** A default run inspects ~5 prefixes × 249 countries
  ≈ 1,200 addresses. The full address space is billions of addresses; scanning it is not
  what this does and never should.
- **Some countries return no data.** Antarctica, Bouvet Island and similar have no
  delegated blocks, so they report `no-prefix-data` instead of failing.
- **The first address of a block is often a router or unused**, which is why many samples
  show `0 reachable`. Raise `--samples` for better coverage, not `--workers`.
- **RDAP is a filter, not a scanner.** It only tells us whether a block is really
  delegated to the country we are attributing it to.
- **Reporting ≠ permission.** Finding an open panel abroad does not authorize touching it.

## Tests

```bash
python -m unittest discover -s tests -v
```

The suite is fully offline: it uses `tests/fixtures/prefixes.txt` and `127.0.0.1`
instead of the network, and covers country-code parsing, prefix selection, sample
address picking, closed-port behaviour and the report schema.
