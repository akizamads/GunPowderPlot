# Security Policy

Repository: <https://github.com/akizamads/GunPowderPlot>

This project is an offensive security toolkit. It contains exploit modules, payload
generators, brute-force helpers and a C2 console. Read this before cloning, forking or
publishing a fork.

## Authorized use only

Use VULNSCAN PRO exclusively against systems you own or have **written** permission to
test (penetration testing engagements, bug bounty programs, your own labs). Unauthorized
scanning or exploitation is illegal in most jurisdictions and is not supported.

## What must never be committed

The repository `.gitignore` already excludes these, but double-check before pushing:

| Item                                    | Why                                                          |
| --------------------------------------- | ------------------------------------------------------------ |
| `.env`, `config.local.yaml`             | API keys, C2 shared secrets, proxy credentials               |
| `c2_state.json`                         | C2 session list and queued tasks from a live engagement      |
| `reports/`, `report.json`, `report.csv` | Contain target hostnames, banners and findings (client data) |
| `*.pem`, `*.key`                        | Private keys used for TLS or C2 encryption                   |

Run `git status` and `git diff --cached` before the first push and confirm none of the
paths above are staged. To purge a secret that already landed in history, rotate the
secret **first**, then rewrite history (`git filter-repo` or the BFG).

## Operator responsibilities

1. **Scope** — every engagement must have a written scope and rules of engagement.
2. **Rate limits** — brute-force (`bruteforce`) and `auto-exploit` can disrupt services; keep `-j` low.
3. **C2 (`c2-server` / `c2-agent`)** — bind to lab networks only, always set a strong `--key`,
   and never point agents at third-party infrastructure.
4. **Data** — post-exploitation output can contain credentials and PII. Treat report files as
   sensitive client data and delete them when the engagement ends.
5. **Metasploit (`msf-integration`)** — requires an RPC instance you control; do not point it at
   someone else's Metasploit.

## Reporting a vulnerability in this tool

If you find a security issue in the toolkit itself (for example a payload that escapes its
intended context, or a C2 message that can be replayed), please open a private security
advisory on [GitHub](https://github.com/akizamads/GunPowderPlot/security/advisories/new)
rather than a public issue, and include:

- affected command or module
- a minimal reproduction
- expected vs. actual behaviour

## Deployment notes

The Docker image runs as the non-root user `scanner` (UID 1000) and the compose file mounts
`./reports` into the container. Do not mount the Docker socket or the host filesystem into
the scanner container.
