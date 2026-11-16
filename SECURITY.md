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

## Keep the published code intact

If you want the code as published to stay identical to what you shipped, use these
controls. None of them can stop a determined person from running a modified copy — a
public repository is always forkable and a downloaded Python file is always editable —
but they do catch accidental and casual modification.

### 1. Branch protection (do this in the browser once)

`Settings` → `Branches` → `Add branch ruleset` for `main`:

- **Require a pull request before merging** — nobody pushes straight to `main`, not even you.
- **Require approvals: 1** and **Dismiss stale approvals** — changes need a second pair of eyes.
- **Block force pushes** and **Restrict deletions**.
- **Require status checks: `check`** — the CI job from `.github/workflows/ci.yml` must pass.
- **Require linear history** so history cannot be rewritten silently.
- **Restrict who can push** to `main` (under *Rules* → *Bypass list*), typically just you.

### 2. Signed commits

Unsigned commits can be amended and re-pushed by anyone with write access. Sign yours so
the GitHub UI shows a **Verified** badge, and reviewers can tell a genuine commit from a
rewritten one:

```bash
ssh-keygen -t ed25519 -C "signing" -f ~/.ssh/id_ed25519_signing
# add the .pub key to GitHub as a *Signing Key*:
# https://github.com/settings/ssh/new  ->  Key type: Signing Key
git config --global gpg.format ssh
git config --global user.signingkey ~/.ssh/id_ed25519_signing
git config --global commit.gpgsign true
```

### 3. Integrity manifest

Record the SHA-256 of every shipped file so a modified copy can be detected. Generate it
from a clean checkout and keep it in the release, not in the repository:

```bash
git ls-files -z | xargs -0 sha256sum > SHA256SUMS
git show HEAD:SHA256SUMS >/dev/null    # only if you deliberately committed it
```

Then anyone can verify a download with `sha256sum -c SHA256SUMS`.

### 4. Rerelease artifacts

Tag releases (`v3.1.0`) and attach the archive plus `SHA256SUMS` to **Releases** instead
of letting people grab a mutable branch tarball. Tags can be protected the same way as
branches (`Settings` → `Rules` → `Target tags`).

### 5. Local guard hook

`.githooks/pre-commit` blocks committing reports, `config.local.yaml`, `c2_state.json`,
`.env` files, private keys and `__pycache__`. Enable it in every clone you work from:

```bash
git config core.hooksPath .githooks
```

### What this does *not* protect against

Anyone can `git clone`, edit `smoke_check.py` or any other file locally, and run it. If the
behaviour of the code must be trusted remotely, the enforcement has to live on your side:
verify the `SHA256SUMS` of a release, require signed commits on `main`, and never run a
fork's code against real infrastructure. Do not put real API keys or C2 secrets in the
repository — a client with a case can replace a local file, but they cannot recover a key
you never published.

## Deployment notes

The Docker image runs as the non-root user `scanner` (UID 1000) and the compose file mounts
`./reports` into the container. Do not mount the Docker socket or the host filesystem into
the scanner container.
