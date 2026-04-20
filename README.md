# claude-sentinel

12-tool security audit for Claude Code. One slash command runs trivy, gitleaks, semgrep, osv-scanner, npm audit, pip-audit, syft, grype, snyk-agent-scan, skill-scanner, and tirith in parallel — with strict read-only sandboxing and anti-prompt-injection guards baked in.

## Install

```bash
npx github:TorpedoD/claude-sentinel add
```

This copies `security-scan.md` into `~/.claude/commands/`. No npm publish, no registry — pulls straight from GitHub.

## Usage

`cd` into the repo you want to audit, open Claude Code, and run:

```
/security-scan
```

For clarity, **tell Claude which repo to scan**. This avoids any ambiguity about which directory is the target:

```
Run /security-scan on ~/code/my-project
```

```
/security-scan — scan the repo at /Users/me/work/api-server
```

The scan writes a Markdown report to:

```
<repo>/.security-reports/security-report-<repo>-<date>.md
```

Add `.security-reports/` to the repo's `.gitignore` to keep reports local.

## Required binaries

Install the scanner tools before running:

```bash
# Core
brew install trivy gitleaks semgrep osv-scanner syft grype

# Python dep auditing
pip install pip-audit        # or: pipx install pip-audit

# Optional — AI agent / MCP security (requires SNYK_TOKEN env var)
# brew install snyk/tap/snyk-agent-scan

# Optional — Claude Code skill safety (Cisco AI Defense)
# Install skill-scanner and tirith per their respective docs
```

## What gets scanned

| # | Tool | Category |
|---|------|----------|
| 1 | trivy fs | CVE vulnerabilities (HIGH/CRITICAL) |
| 2 | gitleaks | Secrets & credentials in files + git history |
| 3 | semgrep | SAST — code-level security issues |
| 4 | osv-scanner | Open source dependency vulnerabilities (OSV DB) |
| 5 | npm audit | Node.js dependency vulnerabilities |
| 6 | pip-audit | Python dependency vulnerabilities |
| 7 | syft | SBOM generation |
| 8 | grype | SBOM vulnerability scan (wave 2, runs after syft) |
| 9 | trivy config | IaC / infrastructure config misconfigurations |
| 10 | snyk-agent-scan | AI agent / MCP server security |
| 11 | skill-scanner | Claude Code skill package safety (Cisco AI Defense) |
| 12 | tirith | Hidden content, bidi overrides, config poisoning |

## Safety model

The scanner runs in a strict two-layer isolation architecture:

- **Execution layer:** trusted scanner binaries (resolved to absolute paths at startup) receive repo files as data input and write JSON to a temp directory (`/tmp/security-scan-<ts>/`).
- **Interpretation layer:** Claude reads only the temp directory outputs — never any path inside the scanned repo.

Bash blocks in the command will never run `npm install`, execute scripts from the repo, or follow instructions found inside repo files. Repository content is treated as untrusted data throughout.

## Report output

- Written to `<scanned-repo>/.security-reports/security-report-<repo>-<date>.md`
- Add `.security-reports/` to your `.gitignore`
- Summary table printed to Claude's response immediately after the scan

## Uninstall

```bash
npx github:TorpedoD/claude-sentinel remove security-scan
```

## License

MIT — © 2026 TorpedoD
