# claude-sentinel

> Security audit slash command for Claude Code — 12 scanners, one command.

![License](https://img.shields.io/github/license/TorpedoD/claude-sentinel)
![Last Commit](https://img.shields.io/github/last-commit/TorpedoD/claude-sentinel)
![Release](https://img.shields.io/github/v/release/TorpedoD/claude-sentinel)

12-tool security audit for Claude Code. One slash command runs trivy, gitleaks, semgrep, osv-scanner, npm audit, pip-audit, syft, grype, snyk-agent-scan, skill-scanner, and tirith in parallel — with strict read-only sandboxing and anti-prompt-injection guards baked in.

## Install

```bash
npx github:TorpedoD/claude-sentinel add
```

This copies `security-scan.md` into `~/.claude/commands/`. No npm publish, no registry — pulls straight from GitHub.

## Usage

**claude-sentinel runs from *outside* the repo it is auditing.** Create a project folder, clone the target repo inside it, then open Claude from the project folder — not from inside the clone:

```bash
mkdir ~/audits/acme-audit && cd ~/audits/acme-audit
git clone https://github.com/acme/api-server.git
claude
```

Then in Claude:

```
/security-scan
```

The command auto-detects the single `.git` subdirectory (`api-server/` here) as the scan target. It refuses to run if your current directory is itself a git repo — that would put Claude's shell *inside* the code being audited, which is exactly what the isolation model prevents.

**Why outside the clone?** Scanner tools treat the target as data. If Claude's shell lives inside the target, any compromised file (hook, pre-commit, dotfile, script buried in a README) is one stray command away from executing. Keeping the shell in a clean outer folder means the target repo is never Claude's CWD — it's only ever a path argument passed to trusted scanner binaries.

**Scanning multiple repos:** use a fresh project folder per scan, each containing exactly one clone. The auto-detector errors if it finds zero or multiple `.git` subdirectories.

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
| 1 | [trivy fs](https://github.com/aquasecurity/trivy) | CVE vulnerabilities (HIGH/CRITICAL) |
| 2 | [gitleaks](https://github.com/gitleaks/gitleaks) | Secrets & credentials in files + git history |
| 3 | [semgrep](https://github.com/semgrep/semgrep) | SAST — code-level security issues |
| 4 | [osv-scanner](https://github.com/google/osv-scanner) | Open source dependency vulnerabilities (OSV DB) |
| 5 | [npm audit](https://docs.npmjs.com/cli/v10/commands/npm-audit) | Node.js dependency vulnerabilities |
| 6 | [pip-audit](https://github.com/pypa/pip-audit) | Python dependency vulnerabilities |
| 7 | [syft](https://github.com/anchore/syft) | SBOM generation |
| 8 | [grype](https://github.com/anchore/grype) | SBOM vulnerability scan (wave 2, runs after syft) |
| 9 | [trivy config](https://github.com/aquasecurity/trivy) | IaC / infrastructure config misconfigurations |
| 10 | [snyk-agent-scan](https://github.com/snyk/agent-scan) | AI agent / MCP server security |
| 11 | [skill-scanner](https://github.com/cisco-ai-defense/skill-scanner) | Claude Code skill package safety (Cisco AI Defense) |
| 12 | [tirith](https://github.com/sheeki03/tirith) | Hidden content, bidi overrides, config poisoning |

## Safety model

claude-sentinel enforces three isolation boundaries:

1. **Shell boundary** — Claude's working directory stays in the outer project folder. The scanner never `cd`s into the cloned repo. Tools that accept a path flag get `$SCAN_TARGET` as an explicit argument; tools without one (npm audit, pip-audit, snyk-agent-scan) run inside scoped `bash -c "cd <target> && tool"` subshells so only that subprocess ever touches the repo.
2. **Execution boundary** — Trusted scanner binaries are resolved to absolute paths via `command -v` at startup. Scanners read repo files as data and write JSON output to a fresh temp directory (`/tmp/security-scan-<ts>/`). Bash blocks never run `npm install`, execute scripts from the repo, or follow instructions found inside repo files.
3. **Interpretation boundary** — Claude reads only the scanner JSON outputs from the temp directory. Repo file contents are never sourced into the conversation, so nothing inside the audited code can steer Claude's behavior via prompt injection.

## Report output

The scan writes a single Markdown report to the **project folder** (one level above the clone):

```
<project-folder>/security-report-<repo>-<YYYY-MM-DD>.md
```

Reports live outside the cloned repo by design — no `.gitignore` edits needed, and re-cloning the target never overwrites or leaks audit history. A summary table is also printed to Claude's response immediately after the scan completes.

## Uninstall

```bash
npx github:TorpedoD/claude-sentinel remove security-scan
```

## License

MIT — © 2026 TorpedoD
