# Contributing to claude-sentinel

Thanks for your interest in improving claude-sentinel.

## Reporting issues

Open a GitHub issue with:
- The scanner that failed (if applicable)
- Your OS and `gh --version` / `node --version`
- The exact command you ran and the output

## Local development

1. Clone the repo
2. Copy the skill into place: `cp -r skills/security-scan ~/.claude/skills/security-scan`
3. Edit `~/.claude/skills/security-scan/SKILL.md` to test, then copy back when done

## Pull requests

- Keep changes focused — one concern per PR
- Do not add new scanner tools without discussion in an issue first
- The safety model (two-layer isolation, no execution of repo content) is non-negotiable
- Update `README.md` if you change install steps, required binaries, or output paths

## License

By contributing, you agree your contributions are licensed under the MIT license.
