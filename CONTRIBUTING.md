# Contributing to claude-sentinel

Thanks for your interest in improving claude-sentinel.

## Reporting issues

Open a GitHub issue with:
- The scanner that failed (if applicable)
- Your OS and `gh --version` / `node --version`
- The exact command you ran and the output

## Local development

1. Clone the repo
2. Run `node bin/cli.mjs add` to install the command into `~/.claude/commands/`
3. Edit `commands/security-scan.md` and re-run the installer to test

## Pull requests

- Keep changes focused — one concern per PR
- Do not add new scanner tools without discussion in an issue first
- The safety model (two-layer isolation, no execution of repo content) is non-negotiable
- Update `README.md` if you change install steps, required binaries, or output paths

## License

By contributing, you agree your contributions are licensed under the MIT license.
