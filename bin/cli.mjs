#!/usr/bin/env node
// Claude Sentinel — security audit command installer for Claude Code.
// Zero-dep Node CLI. Copies commands from this package into ~/.claude/commands/.
//
// Usage:
//   npx github:TorpedoD/claude-sentinel add           # install everything
//   npx github:TorpedoD/claude-sentinel add <name>    # install one command
//   npx github:TorpedoD/claude-sentinel list          # list available + installed
//   npx github:TorpedoD/claude-sentinel remove <name> # remove a command
//
// Flags:
//   --force / -f   overwrite existing without backup
//   --dry-run      print actions without writing
//   --no-backup    skip .bak backup when overwriting
//   --help / -h    show help

import { readdirSync, existsSync, mkdirSync, cpSync, rmSync, renameSync } from "node:fs";
import { join, dirname, resolve } from "node:path";
import { homedir } from "node:os";
import { fileURLToPath } from "node:url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const PKG_ROOT = resolve(__dirname, "..");
const SRC_COMMANDS = join(PKG_ROOT, "commands");

const CLAUDE_HOME = process.env.CLAUDE_HOME || join(homedir(), ".claude");
const DST_COMMANDS = join(CLAUDE_HOME, "commands");

// --- pretty printing (ANSI, falls back to plain if NO_COLOR) -----------------
const useColor = !process.env.NO_COLOR && process.stdout.isTTY;
const c = (code, s) => (useColor ? `\x1b[${code}m${s}\x1b[0m` : s);
const bold = (s) => c("1", s);
const dim = (s) => c("2", s);
const green = (s) => c("32", s);
const yellow = (s) => c("33", s);
const red = (s) => c("31", s);
const cyan = (s) => c("36", s);

// --- arg parsing -------------------------------------------------------------
const argv = process.argv.slice(2);
const flags = new Set();
const positional = [];
for (const a of argv) {
  if (a.startsWith("--") || /^-[a-zA-Z]$/.test(a)) flags.add(a);
  else positional.push(a);
}
const has = (...names) => names.some((n) => flags.has(n));
const DRY = has("--dry-run");
const FORCE = has("--force", "-f");
const NO_BACKUP = has("--no-backup");
const HELP = has("--help", "-h");

const subcommand = positional[0];
const target = positional[1];

// --- inventory ---------------------------------------------------------------
function listCommands() {
  if (!existsSync(SRC_COMMANDS)) return [];
  return readdirSync(SRC_COMMANDS, { withFileTypes: true })
    .filter((d) => d.isFile() && d.name.endsWith(".md"))
    .map((d) => d.name.replace(/\.md$/, ""));
}

function isInstalledCommand(name) {
  return existsSync(join(DST_COMMANDS, `${name}.md`));
}

// --- filesystem ops ----------------------------------------------------------
function ensureDir(p) {
  if (DRY) return;
  mkdirSync(p, { recursive: true });
}

function backup(path) {
  if (DRY) return;
  const bak = `${path}.bak`;
  if (existsSync(bak)) rmSync(bak, { recursive: true, force: true });
  renameSync(path, bak);
}

function installCommand(name) {
  const src = join(SRC_COMMANDS, `${name}.md`);
  if (!existsSync(src)) {
    console.log(red(`  ✗ command not found: ${name}`));
    return false;
  }
  const dst = join(DST_COMMANDS, `${name}.md`);
  if (existsSync(dst)) {
    if (FORCE && NO_BACKUP) {
      console.log(yellow(`  ⟳ ${name} exists — overwriting`));
      if (!DRY) rmSync(dst, { force: true });
    } else {
      console.log(yellow(`  ⟳ ${name} exists — backing up to ${name}.md.bak`));
      if (!DRY) backup(dst);
    }
  }
  if (!DRY) cpSync(src, dst);
  console.log(green(`  ✓ command: ${name}`));
  return true;
}

function removeCommand(name) {
  const dst = join(DST_COMMANDS, `${name}.md`);
  if (!existsSync(dst)) {
    console.log(dim(`  - command not installed: ${name}`));
    return false;
  }
  if (!DRY) rmSync(dst, { force: true });
  console.log(green(`  ✓ removed command: ${name}`));
  return true;
}

// --- commands ----------------------------------------------------------------
function cmdAdd() {
  const commands = listCommands();

  console.log(bold("→ Claude Sentinel installer"));
  console.log(dim(`  source: ${PKG_ROOT}`));
  console.log(dim(`  target: ${CLAUDE_HOME}`));
  if (DRY) console.log(yellow("  (dry run — no files will be written)"));
  console.log();

  ensureDir(DST_COMMANDS);

  if (target) {
    if (!commands.includes(target)) {
      console.log(red(`Unknown command: ${target}`));
      console.log(dim("Run with `list` to see what's available."));
      process.exit(1);
    }
    installCommand(target);
  } else {
    console.log(bold("Commands"));
    for (const cmd of commands) installCommand(cmd);
  }

  console.log();
  console.log(green("✓ Done."));
  console.log();
  console.log(bold("Next steps:"));
  console.log(`  1. Install scanner binaries (see README for full list):`);
  console.log(dim(`       brew install trivy gitleaks`));
  console.log(dim(`       brew install semgrep osv-scanner syft grype`));
  console.log(`  2. Open Claude Code, ${cyan("cd")} into the repo you want to audit, then run:`);
  console.log(dim(`       /security-scan`));
  console.log(`     Or tell Claude: ${cyan('"Run /security-scan on ~/path/to/my-repo"')}`);
  console.log(`  3. Report is written to ${cyan("<repo>/.security-reports/")}`);
}

function cmdList() {
  const commands = listCommands();
  console.log(bold("Commands") + dim(`  (source → ~/.claude/commands)`));
  for (const cmd of commands) {
    const status = isInstalledCommand(cmd) ? green("installed") : dim("not installed");
    console.log(`  ${cmd}  ${status}`);
  }
}

function cmdRemove() {
  if (!target) {
    console.log(red("Usage: remove <name>"));
    process.exit(1);
  }
  const commands = listCommands();
  if (!commands.includes(target)) {
    console.log(red(`Unknown command: ${target}`));
    process.exit(1);
  }
  removeCommand(target);
}

function cmdHelp() {
  console.log(`${bold("claude-sentinel")} — 12-tool security audit for Claude Code
${dim("repo: https://github.com/TorpedoD/claude-sentinel")}

${bold("Usage")}
  npx github:TorpedoD/claude-sentinel ${cyan("add")}              install all commands
  npx github:TorpedoD/claude-sentinel ${cyan("add <name>")}       install one
  npx github:TorpedoD/claude-sentinel ${cyan("list")}             show available / installed
  npx github:TorpedoD/claude-sentinel ${cyan("remove <name>")}    uninstall one

${bold("Flags")}
  --force, -f     overwrite existing (still backs up to .bak unless --no-backup)
  --no-backup     skip .bak backup when overwriting
  --dry-run       print what would happen without touching the filesystem
  --help, -h      show this message

${bold("Environment")}
  CLAUDE_HOME     override target directory (default: ~/.claude)
  NO_COLOR        disable ANSI colors

${bold("Examples")}
  npx github:TorpedoD/claude-sentinel add
  npx github:TorpedoD/claude-sentinel list
  npx github:TorpedoD/claude-sentinel add security-scan --dry-run
  CLAUDE_HOME=/tmp/claude-test npx github:TorpedoD/claude-sentinel add --dry-run
`);
}

// --- entry -------------------------------------------------------------------
if (HELP || !subcommand) {
  cmdHelp();
  process.exit(0);
}

try {
  switch (subcommand) {
    case "add":
    case "install":
      cmdAdd();
      break;
    case "list":
    case "ls":
      cmdList();
      break;
    case "remove":
    case "uninstall":
    case "rm":
      cmdRemove();
      break;
    case "help":
      cmdHelp();
      break;
    default:
      console.log(red(`Unknown command: ${subcommand}`));
      console.log();
      cmdHelp();
      process.exit(1);
  }
} catch (err) {
  console.error(red("✗ Error:"), err.message);
  if (process.env.DEBUG) console.error(err.stack);
  process.exit(1);
}
