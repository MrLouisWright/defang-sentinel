#!/usr/bin/env node
import { readFileSync, writeFileSync } from 'node:fs';
import { runCli, list, UsageError } from '../src/cli-core.js';
import { check, defangText, refangText, TOOL, STYLES, DEFAULT_EXTENSIONS } from '../src/index.js';

const HELP = `defang-sentinel {VERSION} — defang/refang IOCs and keep live indicators out of reports

Usage:
  defang-sentinel defang [file|-] [--style s] [--write]   make URLs, domains, IPs, emails safe to share
  defang-sentinel refang [file|-] [--write]               turn hxxps://evil[.]com back into https://evil.com
  defang-sentinel [check] <file|dir...> [options]         fail on live indicators (default command)

Defang/refang
      --style <s>            ${STYLES.join(' | ')} (default brackets)
                               brackets: hxxps://evil[.]com/a.php   full: hxxps[://]evil[.]com/a[.]php
                               dot: hxxps://evil[dot]com            minimal: hxxps://www.evil[.]com
  -w, --write                Rewrite the file in place instead of printing
Check
      --ignore-domain <list> Domains that may stay live (globs ok, repeatable)
      --no-reference-domains Also flag links to mitre.org, nvd.nist.gov, virustotal.com, github.com etc.
      --include-private      Also flag private/loopback IPs
      --skip-code            Ignore fenced code blocks in Markdown
      --ext <list>           Extensions to scan in directories (default ${DEFAULT_EXTENSIONS.slice(0, 6).join(',')},...)
{COMMON}`;

const read = (f) => (f === '-' || f === undefined ? readFileSync(0, 'utf8') : readFileSync(f, 'utf8'));
process.exitCode = await runCli(TOOL, {
  help: HELP,
  options: {
    style: { type: 'string' }, write: { type: 'boolean', short: 'w' }, 'ignore-domain': { type: 'string', multiple: true },
    'no-reference-domains': { type: 'boolean' }, 'include-private': { type: 'boolean' }, 'skip-code': { type: 'boolean' }, ext: { type: 'string' },
  },
  run(o, pos, cfg, ctx) {
    let [cmd, ...rest] = pos;
    if (!['defang', 'refang', 'check'].includes(cmd)) { rest = pos; cmd = 'check'; }
    const style = o.style || cfg.style || 'brackets';
    if (!STYLES.includes(style)) throw new UsageError(`Invalid --style ${style}`);
    const ignoreDomains = [...(cfg.ignoreDomains || []), ...list(o['ignore-domain'])];
    if (cmd === 'defang' || cmd === 'refang') {
      if (rest.length > 1) throw new UsageError(`${cmd} takes one file (or - for stdin)`);
      let input; try { input = read(rest[0]); } catch (e) { throw new UsageError(`Cannot read ${rest[0]}: ${e.code}`); }
      const r = cmd === 'defang' ? defangText(input, { style, ignoreDomains, includePrivate: o['include-private'] }) : refangText(input);
      if (o.write) {
        if (!rest[0] || rest[0] === '-') throw new UsageError('--write needs a file');
        writeFileSync(rest[0], r.text); ctx.io.stderr.write(`${cmd}: ${r.changes} change(s) written to ${rest[0]}\n`); return 0;
      }
      ctx.io.stdout.write(r.text); return 0;
    }
    const paths = rest.length ? rest : cfg.paths || [];
    if (!paths.length) throw new UsageError('No files or directories to check');
    return check(paths.map((p) => (p === '-' ? { name: 'stdin', text: read('-') } : p)), {
      ignoreDomains, referenceDomains: o['no-reference-domains'] ? false : cfg.referenceDomains, includePrivate: o['include-private'] ?? cfg.includePrivate,
      skipCode: o['skip-code'] ?? cfg.skipCode, extensions: o.ext ? list(o.ext) : cfg.extensions, style, allow: cfg.allow, severity: cfg.severity,
    });
  },
});
