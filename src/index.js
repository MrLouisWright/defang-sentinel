import { readFileSync, writeFileSync, statSync, readdirSync, existsSync, mkdirSync, chmodSync } from 'node:fs';
import { join, relative, extname, dirname } from 'node:path';
import { buildReport, exceeds, exitCode, formatText, formatJson, formatSarif, formatMarkdown, SEVERITIES, ConfigError, validateConfig } from './core.js';
import { RULES } from './rules.js';
import { refang, refangValue, refangText, defangText, defangValue, findLive, checkText, splitCode, STYLES, REFERENCE_DOMAINS } from './defang.js';

export { refang, refangValue, splitCode, refangText, defangText, defangValue, findLive, checkText, STYLES, REFERENCE_DOMAINS, RULES, exceeds, exitCode, formatText, formatJson, formatSarif, formatMarkdown, SEVERITIES, ConfigError };
export const VERSION = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8')).version;
export const TOOL = { name: 'defang-sentinel', version: VERSION, rules: RULES, title: 'defang-sentinel', emoji: '🧯', defaultFailOn: 'medium' };

export const DEFAULT_EXTENSIONS = ['.md', '.markdown', '.txt', '.rst', '.adoc', '.html', '.htm', '.csv', '.json', '.yml', '.yaml', '.xml', '.eml', '.log', '.ioc', '.rules', '.yar', '.yara', '.org', '.tex'];
const SKIP = new Set(['.git', 'node_modules', '.hg', '.svn', 'dist', 'vendor']);
function walk(p, exts, out = []) {
  const st = statSync(p);
  if (st.isDirectory()) { for (const e of readdirSync(p).sort()) if (!SKIP.has(e)) walk(join(p, e), exts, out); }
  else if (st.isFile()) out.push(p);
  return out;
}

/**
 * Check files/directories (or in-memory texts) for live indicators.
 * Directories are walked for DEFAULT_EXTENSIONS (override with opts.extensions); explicit files are always checked.
 */
export function check(inputs, opts = {}) {
  validateConfig({ allow: opts.allow, severity: opts.severity });
  const exts = (opts.extensions || DEFAULT_EXTENSIONS).map((e) => (e.startsWith('.') ? e : `.${e}`).toLowerCase());
  const results = [];
  for (const inp of inputs) {
    if (typeof inp === 'object') { const raw = checkText(inp.text, inp.name, opts); results.push({ target: inp.name, raw, summary: { live: raw.length } }); continue; }
    let files;
    try {
      const isDir = statSync(inp).isDirectory();
      files = walk(inp, exts).filter((f) => !isDir || exts.includes(extname(f).toLowerCase()));
    } catch (e) { results.push({ target: inp, fatal: true, raw: [], errors: [`Cannot read ${inp}: ${e.code || e.message}`] }); continue; }
    for (const f of files) {
      const buf = readFileSync(f);
      if (buf.subarray(0, 8000).includes(0)) continue; // binary
      const name = relative(process.cwd(), f) || f;
      const raw = checkText(buf.toString('utf8'), name, opts);
      results.push({ target: name, raw });
    }
  }
  return buildReport(TOOL, results, opts);
}

const MARKUP = new Set(['.md', '.markdown', '.html', '.htm', '.rst', '.adoc']);
/**
 * Fix mode: defang live indicators in place in files/directories.
 * Markdown/HTML files are rewritten code-aware (code blocks and inline code untouched) unless opts.skipCode === false.
 * Reference domains and opts.ignoreDomains stay live. Returns [{ file, changes }] for files that changed.
 * @param {string[]} inputs
 * @param {{style?: string, ignoreDomains?: string[], referenceDomains?: boolean, includePrivate?: boolean, skipCode?: boolean, extensions?: string[], dryRun?: boolean}} [opts]
 */
export function fix(inputs, opts = {}) {
  const exts = (opts.extensions || DEFAULT_EXTENSIONS).map((e) => (e.startsWith('.') ? e : `.${e}`).toLowerCase());
  const ignoreDomains = [...(opts.referenceDomains === false ? [] : REFERENCE_DOMAINS), ...(opts.ignoreDomains || [])];
  const out = [];
  for (const inp of inputs) {
    const isDir = statSync(inp).isDirectory();
    for (const f of walk(inp, exts).filter((x) => !isDir || exts.includes(extname(x).toLowerCase()))) {
      const buf = readFileSync(f); if (buf.subarray(0, 8000).includes(0)) continue;
      const skipCode = opts.skipCode ?? MARKUP.has(extname(f).toLowerCase());
      const r = defangText(buf.toString('utf8'), { style: opts.style, ignoreDomains, includePrivate: opts.includePrivate, skipCode });
      if (r.changes) { if (!opts.dryRun) writeFileSync(f, r.text); out.push({ file: relative(process.cwd(), f) || f, changes: r.changes }); }
    }
  }
  return out;
}

export const PRE_COMMIT_HOOK = `#!/bin/sh
# defang-sentinel pre-commit hook: block commits that add live IOCs to docs/reports.
files=$(git diff --cached --name-only --diff-filter=ACM | grep -Ei '\\.(md|markdown|txt|rst|adoc|html?|csv|ioc|yara?)$')
[ -z "$files" ] && exit 0
exec npx --no-install defang-sentinel check --skip-code $files
`;
/** Install a git pre-commit hook in repoDir (default cwd). Refuses to overwrite a foreign hook unless force. Returns the hook path. */
export function installHook(repoDir = process.cwd(), { force = false } = {}) {
  const gitDir = join(repoDir, '.git');
  if (!existsSync(gitDir)) throw new Error(`No .git directory in ${repoDir}`);
  const hook = join(gitDir, 'hooks', 'pre-commit');
  if (existsSync(hook) && !force && !readFileSync(hook, 'utf8').includes('defang-sentinel')) throw new Error(`${hook} already exists (use --force to overwrite)`);
  mkdirSync(dirname(hook), { recursive: true });
  writeFileSync(hook, PRE_COMMIT_HOOK); chmodSync(hook, 0o755);
  return hook;
}
