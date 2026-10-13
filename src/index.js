import { readFileSync, statSync, readdirSync } from 'node:fs';
import { join, relative, extname } from 'node:path';
import { buildReport, exceeds, exitCode, formatText, formatJson, formatSarif, formatMarkdown, SEVERITIES, ConfigError, validateConfig } from './core.js';
import { RULES } from './rules.js';
import { refang, refangText, defangText, defangValue, findLive, checkText, STYLES, REFERENCE_DOMAINS } from './defang.js';

export { refang, refangText, defangText, defangValue, findLive, checkText, STYLES, REFERENCE_DOMAINS, RULES, exceeds, exitCode, formatText, formatJson, formatSarif, formatMarkdown, SEVERITIES, ConfigError };
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
