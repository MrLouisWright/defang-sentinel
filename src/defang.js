import { TLDS, FILE_EXT } from './tlds.js';

export const STYLES = ['brackets', 'full', 'dot', 'minimal', 'paren', 'colon'];
// Reference sites that threat reports link to on purpose. Used by check() unless disabled.
export const REFERENCE_DOMAINS = ['attack.mitre.org', 'mitre.org', 'cve.org', '*.cve.org', 'cve.mitre.org', 'nvd.nist.gov', 'nist.gov', 'cisa.gov', '*.cisa.gov', 'ncsc.gov.uk', '*.ncsc.gov.uk', 'virustotal.com', '*.virustotal.com', 'bazaar.abuse.ch', 'urlhaus.abuse.ch', 'threatfox.abuse.ch', 'abuse.ch', 'otx.alienvault.com', 'shodan.io', 'www.shodan.io', 'urlscan.io', 'github.com', 'docs.github.com', 'opensource.org', 'spdx.org', 'npmjs.com', 'www.npmjs.com', 'schema.org', 'json.schemastore.org', 'www.w3.org', 'w3.org', 'img.shields.io', 'learn.microsoft.com', 'msrc.microsoft.com', 'datatracker.ietf.org', 'www.rfc-editor.org', 'example.com', '*.example.com', 'example.org', 'example.net', 'localhost'];

/** Undo defanging. Returns { text, changes }. */
export function refang(s) {
  const out = String(s)
    .replace(/\b([hH])(?:xx|XX|xX|Xx|\[x\]|\[xx\]|\*\*|__)([pP])([sS]?)(?=[[({]?:)/g, (_, h, p, x) => h + (h === 'H' ? 'TT' : 'tt') + p + x)
    .replace(/\b([hH])(?:xx|XX|xX|Xx)([pP])([sS]?)\b/g, (_, h, p, x) => h + (h === 'H' ? 'TT' : 'tt') + p + x)
    .replace(/\b([fF])[xX]([pP])\b/g, (_, f, p) => f + (f === 'F' ? 'T' : 't') + p)
    .replace(/\[:\/\/\]|\[:\]\/\/|\(:\/\/\)|\(:\)\/\/|\{:\/\/\}|\[:\/\]\/|:\[\/\/\]/g, '://')
    .replace(/\[:\]|\(:\)/g, ':')
    .replace(/ ?[[({<] ?(?:\.|dot|DOT|Dot) ?[\])}>] ?/g, '.')
    .replace(/(?<=\w)\\\.(?=\w)/g, '.')
    .replace(/ ?[[({<] ?(?:@|at|AT|At) ?[\])}>] ?/g, '@')
    .replace(/\[\/\]/g, '/');
  return out;
}

const OCT = '(?:25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)';
export const RE = {
  url: /(?:https?|ftp|sftp|ftps|wss?):\/\/[^\s"'<>`)\]}|\\^]+/gi,
  email: /(?<![\w.+-])[a-z0-9._%+-]{1,64}@(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}\b/gi,
  ipv4: new RegExp(`(?<![\\w.])${OCT}(?:\\.${OCT}){3}(?![\\w]|\\.\\d)`, 'g'),
  ipv6: /(?<![\w:.])(?:[0-9a-f]{1,4}:){2,7}(?::?[0-9a-f]{1,4})(?![\w:])|(?<![\w:.])(?:[0-9a-f]{1,4}:){1,6}:(?:[0-9a-f]{1,4}(?::[0-9a-f]{1,4}){0,5})?(?![\w:])/gi,
  domain: /(?<![\w@.-])(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:xn--[a-z0-9-]{2,59}|[a-z]{2,24})(?![\w-]|\.[a-z0-9])/gi,
};
function trimUrl(u) {
  let s = u.replace(/[.,;:!?]+$/, '');
  while (s.endsWith(')') && (s.match(/\(/g) || []).length < (s.match(/\)/g) || []).length) s = s.slice(0, -1);
  return s.replace(/[.,;:!?*_]+$/, '');
}
export function isDomain(d, { fileNames = false } = {}) {
  const labels = d.toLowerCase().split('.'); const tld = labels[labels.length - 1];
  if (labels.length < 2 || /^\d+$/.test(tld)) return false;
  if (!tld.startsWith('xn--') && !TLDS.has(tld)) return false;
  if (!fileNames && FILE_EXT.has(tld)) return false;
  return true;
}
export function ipv4Public(ip) {
  const [a, b, c] = ip.split('.').map(Number);
  return !(a === 10 || a === 127 || a === 0 || a >= 224 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || (a === 169 && b === 254) || (a === 100 && b >= 64 && b <= 127) || (a === 192 && b === 0 && c === 2) || (a === 198 && b === 51 && c === 100) || (a === 203 && b === 0 && c === 113));
}
function ipv6Public(ip) { const s = ip.toLowerCase(); return !(s === '::1' || s === '::' || /^fe[89ab]|^f[cd]|^ff|^2001:0?db8:/.test(s)); }
const glob = (g) => new RegExp('^' + g.toLowerCase().replace(/[.+^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*') + '$');

/**
 * Find live (fanged) indicators in one line. Returns spans sorted by start.
 * @returns {{type:'url'|'email'|'ipv4'|'ipv6'|'domain', value:string, start:number, end:number, host?:string}[]}
 */
export function findLive(line, opts = {}) {
  const ignore = (opts.ignoreDomains || []).map(glob);
  const ignored = (h) => h && ignore.some((r) => r.test(h.toLowerCase()));
  const spans = [];
  const taken = (s, e) => spans.some((x) => s < x.end && e > x.start);
  for (const m of line.matchAll(RE.url)) {
    const v = trimUrl(m[0]); let host = '';
    try { host = new URL(v).hostname.replace(/^\[|\]$/g, ''); } catch { continue; }
    if (!host || ignored(host)) { spans.push({ type: 'skip', start: m.index, end: m.index + v.length }); continue; }
    if (/^[\d.]+$/.test(host) && !ipv4Public(host) && !opts.includePrivate) { spans.push({ type: 'skip', start: m.index, end: m.index + v.length }); continue; }
    spans.push({ type: 'url', value: v, host, start: m.index, end: m.index + v.length });
  }
  for (const m of line.matchAll(RE.email)) {
    if (taken(m.index, m.index + m[0].length)) continue;
    const host = m[0].split('@')[1];
    if (ignored(host) || !isDomain(host)) continue;
    spans.push({ type: 'email', value: m[0], host, start: m.index, end: m.index + m[0].length });
  }
  for (const m of line.matchAll(RE.ipv4)) {
    if (taken(m.index, m.index + m[0].length) || (!opts.includePrivate && !ipv4Public(m[0]))) continue;
    if (/\d\.$|\bv(?:ersion)?\s*$/i.test(line.slice(0, m.index))) continue; // "v1.2.3.4"
    spans.push({ type: 'ipv4', value: m[0], start: m.index, end: m.index + m[0].length });
  }
  for (const m of line.matchAll(RE.ipv6)) {
    const v = m[0];
    if (taken(m.index, m.index + v.length) || (v.match(/:/g) || []).length < 2 || /^\d{1,2}:\d{2}(:\d{2})?$/.test(v) || /^([0-9a-f]{2}:){5}[0-9a-f]{2}$/i.test(v)) continue;
    if (!opts.includePrivate && !ipv6Public(v)) continue;
    spans.push({ type: 'ipv6', value: v, start: m.index, end: m.index + v.length });
  }
  for (const m of line.matchAll(RE.domain)) {
    if (taken(m.index, m.index + m[0].length)) continue;
    if (!isDomain(m[0], { fileNames: opts.fileNameDomains }) || ignored(m[0])) continue;
    spans.push({ type: 'domain', value: m[0], host: m[0], start: m.index, end: m.index + m[0].length });
  }
  return spans.filter((s) => s.type !== 'skip').sort((a, b) => a.start - b.start);
}

const DOT = { brackets: '[.]', full: '[.]', dot: '[dot]', minimal: '[.]', paren: '(.)', colon: '[.]' };
function defangHost(h, style) {
  if (style === 'minimal') { const i = h.lastIndexOf('.'); return i === -1 ? h : `${h.slice(0, i)}[.]${h.slice(i + 1)}`; }
  return h.replace(/\./g, DOT[style]);
}
/** Defang a single indicator value. */
export function defangValue(v, type = 'auto', style = 'brackets') {
  if (!STYLES.includes(style)) throw new Error(`Unknown style "${style}" (have ${STYLES.join(', ')})`);
  if (type === 'auto') type = /^[a-z][a-z0-9+.-]*:\/\//i.test(v) ? 'url' : v.includes('@') ? 'email' : v.includes(':') ? 'ipv6' : 'domain';
  if (type === 'ipv6') return v.replace(/:/g, '[:]');
  if (type === 'email') { const [u, d] = v.split('@'); return `${u}[@]${defangHost(d, style)}`; }
  if (type !== 'url') return defangHost(v, style);
  const m = v.match(/^([a-z][a-z0-9+.-]*):\/\/([^/?#]*)(.*)$/is);
  if (!m) return defangHost(v, style);
  let [, scheme, auth, rest] = m;
  scheme = scheme.replace(/^http/i, (x) => (x === 'HTTP' ? 'HXXP' : 'hxxp')).replace(/^ftp/i, 'fxp');
  const at = auth.lastIndexOf('@'); const userinfo = at >= 0 ? auth.slice(0, at) + '[@]' : ''; const hostport = at >= 0 ? auth.slice(at + 1) : auth;
  const sep = style === 'full' ? '[://]' : style === 'colon' ? '[:]//' : '://';
  const path = style === 'full' ? rest.replace(/\./g, '[.]') : rest;
  const hp = hostport.startsWith('[') ? hostport.replace(/:/g, '[:]') : defangHost(hostport, style);
  return `${scheme}${sep}${userinfo}${hp}${path}`;
}

/** Refang a single defanged value (inverse of defangValue for every style). */
export function refangValue(v) { return refang(v); }

const CODE_RE = /(^|\n)[ \t]*(```|~~~)[^\n]*\n[\s\S]*?(?:\n[ \t]*\2[^\n]*(?=\n|$)|$)|`[^`\n]+`|<(pre|code|script|style)\b[^>]*>[\s\S]*?<\/\3\s*>|<!--[\s\S]*?-->/gi;
/**
 * Split text into segments, marking Markdown fenced blocks, inline code spans,
 * HTML <pre>/<code>/<script>/<style> elements and HTML comments as protected (code: true).
 * @param {string} text
 * @returns {{text: string, code: boolean}[]}
 */
export function splitCode(text) {
  const s = String(text); const out = []; let pos = 0;
  for (const m of s.matchAll(CODE_RE)) {
    const start = m.index + (m[1] ? m[1].length : 0);
    if (start > pos) out.push({ text: s.slice(pos, start), code: false });
    out.push({ text: s.slice(start, m.index + m[0].length), code: true });
    pos = m.index + m[0].length;
  }
  if (pos < s.length || !out.length) out.push({ text: s.slice(pos), code: false });
  return out;
}

/**
 * Defang every live indicator in text. Returns { text, changes }.
 * With opts.skipCode (Markdown/HTML-aware), code blocks, inline code and <pre>/<code> are left untouched.
 */
export function defangText(text, opts = {}) {
  if (opts.skipCode) {
    let changes = 0; const { skipCode, ...rest } = opts;
    const t = splitCode(text).map((seg) => { if (seg.code) return seg.text; const r = defangText(seg.text, rest); changes += r.changes; return r.text; }).join('');
    return { text: t, changes };
  }
  const style = opts.style || 'brackets'; let changes = 0;
  const lines = String(text).split('\n').map((line) => {
    const spans = findLive(line, opts);
    let out = ''; let pos = 0;
    for (const s of spans) { out += line.slice(pos, s.start) + defangValue(s.value, s.type === 'ipv4' ? 'domain' : s.type, style); pos = s.end; changes++; }
    return out + line.slice(pos);
  });
  return { text: lines.join('\n'), changes };
}
export function refangText(text, opts = {}) {
  const out = opts.skipCode ? splitCode(text).map((seg) => (seg.code ? seg.text : refang(seg.text))).join('') : refang(text); let changes = 0;
  const a = String(text).split('\n'); const b = out.split('\n');
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) changes++;
  return { text: out, changes };
}

const DEFANG_MARK = /hxxp|fxp|\[\.\]|\(\.\)|\{\.\}|\[dot\]|\[:\]|\[@\]|\[:\/\/\]/i;
const LINK = [/\[[^\]]*\]\(\s*<?((?:https?|ftp):\/\/[^)\s>]+)>?(?:\s+"[^"]*")?\s*\)/gi, /<((?:https?|ftp):\/\/[^>\s]+)>/gi, /\bhref\s*=\s*["']?((?:https?|ftp):\/\/[^"'\s>]+)/gi, /^\s*\[[^\]]+\]:\s*<?((?:https?|ftp):\/\/\S+?)>?(?:\s|$)/gim];

/**
 * Check text for live indicators. Returns raw findings (rule, line, message, value...).
 */
export function checkText(text, file, opts = {}) {
  const ignoreDomains = [...(opts.referenceDomains === false ? [] : REFERENCE_DOMAINS), ...(opts.ignoreDomains || [])];
  const o = { ...opts, ignoreDomains };
  const findings = [];
  const src = opts.skipCode ? splitCode(text).map((seg) => (seg.code ? seg.text.replace(/[^\r\n]/g, ' ') : seg.text)).join('') : String(text);
  src.split(/\r?\n/).forEach((line, i) => {
    const ln = i + 1;
    const linkHits = new Set();
    for (const re of LINK) for (const m of line.matchAll(re)) {
      const live = findLive(m[1], o).find((s) => s.type === 'url');
      if (!live) continue;
      linkHits.add(live.value);
      findings.push({ rule: 'live-link', file, line: ln, location: `${file}:${ln}`, value: live.value, message: `Clickable link to live URL ${defangValue(live.value, 'url')}`, fix: 'Remove the hyperlink and write the defanged URL as plain text (or in a code span).' });
    }
    for (const s of findLive(line, o)) {
      if (s.type === 'url' && linkHits.has(s.value)) continue;
      // indicator sits in a token that also carries defang markers -> partial
      const tokStart = line.lastIndexOf(' ', s.start) + 1; const tokEndRaw = line.indexOf(' ', s.end); const token = line.slice(tokStart, tokEndRaw === -1 ? undefined : tokEndRaw);
      const partial = DEFANG_MARK.test(token);
      const rule = partial ? 'partial-defang' : s.type === 'url' ? 'live-url' : s.type === 'email' ? 'live-email' : s.type === 'domain' ? 'live-domain' : 'live-ip';
      const fixed = defangValue(s.value, s.type === 'ipv4' ? 'domain' : s.type, opts.style || 'brackets');
      findings.push({ rule, file, line: ln, location: `${file}:${ln}`, value: s.value, message: partial ? `Partly defanged indicator "${token}" still contains live ${s.type} ${fixed}` : `Live ${s.type === 'ipv4' || s.type === 'ipv6' ? 'IP address' : s.type} ${fixed}`, fix: `Write it as ${fixed} (run: defang-sentinel defang --write ${file}).` });
    }
  });
  return findings;
}
