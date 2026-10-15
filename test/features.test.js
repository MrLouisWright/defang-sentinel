import { test } from 'node:test';
import assert from 'node:assert/strict';
import { writeFileSync, readFileSync, mkdtempSync, mkdirSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { refang, refangValue, defangValue, defangText, refangText, splitCode, fix, installHook, check, STYLES } from '../src/index.js';

const BIN = new URL('../bin/defang-sentinel.js', import.meta.url).pathname;
const run = (args, opts = {}) => spawnSync(process.execPath, [BIN, ...args], { encoding: 'utf8', ...opts });

test('vendor styles: paren and colon', () => {
  assert.equal(defangValue('https://evil.com/x', 'url', 'paren'), 'hxxps://evil(.)com/x');
  assert.equal(defangValue('https://evil.com/x', 'url', 'colon'), 'hxxps[:]//evil[.]com/x');
  assert.equal(refang('hxxps(:)//evil(.)com'), 'https://evil.com');
  assert.equal(refang('hxxp{://}evil[dot]com'), 'http://evil.com');
});

test('round-trip refang(defang(x)) === x for every style and type', () => {
  const vals = [['https://www.evil.com/a.php?q=1.2', 'url'], ['ftp://u@files.evil.co.uk:21/x', 'url'], ['HTTP://EVIL.COM/', 'url'], ['bad@phish.ru', 'email'], ['sub.evil.net', 'domain'], ['8.8.4.4', 'domain'], ['2001:4860::8888', 'ipv6'], ['http://[2001:db8::1]:8080/x', 'url']];
  for (const style of STYLES) for (const [v, t] of vals) assert.equal(refangValue(defangValue(v, t, style)), v, `${style} ${v}`);
});

test('splitCode marks Markdown and HTML code as protected', () => {
  const segs = splitCode('a `x` b\n```\nhttp://e.com\n```\n<code>c</code><pre>d</pre><!-- e -->');
  assert.deepEqual(segs.filter((s) => s.code).map((s) => s.text.trim()), ['`x`', '```\nhttp://e.com\n```', '<code>c</code>', '<pre>d</pre>', '<!-- e -->']);
  assert.equal(segs.map((s) => s.text).join(''), 'a `x` b\n```\nhttp://e.com\n```\n<code>c</code><pre>d</pre><!-- e -->');
});

test('defangText/refangText skipCode leave code untouched', () => {
  const md = 'C2 at https://evil.com\n\n```sh\ncurl https://evil.com\n```\nand `evil.org` <code>http://evil.net</code>\n';
  const r = defangText(md, { skipCode: true });
  assert.equal(r.changes, 1);
  assert.match(r.text, /C2 at hxxps:\/\/evil\[\.\]com/);
  assert.match(r.text, /curl https:\/\/evil\.com/);
  assert.match(r.text, /`evil\.org`/);
  assert.match(r.text, /<code>http:\/\/evil\.net<\/code>/);
  assert.equal(refangText('`hxxp://a[.]com` hxxp://b[.]com', { skipCode: true }).text, '`hxxp://a[.]com` http://b.com');
});

test('check skipCode ignores inline code and keeps line numbers', () => {
  const r = check([{ name: 'r.md', text: 'x `https://evil.com`\nlive https://evil.org\n' }], { skipCode: true });
  assert.deepEqual(r.findings.map((f) => f.line), [2]);
});

test('fix() rewrites files in place, code-aware for markdown; CLI --fix', () => {
  const d = mkdtempSync(join(tmpdir(), 'dfs-'));
  writeFileSync(join(d, 'r.md'), 'see https://evil.com and https://attack.mitre.org\n`https://evil.com`\n');
  writeFileSync(join(d, 'n.txt'), 'ip 8.8.8.8\n');
  const res = fix([d]);
  assert.equal(res.length, 2);
  assert.equal(readFileSync(join(d, 'r.md'), 'utf8'), 'see hxxps://evil[.]com and https://attack.mitre.org\n`https://evil.com`\n');
  assert.equal(readFileSync(join(d, 'n.txt'), 'utf8'), 'ip 8[.]8[.]8[.]8\n');
  assert.equal(fix([d]).length, 0);
  writeFileSync(join(d, 'n.txt'), 'evil.ru\n');
  const p = run(['check', '--fix', '--skip-code', d]);
  assert.equal(p.status, 0, p.stdout + p.stderr);
  assert.match(p.stderr, /fixed 1 indicator/);
  assert.equal(readFileSync(join(d, 'n.txt'), 'utf8'), 'evil[.]ru\n');
});

test('installHook and CLI hook install', () => {
  const d = mkdtempSync(join(tmpdir(), 'dfh-'));
  assert.throws(() => installHook(d), /No \.git/);
  mkdirSync(join(d, '.git'));
  const h = installHook(d);
  assert.match(readFileSync(h, 'utf8'), /defang-sentinel check/);
  assert.ok(statSync(h).mode & 0o100);
  writeFileSync(h, '#!/bin/sh\necho other\n');
  assert.throws(() => installHook(d), /already exists/);
  assert.ok(installHook(d, { force: true }));
  const p = run(['hook', 'install', '--force'], { cwd: d });
  assert.equal(p.status, 0, p.stderr);
  assert.equal(run(['hook', 'bogus'], { cwd: d }).status, 2);
});
