import { test } from 'node:test';
import assert from 'node:assert/strict';
import { writeFileSync, readFileSync, mkdtempSync, mkdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { refang, defangValue, defangText, refangText, findLive, check, exitCode } from '../src/index.js';

const BIN = new URL('../bin/defang-sentinel.js', import.meta.url).pathname;
const run = (args, input) => spawnSync(process.execPath, [BIN, ...args], { input, encoding: 'utf8' });
const rules = (r) => r.findings.map((f) => f.rule).sort();

test('defangValue styles', () => {
  assert.equal(defangValue('https://www.evil.com/a.php?x=1'), 'hxxps://www[.]evil[.]com/a.php?x=1');
  assert.equal(defangValue('https://www.evil.com/a.php', 'url', 'full'), 'hxxps[://]www[.]evil[.]com/a[.]php');
  assert.equal(defangValue('http://evil.com', 'url', 'dot'), 'hxxp://evil[dot]com');
  assert.equal(defangValue('http://a.b.evil.com', 'url', 'minimal'), 'hxxp://a.b.evil[.]com');
  assert.equal(defangValue('ftp://user@files.evil.com:21/x'), 'fxp://user[@]files[.]evil[.]com:21/x');
  assert.equal(defangValue('bad@phish.ru'), 'bad[@]phish[.]ru');
  assert.equal(defangValue('1.2.3.4', 'domain'), '1[.]2[.]3[.]4');
  assert.equal(defangValue('2001:4860::8888', 'ipv6'), '2001[:]4860[:][:]8888');
  assert.throws(() => defangValue('x.com', 'auto', 'weird'), /Unknown style/);
});

test('refang reverses all styles', () => {
  for (const s of ['brackets', 'full', 'dot', 'minimal']) assert.equal(refang(defangValue('https://www.evil.com/a.php', 'url', s)), 'https://www.evil.com/a.php');
  assert.equal(refang('hXXps[:]//x(.)y{.}z [at] q (dot) r'), 'https://x.y.z@q.r');
  assert.equal(refang('evil\\.com'), 'evil.com');
  assert.equal(refangText('a\nhxxp://x[.]com\nb').changes, 1);
});

test('findLive: URLs, emails, IPs, domains; ignores noise', () => {
  const s = findLive('see https://evil.com/x), mail a@b-c.ru, 8.8.8.8, 10.0.0.1, v1.2.3.4, evil.net, setup.py, 2606:4700::1111 at 12:30:45');
  assert.deepEqual(s.map((x) => `${x.type}:${x.value}`), ['url:https://evil.com/x', 'email:a@b-c.ru', 'ipv4:8.8.8.8', 'domain:evil.net', 'ipv6:2606:4700::1111']);
  assert.equal(findLive('http://10.0.0.1/admin').length, 0);
  assert.equal(findLive('http://10.0.0.1/admin', { includePrivate: true }).length, 1);
  assert.equal(findLive('https://github.com/x', { ignoreDomains: ['github.com'] }).length, 0);
  assert.equal(findLive('ok.evil.com', { ignoreDomains: ['*.evil.com'] }).length, 0);
});

test('defangText round trip and idempotence', () => {
  const src = 'Go http://a.evil.com/p and mail x@y.org, ip 45.9.148.3\n[l](https://b.evil.com)';
  const d = defangText(src);
  assert.equal(d.changes, 4);
  assert.equal(findLive(d.text.split('\n')[0]).length, 0);
  assert.equal(defangText(d.text).changes, 0);
  assert.equal(refang(d.text), src);
});

test('check: rule classification', () => {
  const text = 'live http://a.evil.com/x\n[t](https://b.evil.com/y)\n<https://c.evil.com>\n<a href="http://d.evil.com/">x</a>\nhalf hxxp://e.evil.com/z\nip 45.9.148.3 mail m@evil.org dom evil.io\nref https://attack.mitre.org/x ok hxxp://f[.]evil[.]com';
  const r = check([{ name: 'r.md', text }], { now: '2026-10-14' });
  assert.deepEqual(rules(r), ['live-domain', 'live-email', 'live-ip', 'live-link', 'live-link', 'live-link', 'live-url', 'partial-defang']);
  assert.equal(r.findings.find((f) => f.rule === 'live-url').line, 1);
  assert.equal(exitCode(r, 'medium'), 1);
  const noRef = check([{ name: 'r.md', text: 'https://attack.mitre.org/x' }], { referenceDomains: false });
  assert.deepEqual(rules(noRef), ['live-url']);
});

test('check: skip code fences, allowlist, severity', () => {
  const text = '```\ncurl http://a.evil.com\n```\nhttp://b.evil.com';
  assert.equal(check([{ name: 'r.md', text }], { skipCode: true }).findings.length, 1);
  const r = check([{ name: 'r.md', text: 'http://b.evil.com' }], { allow: [{ rule: 'live-url', match: '*b.evil.com*', reason: 'demo', expires: '2099-01-01' }], now: '2026-10-14' });
  assert.equal(r.findings.length, 0); assert.equal(r.suppressed.length, 1);
  const s = check([{ name: 'r.md', text: 'x@evil.org' }], { severity: { 'live-email': 'critical' } });
  assert.equal(s.findings[0].severity, 'critical');
});

test('check: directories respect extensions and skip binaries', () => {
  const d = mkdtempSync(join(tmpdir(), 'df-')); mkdirSync(join(d, 'node_modules'));
  writeFileSync(join(d, 'a.md'), 'http://a.evil.com');
  writeFileSync(join(d, 'b.js'), 'http://b.evil.com');
  writeFileSync(join(d, 'c.txt'), Buffer.from([0, 1, 2, 0x68, 0x74]));
  writeFileSync(join(d, 'node_modules', 'x.md'), 'http://c.evil.com');
  const r = check([d]);
  assert.deepEqual(r.findings.map((f) => f.value), ['http://a.evil.com']);
  assert.equal(check([join(d, 'b.js')]).findings.length, 1);
  assert.equal(exitCode(check([join(d, 'nope')]), 'none'), 2);
});

test('CLI', () => {
  assert.equal(run(['defang', '-'], 'http://evil.com/a\n').stdout, 'hxxp://evil[.]com/a\n');
  assert.equal(run(['defang', '-', '--style', 'full'], 'http://evil.com/a.b\n').stdout, 'hxxp[://]evil[.]com/a[.]b\n');
  assert.equal(run(['refang', '-'], 'hxxp://evil[.]com/a\n').stdout, 'http://evil.com/a\n');
  const d = mkdtempSync(join(tmpdir(), 'dfc-')); const f = join(d, 'r.md');
  writeFileSync(f, 'C2 http://evil.com/x\n');
  let r = run([f, '--no-color']); assert.equal(r.status, 1); assert.match(r.stdout, /live-url/);
  r = run(['defang', f, '--write']); assert.equal(r.status, 0); assert.equal(readFileSync(f, 'utf8'), 'C2 hxxp://evil[.]com/x\n');
  assert.equal(run(['check', f]).status, 0);
  r = run(['check', '-', '-f', 'sarif'], 'x@evil.org'); assert.equal(r.status, 0); assert.equal(JSON.parse(r.stdout).runs[0].results[0].ruleId, 'live-email');
  assert.equal(run(['check', '-', '--fail-on', 'low'], 'x@evil.org').status, 1);
  assert.equal(run(['check', '-', '--ignore-domain', 'evil.org', '--fail-on', 'low'], 'x@evil.org').status, 0);
  assert.equal(run(['defang', '-', '--style', 'x'], 'a').status, 2);
  assert.equal(run(['check']).status, 2);
  assert.match(run(['--help']).stdout, /defang-sentinel defang/);
  assert.match(run(['check', '-', '-f', 'markdown'], 'http://evil.com').stdout, /\| high \|/);
});
