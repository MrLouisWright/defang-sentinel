# defang-sentinel

[![npm version](https://img.shields.io/npm/v/defang-sentinel.svg)](https://www.npmjs.com/package/defang-sentinel) [![CI](https://github.com/MrLouisWright/defang-sentinel/actions/workflows/ci.yml/badge.svg)](https://github.com/MrLouisWright/defang-sentinel/actions/workflows/ci.yml) [![Node](https://img.shields.io/node/v/defang-sentinel.svg)](https://nodejs.org) [![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

> Defang and refang indicators of compromise, and stop live malicious links from getting into threat reports, tickets and docs.

Threat-intel write-ups, incident tickets and detection repos are full of malicious URLs, domains and IPs. A single clickable `https://` link to a C2 server in a Markdown report is an accident waiting to happen. `defang-sentinel` does three jobs:

1. **`defang`**: rewrite live indicators as safe text (`https://evil.com` → `hxxps://evil[.]com`) in four styles.
2. **`refang`**: turn defanged indicators back into usable ones for tooling (`hxxps[://]evil[.]com` → `https://evil.com`).
3. **`check`** (default): scan files or directories and **fail CI** when a report contains live, clickable or half-defanged indicators.

CLI, library and GitHub Action. Node.js 18+, **zero runtime dependencies**.

## Features

- **Detects** URLs (http/https/ftp/sftp/ws), domains (validated against gTLD/ccTLD lists, with file names such as `setup.py` ignored), public IPv4/IPv6 addresses (private, loopback and documentation ranges ignored unless `--include-private`; version strings like `v1.2.3.4` skipped) and email addresses.
- **Clickable link detection** (`live-link`, high): Markdown links `[text](https://…)`, reference links, autolinks `<https://…>` and HTML `href` attributes. Defanged link text doesn't help if the href is still live.
- **Half-defanged detection** (`partial-defang`): `hxxp://evil.com` or `evil[.]com.badhost.ru` look safe at a glance but still contain a live host.
- **Reference allowlist**: links to MITRE ATT&CK, NVD, CVE.org, CISA, NCSC, VirusTotal, abuse.ch, urlscan, GitHub and others are expected in reports and allowed by default (`--no-reference-domains` turns this off). Add your own with `--ignore-domain` or `ignoreDomains` in the config.
- **Defang styles** (`--style`): `brackets` (default) `hxxps://www[.]evil[.]com/a.php`, `full` `hxxps[://]www[.]evil[.]com/a[.]php`, `dot` `hxxps://www[dot]evil[dot]com`, `minimal` `hxxps://www.evil[.]com`. Emails become `user[@]domain[.]com`; IPv6 colons become `[:]`.
- **Refang** understands `hxxp`, `hXXps`, `h[xx]p`, `fxp`, `[.]`, `(.)`, `{.}`, `[dot]`, `(dot)`, `\.`, `[:]`, `[://]`, `[@]`, `(at)`, `[at]`.
- `defang`/`refang` can rewrite files in place (`--write`) and are idempotent. Defanging already-defanged text changes nothing.
- `check` walks directories for text formats (`.md`, `.txt`, `.html`, `.csv`, `.json`, `.yml`, `.eml`, `.log`, `.yar`…; change with `--ext`), skips binaries and `node_modules`, and can ignore fenced code blocks (`--skip-code`).

## Rules

| Rule | Default | Meaning |
|---|---|---|
| `live-link` | high | Clickable Markdown/HTML link or autolink to a live URL |
| `live-url` | high | URL not defanged |
| `partial-defang` | medium | Token carries defang markers but still has a live host |
| `live-domain` | medium | Domain not defanged |
| `live-ip` | medium | Public IPv4/IPv6 not defanged |
| `live-email` | low | Email address not defanged |

## Install and run

```bash
echo 'C2: https://evil.com/gate.php 45.9.148.3' | npx defang-sentinel defang -
# C2: hxxps://evil[.]com/gate.php 45[.]9[.]148[.]3

npx defang-sentinel refang iocs.txt > iocs-live.txt
npx defang-sentinel defang --write reports/2026-10-apt.md

npx defang-sentinel reports/ --skip-code --ignore-domain 'mycompany.com,*.mycompany.com'
```

## Library

```js
import { defangText, refang, defangValue, check } from 'defang-sentinel';

defangText('see https://evil.com', { style: 'brackets' }).text; // 'see hxxps://evil[.]com'
refang('hxxps[://]evil[.]com');                                  // 'https://evil.com'
defangValue('bad@phish.ru');                                     // 'bad[@]phish[.]ru'
const report = check(['reports/'], { skipCode: true });
```

## Configuration

Put a `.defang-sentinel.json` in the working directory (or pass `--config <file>`). Every key is optional; CLI flags override the file.

```json
{
  "failOn": "medium",
  "severity": { "live-url": "high" },
  "allow": [
    { "rule": "live-url", "match": "*cdn.example.net*", "reason": "Accepted risk, ticket SEC-123", "expires": "2027-03-31" }
  ]
}
```

- **`severity`** changes the severity of any rule, or turns it `off`.
- **`allow`** suppresses findings. Each entry needs a `rule` (globs such as `live-*` work) and a `reason`, and can be narrowed with `target` and `match` (a glob tested against the target, location and value). Suppressed findings are listed in the JSON report. When `expires` (YYYY-MM-DD) has passed, the finding comes back together with an `allow-expired` finding, so exceptions can't be forgotten. Entries that match nothing are reported as `allow-unused` (info).

## Output and exit codes

- `--format text|json|sarif|markdown` for stdout, plus `--json`, `--sarif` and `--markdown <file>` to write extra copies in one run. SARIF 2.1.0 works with GitHub code scanning.
- `--fail-on critical|high|medium|low|info|none` (default `medium`).
- Exit code **0**: passed. **1**: at least one finding at or above `--fail-on`. **2**: usage or config error, or a target could not be checked.
- `--list-rules` prints every rule with its default severity.

## GitHub Action

```yaml
permissions:
  contents: read
  security-events: write   # only for the SARIF upload
steps:
  - uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262 # v4
    with: { persist-credentials: false }
  - uses: MrLouisWright/defang-sentinel@v1
    with:
      targets: 'reports/'
      fail-on: medium
      sarif: defang-sentinel.sarif
  - uses: github/codeql-action/upload-sarif@v3
    if: always()
    with: { sarif_file: defang-sentinel.sarif }
```

Inputs: `targets`, `fail-on`, `config`, `sarif`, `json`, `job-summary` (Markdown report in the job summary, default `true`), `args` (extra CLI flags), `ignore-domains`. Outputs: `markdown-file`, `exit-code`.

## Requirements

Node.js 18 or newer. No runtime dependencies.

## Support

If this project is useful to you, you can support its development with a donation: [Buy me a coffee](https://donate.stripe.com/aFa00lek3cvX4Ds2Fk9EI0b). It helps keep these tools maintained, documented and free for everyone.

## Credit (optional)

Free to use under MIT, no attribution required. If defang-sentinel helps you, a link back is appreciated:

```html
<a href="https://louiswright.co.uk">Built with defang-sentinel by Louis Wright</a>
```

```markdown
[![Built with defang-sentinel by Louis Wright](https://img.shields.io/badge/built%20with-defang--sentinel-blue)](https://louiswright.co.uk)
```

## License

MIT © Louis Wright ([Louis Wright](https://github.com/MrLouisWright))
