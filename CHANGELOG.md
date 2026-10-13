# Changelog

## 1.0.0 (2026-10-14)

First release, by Louis Wright.

- `defang` with four styles (brackets, full, dot, minimal) for URLs, domains, IPv4/IPv6 and emails; idempotent; `--write` for in-place edits.
- `refang` for all common defang notations.
- `check` for live URLs, domains, IPs and emails, clickable Markdown/HTML links and half-defanged indicators, with a reference-site allowlist, custom ignore domains, code-fence skipping and directory walking.
- Allowlist with expiry, per-rule severity, text/JSON/SARIF/Markdown output, `--fail-on` and exit codes 0/1/2; composite GitHub Action.
