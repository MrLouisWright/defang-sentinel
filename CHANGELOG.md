# Changelog

## 1.0.0 (2026-10-15)

- **More vendor styles:** `paren` (`evil(.)com`) and `colon` (`hxxps[:]//`); refang also understands `(:)//`, `{://}`, `:[//]` and preserves case (`HXXP` → `HTTP`). `refangValue` round-trips every style for URLs, domains, IPs and emails (tested).
- **Markdown/HTML-aware rewriting:** `--skip-code` / `{ skipCode: true }` leaves fenced blocks, inline code, `<pre>`, `<code>`, `<script>`, `<style>` and comments untouched for defang, refang and check. New `splitCode()` helper.
- **`check --fix`** and `fix()` API defang findings in place (code-aware for Markdown/HTML).
- **Pre-commit hook:** `defang-sentinel hook install`, `installHook()`, and a `.pre-commit-hooks.yaml` for the pre-commit framework.
- Dual ESM + CJS build, generated `.d.ts`, require/import CI checks. defang-sentinel is the single home of defang/refang for the Louis Wright toolset (ioc-sentinel imports it).

First release, by Louis Wright.

- `defang` with four styles (brackets, full, dot, minimal) for URLs, domains, IPv4/IPv6 and emails; idempotent; `--write` for in-place edits.
- `refang` for all common defang notations.
- `check` for live URLs, domains, IPs and emails, clickable Markdown/HTML links and half-defanged indicators, with a reference-site allowlist, custom ignore domains, code-fence skipping and directory walking.
- Allowlist with expiry, per-rule severity, text/JSON/SARIF/Markdown output, `--fail-on` and exit codes 0/1/2; composite GitHub Action.
