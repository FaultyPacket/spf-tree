# Changelog

## 1.0.0 – 2026-10-29

First public release.

- Recursive SPF expansion with lookup counting per RFC 7208 §4.6.4 (10-term and 2-void limits, >10 MX records)
- permerror checks: multiple records, missing include/redirect target, syntax, invalid IP/CIDR, duplicate modifiers, loops
- `redirect` ignored when `all` is present; macros and `ptr` flagged and counted, never expanded
- Port-53 (dnspython) and DNS-over-HTTPS JSON transports
- Batch mode: arguments, `--file`, stdin; URLs and emails accepted; IDNA; dedupe; `--concurrency`; per-domain error isolation
- JSON (one object per domain), summary CSV, per-lookup CSV; UTC timestamps and resolver recorded
- `--version`; exit codes 0/1/2
