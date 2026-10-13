# Changelog

## v0.1.1

Fixes from an independent review (13 Oct 2026).

- The `exit` field in `--json` output now always equals the process exit status (it ignored `--ignore-warnings`).
- `--ignore-warnings` no longer hides a check that could not run: warnings plus an unknown result now exit 2, not 0.
  A failure is 1, an unknown result 2, otherwise 0. Without the flag nothing changes.
- Windows: the default resolver is now the DNS servers of the active network adapters, as the help always said,
  instead of 1.1.1.1 and 8.8.8.8. The public fallback is only used when no system resolver is found, and is labelled.
- Dependencies updated (golang.org/x/net 0.61.0, golang.org/x/sys 0.49.0, miekg/dns 1.1.73; Go 1.26 or newer to
  build). CI and the release workflow now run `govulncheck` and stop on a reachable vulnerability.

## v0.1.0

First public release.

- `srvs check`: DNS, HTTPS certificate, website headers, mail records and mail-server blacklists in one run.
- `srvs dns`, `srvs mail`, `srvs ssl` (with STARTTLS for SMTP, IMAP and POP3), `srvs http`, `srvs bl`.
- SPF lookup counting across includes and redirects (RFC 7208 limits), DMARC with organizational-domain fallback,
  DKIM key size, MTA-STS policy matched against the MX hosts.
- Blacklist results are only trusted when the list answers its own RFC 5782 test entry through your resolver.
- `--json` output and exit codes 0/1/2 for cron and monitoring.
