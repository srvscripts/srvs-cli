# Changelog

## v0.1.0

First public release.

- `srvs check`: DNS, HTTPS certificate, website headers, mail records and mail-server blacklists in one run.
- `srvs dns`, `srvs mail`, `srvs ssl` (with STARTTLS for SMTP, IMAP and POP3), `srvs http`, `srvs bl`.
- SPF lookup counting across includes and redirects (RFC 7208 limits), DMARC with organizational-domain fallback,
  DKIM key size, MTA-STS policy matched against the MX hosts.
- Blacklist results are only trusted when the list answers its own RFC 5782 test entry through your resolver.
- `--json` output and exit codes 0/1/2 for cron and monitoring.
