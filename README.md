# srvs: server, website, DNS and e-mail checks from the command line

[![ci](https://github.com/srvscripts/srvs-cli/actions/workflows/ci.yml/badge.svg)](https://github.com/srvscripts/srvs-cli/actions/workflows/ci.yml)

`srvs` is a single binary for Linux, macOS and Windows that runs the checks a server admin does by hand with `dig`,
`openssl s_client` and `curl`, and tells you what is wrong and how to fix it. It is the command-line companion of the
free tools on [srvscripts.com](https://srvscripts.com/tools/).

```text
$ srvs check example.com
check: example.com

  DNS
  ✓ Name servers        ns1.example.net, ns2.example.net
  ✓ Address             203.0.113.10 · IPv6 2001:db8::10
  ✓ DNSSEC              signed and validated

  HTTPS certificate
  ✓ Trusted             yes, chain is valid
  ! Expires             2026-10-20 08:00 UTC (9 days left)
                        → Renew soon; check that automatic renewal (AutoSSL, certbot, acme.sh) is working.

  E-mail
  ✓ SPF                 v=spf1 include:_spf.google.com ~all
                        3 of 10 DNS lookups
  ! DMARC               v=DMARC1; p=none; rua=mailto:dmarc@example.com
                        p=none only monitors: spoofed mail using this domain is still delivered.
  ...
  21 passed · 2 warning(s) · 0 failed · 0 not checked
```

Every check runs **from your own machine**. Nothing is sent to srvscripts.com, and there is no telemetry.

## Install

**Linux and macOS:**

```sh
curl -fsSL https://raw.githubusercontent.com/srvscripts/srvs-cli/main/scripts/install.sh | sh
```

The script downloads the release for your system, checks its SHA-256 checksum and installs `srvs` to `/usr/local/bin`
(or `~/.local/bin` without root). Pin a version with `SRVS_VERSION=v0.1.0`.

**Windows (PowerShell):**

```powershell
irm https://raw.githubusercontent.com/srvscripts/srvs-cli/main/scripts/install.ps1 | iex
```

**By hand:** download the archive for your system from [Releases](https://github.com/srvscripts/srvs-cli/releases),
check it against `SHA256SUMS`, and put `srvs` (or `srvs.exe`) in your PATH.

**With Go 1.22 or later:** `go install github.com/srvscripts/srvs-cli/cmd/srvs@latest`

## Commands

| Command | What it checks |
|---|---|
| `srvs check <domain>` | Everything at once: name servers, addresses, DNSSEC, CAA, HTTPS certificate, HTTP to HTTPS redirect, security headers, MX, SPF, DMARC, DKIM, MTA-STS, TLS-RPT, BIMI and blacklists for the mail server IPs |
| `srvs dns <name> [TYPE...]` | DNS records (default A, AAAA, CNAME, MX, NS, TXT, CAA, SOA); an IP gives its PTR |
| `srvs mail <domain>` | MX and forward-confirmed reverse DNS, SPF with the 10-lookup count across includes, DMARC, DKIM (common selectors or `--selector`), MTA-STS policy against your MX hosts, TLS-RPT, BIMI |
| `srvs ssl <host[:port]>` | Chain of trust, name match, expiry, key, protocol and cipher; STARTTLS on ports 25, 587, 143 and 110; `--legacy` tests TLS 1.0/1.1 |
| `srvs http <url\|host>` | HTTP to HTTPS redirect, redirect chain, status, response time and six security headers |
| `srvs bl <ip\|domain>` | 29 IP blacklists; for a domain, the IPs of its mail servers plus Spamhaus DBL, SURBL and URIBL |

Every command accepts several targets: `srvs ssl mail.example.com:993 mail.example.com:587 example.com`.

## Options

| Option | Meaning |
|---|---|
| `--json` | Machine-readable output |
| `-q`, `--quiet` | Only show warnings, failures and checks that could not run |
| `--resolver IP` | DNS server to use (default: your system resolver, see below) |
| `--timeout 8s` | Time limit per network step |
| `--warn-days 14` | `ssl`: warn when the certificate expires within N days |
| `--starttls auto` | `ssl`: `auto`, `smtp`, `imap`, `pop3` or `none` |
| `--selector NAME` | `mail`: DKIM selector to check (repeatable) |
| `--spamhaus-key KEY` | `bl`: free [Spamhaus DQS](https://www.spamhaus.com/free-trial/free-data-query-service/) key (or `SRVS_SPAMHAUS_KEY`) |
| `-v`, `--verbose` | `bl`: list every clean blacklist; `mail`: show the SPF include tree |
| `--ignore-warnings` | Warnings do not count: exit 1 on a failure, 2 if something could not be checked, otherwise 0 |
| `--no-color` | Plain output (also `NO_COLOR=1`) |

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Every check that ran passed |
| 1 | At least one warning or failure |
| 2 | Something could not be checked, and nothing failed (timeout, blocked port, refused query, bad arguments) |

A failure always wins over "could not check", so a monitor never misses a real problem.

With `--ignore-warnings`, warnings are left out of the exit code but nothing else is: a failure is still 1 and a check
that could not run is still 2, even when warnings are also present. With `--json`, the `exit` field is always the same
number as the process exit status.

## Use it in cron or monitoring

```sh
# Mail me when a certificate is within 21 days of expiry, or when the mail setup breaks.
15 6 * * * srvs ssl example.com mail.example.com:587 --warn-days 21 -q --no-color || mail -s "srvs: TLS" you@example.com
30 6 * * * srvs mail example.com -q --no-color --ignore-warnings || mail -s "srvs: mail records" you@example.com
```

With `--json` the output is one document with `exit`, and per target a list of checks with `section`, `name`,
`status` (`ok`, `info`, `warn`, `fail`, `unknown`), `value`, `detail` and `fix`.

## Good to know

- **Which DNS server is used.** By default `srvs` asks the resolver your system uses: the `nameserver` lines of
  `/etc/resolv.conf` on Linux and macOS, and the DNS servers of the active network adapters on Windows (the ones
  `ipconfig /all` shows). Only if none is found does it fall back to 1.1.1.1 and 8.8.8.8, and the output then says so
  next to "Resolver:". Use `--resolver` to pick one yourself, for example an internal server for split DNS.

- **Blacklists and public resolvers.** Spamhaus and URIBL refuse queries that arrive through public resolvers such as
  1.1.1.1 or 8.8.8.8. Some resolvers even answer "not listed" for every address. `srvs` checks each list's own test entry
  (RFC 5782) and reports a list as *not checked* instead of *clean* when the test entry does not come back. Use your
  own resolver (`--resolver`) or a free Spamhaus DQS key.
- **Port 25.** Many home and cloud networks block outgoing port 25. `srvs ssl mail.example.com:25` then reports
  *not checked*; run it from a server, or check 587 or 465.
- **DKIM.** A DKIM key can only be found with its selector. `srvs` tries the common selectors; find yours in the
  `DKIM-Signature: ... s=` header of a sent message and pass `--selector`.

## Build from source

```sh
git clone https://github.com/srvscripts/srvs-cli && cd srvs-cli
go test ./... && go build -o srvs ./cmd/srvs
```

## Licence

MIT. See [LICENSE](LICENSE). Found a bug or a wrong result? [Open an issue](https://github.com/srvscripts/srvs-cli/issues).
Security problems: see [SECURITY.md](SECURITY.md).
