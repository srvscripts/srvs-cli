// Command srvs runs server, website, DNS and e-mail checks from the command line.
// It is the command-line companion of the free tools on https://srvscripts.com/tools/.
package main

import (
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/srvscripts/srvs-cli/internal/dnsbl"
	"github.com/srvscripts/srvs-cli/internal/mail"
	"github.com/srvscripts/srvs-cli/internal/report"
	"github.com/srvscripts/srvs-cli/internal/resolver"
	"github.com/srvscripts/srvs-cli/internal/tlscheck"
	"github.com/srvscripts/srvs-cli/internal/web"
)

const usage = `srvs: server, website, DNS and e-mail checks from the command line
https://srvscripts.com/cli/

Usage:
  srvs check <domain>...        everything at once: DNS, website, SSL, mail records, blacklists
  srvs dns   <name> [TYPE...]   DNS records (default: A AAAA CNAME MX NS TXT CAA SOA)
  srvs mail  <domain>...        MX, reverse DNS, SPF (with lookup count), DMARC, DKIM, MTA-STS, TLS-RPT, BIMI
  srvs ssl   <host[:port]>...   certificate trust, name, expiry, protocol; STARTTLS on 25, 587, 143 and 110
  srvs http  <url|host>...      HTTP to HTTPS redirect, redirect chain, status, security headers
  srvs bl    <ip|domain>...     29 IP blacklists; for a domain, its mail server IPs and 3 domain lists
  srvs version

Options (before or after the target):
  --json               machine-readable output
  -q, --quiet          only show warnings, failures and checks that could not run
  --resolver IP        DNS server to use (default: the system resolver: /etc/resolv.conf on Linux and macOS,
                       the network adapters' DNS servers on Windows; 1.1.1.1 and 8.8.8.8 only if none is found)
  --timeout 8s         time limit per network step
  --warn-days 14       ssl: warn when the certificate expires within N days
  --starttls auto      ssl: auto, smtp, imap, pop3 or none
  --legacy             ssl: also test whether TLS 1.0/1.1 are accepted
  --selector NAME      mail: DKIM selector to check (repeatable; default: common selectors)
  --spamhaus-key KEY   bl: Spamhaus Data Query Service key (or env SRVS_SPAMHAUS_KEY)
  -v, --verbose        bl: list every clean blacklist; mail: show the SPF include tree
  --ignore-warnings    warnings do not count: exit 1 on a failure, 2 if something could not be checked, else 0
  --no-color           plain output (also NO_COLOR=1)

Exit codes: 0 all checks passed · 1 a warning or failure · 2 something could not be checked (and nothing failed)
`

type opts struct {
	json, quiet, verbose, legacy, noColor, ignoreWarn bool
	resolverAddr, starttls, spamhausKey               string
	timeout                                           time.Duration
	warnDays                                          int
	selectors                                         multi
}

type multi []string

func (m *multi) String() string     { return strings.Join(*m, ",") }
func (m *multi) Set(v string) error { *m = append(*m, strings.Split(v, ",")...); return nil }

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stdout, usage)
		return 0
	}
	cmd := args[0]
	switch cmd {
	case "-h", "--help", "help":
		fmt.Fprint(stdout, usage)
		return 0
	case "version", "--version", "-V":
		fmt.Fprintf(stdout, "srvs %s (%s/%s)\n", report.Version, runtime.GOOS, runtime.GOARCH)
		return 0
	}
	var o opts
	fs := flag.NewFlagSet("srvs "+cmd, flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() { fmt.Fprint(stderr, usage) }
	fs.BoolVar(&o.json, "json", false, "")
	fs.BoolVar(&o.quiet, "quiet", false, "")
	fs.BoolVar(&o.quiet, "q", false, "")
	fs.BoolVar(&o.verbose, "verbose", false, "")
	fs.BoolVar(&o.verbose, "v", false, "")
	fs.BoolVar(&o.legacy, "legacy", false, "")
	fs.BoolVar(&o.noColor, "no-color", false, "")
	fs.BoolVar(&o.ignoreWarn, "ignore-warnings", false, "")
	fs.StringVar(&o.resolverAddr, "resolver", "", "")
	fs.StringVar(&o.starttls, "starttls", "auto", "")
	fs.StringVar(&o.spamhausKey, "spamhaus-key", os.Getenv("SRVS_SPAMHAUS_KEY"), "")
	fs.DurationVar(&o.timeout, "timeout", 8*time.Second, "")
	fs.IntVar(&o.warnDays, "warn-days", 14, "")
	fs.Var(&o.selectors, "selector", "")

	// Allow options anywhere: parse, take the first positional argument, continue with the rest.
	var targets []string
	rest := args[1:]
	for {
		if err := fs.Parse(rest); err != nil {
			return 2
		}
		if fs.NArg() == 0 {
			break
		}
		targets = append(targets, fs.Arg(0))
		rest = fs.Args()[1:]
	}
	if len(targets) == 0 {
		fmt.Fprintf(stderr, "srvs %s: missing target\n\n%s", cmd, usage)
		return 2
	}
	if o.timeout <= 0 {
		o.timeout = 8 * time.Second
	}

	r := resolver.New(o.resolverAddr, o.timeout)
	ua := "srvs-cli/" + report.Version + " (+https://srvscripts.com/cli/)"
	var reports []*report.Report

	switch cmd {
	case "dns":
		reports = append(reports, cmdDNS(r, targets[0], targets[1:]))
	case "mail":
		for _, t := range targets {
			d := cleanDomain(t)
			rep := report.New("mail", d)
			mail.Check(r, rep, "", d, mail.Options{Selectors: o.selectors, Timeout: o.timeout, UserAgent: ua})
			if o.verbose {
				if spf, err := mail.EvaluateSPF(txtLookup{r}, d); err == nil && len(spf.Tree) > 0 {
					rep.Note("SPF include tree:\n" + strings.Join(spf.Tree, "\n"))
				}
			}
			reports = append(reports, rep)
		}
	case "ssl", "tls":
		for _, t := range targets {
			host, port, err := tlscheck.ParseTarget(t)
			rep := report.New("ssl", t)
			if err != nil {
				rep.Add("", "Target", report.Unknown, err.Error())
			} else {
				tlscheck.Check(rep, "", tlscheck.Options{Host: host, Port: port, StartTLS: o.starttls, WarnDays: o.warnDays, Timeout: o.timeout, Legacy: o.legacy})
			}
			reports = append(reports, rep)
		}
	case "http", "web":
		for _, t := range targets {
			rep := report.New("http", t)
			web.Check(rep, "", t, web.Options{Timeout: o.timeout, UserAgent: ua})
			reports = append(reports, rep)
		}
	case "bl", "blacklist":
		for _, t := range targets {
			reports = append(reports, cmdBL(r, t, o))
		}
	case "check":
		for _, t := range targets {
			reports = append(reports, cmdCheck(r, cleanDomain(t), o, ua))
		}
	default:
		fmt.Fprintf(stderr, "srvs: unknown command %q\n\n%s", cmd, usage)
		return 2
	}

	for _, rep := range reports {
		if needsResolverNote(rep) && r.UsesPublicResolver() {
			rep.Note("Some blacklists (Spamhaus, URIBL) refuse queries from public resolvers like " + r.Describe() + ". Use your own resolver (--resolver) or a free Spamhaus DQS key (--spamhaus-key).")
		}
	}
	code := report.Exit(o.ignoreWarn, reports...)
	if o.json {
		if err := report.JSON(stdout, code, reports); err != nil {
			fmt.Fprintln(stderr, err)
			return 2
		}
		return code
	}
	st := style(o)
	for i, rep := range reports {
		if i > 0 {
			fmt.Fprintln(stdout)
		}
		rep.Text(stdout, st)
	}
	return code
}

type txtLookup struct{ r *resolver.Resolver }

func (t txtLookup) TXT(name string) ([]string, error) {
	v, _, err := t.r.TXT(name)
	return v, err
}

func needsResolverNote(rep *report.Report) bool {
	for _, c := range rep.Checks {
		if c.Status == report.Unknown && strings.Contains(c.Detail, "refused") {
			return true
		}
	}
	return false
}

func style(o opts) report.Style {
	tty := false
	if fi, err := os.Stdout.Stat(); err == nil && fi.Mode()&os.ModeCharDevice != 0 {
		tty = true
	}
	modernWin := runtime.GOOS != "windows" || os.Getenv("WT_SESSION") != "" || os.Getenv("TERM_PROGRAM") != ""
	color := tty && !o.noColor && os.Getenv("NO_COLOR") == "" && modernWin && os.Getenv("TERM") != "dumb"
	return report.Style{Color: color, Unicode: tty && modernWin, Quiet: o.quiet}
}

// cleanDomain accepts "Example.com", "https://example.com/path" or "user@example.com".
func cleanDomain(s string) string {
	s = strings.TrimSpace(strings.ToLower(s))
	s = strings.TrimPrefix(strings.TrimPrefix(s, "https://"), "http://")
	if i := strings.LastIndex(s, "@"); i >= 0 {
		s = s[i+1:]
	}
	if i := strings.IndexAny(s, "/?#:"); i >= 0 {
		s = s[:i]
	}
	return strings.TrimSuffix(s, ".")
}

func cmdDNS(r *resolver.Resolver, name string, types []string) *report.Report {
	name = cleanDomain(name)
	rep := report.New("dns", name)
	rep.Listing = true
	var qtypes []string
	if ip := net.ParseIP(name); ip != nil {
		names, err := r.PTR(ip)
		switch {
		case err != nil:
			rep.Add("", "PTR", report.Unknown, err.Error())
		case len(names) == 0:
			rep.Add("", "PTR", report.Warn, "no reverse DNS for "+name)
		default:
			rep.Add("", "PTR", report.Info, strings.Join(names, ", "))
		}
		return rep
	}
	if len(types) == 0 {
		qtypes = []string{"A", "AAAA", "CNAME", "MX", "NS", "TXT", "CAA", "SOA"}
	}
	for _, t := range types {
		qtypes = append(qtypes, strings.ToUpper(t))
	}
	ad := false
	shown := map[string]bool{}
	for _, t := range qtypes {
		qt := resolver.TypeByName(t)
		if qt == 0 {
			rep.Add("", t, report.Unknown, "unknown record type")
			continue
		}
		a, err := r.Query(name, qt)
		if err != nil {
			rep.Add("", t, report.Unknown, err.Error())
			continue
		}
		if a.AD {
			ad = true
		}
		switch a.RcodeName() {
		case "NXDOMAIN":
			rep.Add("", t, report.Fail, "NXDOMAIN: the name does not exist")
			rep.Note("Resolver: " + r.Label(a.Server))
			return rep
		case "SERVFAIL":
			rep.Add("", t, report.Fail, "SERVFAIL", "The resolver could not get an answer: broken name servers or a DNSSEC validation failure.")
			continue
		}
		n := 0
		for _, rr := range a.RRs {
			typ, ttl, val := resolver.Format(rr)
			if typ != t && typ != "CNAME" || shown[rr.String()] { // CNAME hops are shown once, wherever they first appear
				continue
			}
			shown[rr.String()] = true
			rep.Add("", typ, report.Info, fmt.Sprintf("%-6d %s", ttl, val))
			n++
		}
		if n == 0 && len(types) > 0 {
			rep.Add("", t, report.Info, "no records")
		}
	}
	if ad {
		rep.Note("DNSSEC: answers validated by the resolver (AD flag).")
	}
	if len(r.Servers) > 0 {
		rep.Note("Resolver: " + r.Label(r.Servers[0]))
	}
	return rep
}

func cmdBL(r *resolver.Resolver, t string, o opts) *report.Report {
	t = strings.TrimSpace(t)
	rep := report.New("bl", t)
	if ip := net.ParseIP(t); ip != nil {
		dnsbl.CheckIP(r, rep, "", ip, o.spamhausKey, o.verbose)
		return rep
	}
	d := cleanDomain(t)
	ips := mail.IPsOfMX(r, d, 5)
	if len(ips) == 0 {
		all, _ := r.IPs(d)
		for _, ip := range all {
			if ip.To4() != nil {
				ips = append(ips, ip)
			}
		}
		if len(ips) > 0 {
			rep.Note("No MX hosts found, so the website IPs (A records) were checked.")
		}
	} else {
		rep.Note("Checked the IPv4 addresses of the domain's mail servers (MX), the ones receivers see.")
	}
	if len(ips) == 0 {
		rep.Add("", d, report.Unknown, "the domain has no MX or A records to check")
	}
	for _, ip := range ips {
		dnsbl.CheckIP(r, rep, "Mail server IPs", ip, o.spamhausKey, o.verbose)
	}
	dnsbl.CheckDomain(r, rep, "Domain lists", d, o.spamhausKey, o.verbose)
	return rep
}

func cmdCheck(r *resolver.Resolver, d string, o opts, ua string) *report.Report {
	rep := report.New("check", d)
	sec := "DNS"
	ns, nsAns, err := r.NS(d)
	switch {
	case err != nil:
		rep.Add(sec, "Name servers", report.Unknown, err.Error())
	case nsAns.Rcode == 3:
		rep.Add(sec, "Name servers", report.Fail, "NXDOMAIN: "+d+" does not exist")
		return rep
	case len(ns) == 0:
		if org := mail.OrgDomain(d); org != d {
			rep.Add(sec, "Name servers", report.Info, "none at "+d+" (served by the "+org+" zone)")
		} else {
			rep.Add(sec, "Name servers", report.Fail, "no NS records")
		}
	case len(ns) == 1:
		rep.Add(sec, "Name servers", report.Warn, ns[0], "Only one name server: if it goes down, the whole domain stops resolving.", "Use at least two name servers on different networks.")
	default:
		rep.Add(sec, "Name servers", report.OK, strings.Join(ns, ", "))
	}
	ips, err := r.IPs(d)
	var v4, v6 []string
	for _, ip := range ips {
		if ip.To4() != nil {
			v4 = append(v4, ip.String())
		} else {
			v6 = append(v6, ip.String())
		}
	}
	switch {
	case err != nil:
		rep.Add(sec, "Address", report.Unknown, err.Error())
	case len(ips) == 0:
		rep.Add(sec, "Address", report.Warn, "no A or AAAA record", "Visitors cannot open "+d+" in a browser.")
	default:
		v := strings.Join(v4, ", ")
		if len(v6) > 0 {
			v = strings.TrimPrefix(v+" · IPv6 "+strings.Join(v6, ", "), " · ")
		}
		rep.Add(sec, "Address", report.OK, v)
		if len(v6) == 0 {
			rep.Add(sec, "IPv6", report.Info, "no AAAA record (optional)")
		}
	}
	zone := mail.OrgDomain(d)
	if ds, err := r.HasDS(zone); err == nil {
		if ds {
			a, _ := r.Query(zone, resolver.TypeByName("SOA"))
			if a != nil && a.AD {
				rep.Add(sec, "DNSSEC", report.OK, "signed and validated")
			} else {
				rep.Add(sec, "DNSSEC", report.OK, "signed (your resolver does not report validation)")
			}
		} else {
			rep.Add(sec, "DNSSEC", report.Info, "not signed (optional: protects DNS answers from forgery)")
		}
	}
	if caa, err := r.CAA(zone); err == nil {
		if len(caa) > 0 {
			rep.Add(sec, "CAA", report.OK, summarizeCAA(caa))
		} else {
			rep.Add(sec, "CAA", report.Info, "none (any certificate authority may issue for this domain)")
		}
	}

	if len(ips) > 0 {
		tlscheck.Check(rep, "HTTPS certificate", tlscheck.Options{Host: d, Port: 443, StartTLS: "none", WarnDays: o.warnDays, Timeout: o.timeout})
		web.Check(rep, "Website", d, web.Options{Timeout: o.timeout, UserAgent: ua, Insecure: true})
	}
	mail.Check(r, rep, "E-mail", d, mail.Options{Selectors: o.selectors, Timeout: o.timeout, UserAgent: ua})
	for _, ip := range mail.IPsOfMX(r, d, 3) {
		dnsbl.CheckIP(r, rep, "Blacklists (mail server IPs)", ip, o.spamhausKey, false)
	}
	rep.Note("Full reports and fixes: https://srvscripts.com/tools/domain-health-checker/?q=" + d)
	return rep
}

// summarizeCAA turns CAA records into "issue: letsencrypt.org, ssl.com · wildcard: … · reports: mailto:…".
func summarizeCAA(recs []string) string {
	groups := map[string][]string{}
	var order []string
	for _, r := range recs {
		parts := strings.SplitN(r, " ", 3)
		if len(parts) < 3 {
			continue
		}
		tag := parts[1]
		val := strings.Trim(parts[2], `"`)
		if i := strings.Index(val, ";"); i >= 0 {
			val = strings.TrimSpace(val[:i])
		}
		if val == "" {
			val = "none allowed"
		}
		if _, ok := groups[tag]; !ok {
			order = append(order, tag)
		}
		groups[tag] = append(groups[tag], val)
	}
	label := map[string]string{"issue": "issue", "issuewild": "wildcard", "iodef": "reports"}
	sort.Strings(order)
	var out []string
	for _, t := range order {
		l := label[t]
		if l == "" {
			l = t
		}
		v := groups[t]
		sort.Strings(v)
		out = append(out, l+": "+strings.Join(v, ", "))
	}
	return strings.Join(out, " · ")
}
