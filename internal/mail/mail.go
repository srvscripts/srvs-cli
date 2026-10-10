package mail

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/srvscripts/srvs-cli/internal/report"
	"github.com/srvscripts/srvs-cli/internal/resolver"
	"golang.org/x/net/publicsuffix"
)

// DefaultSelectors are tried when no DKIM selector is given: the names used by common providers and panels.
var DefaultSelectors = []string{
	"default", "dkim", "mail", "x", "s1", "s2", "k1", "k2", "k3", "selector1", "selector2", "google",
	"fm1", "fm2", "fm3", "protonmail", "protonmail2", "protonmail3", "zoho", "zmail", "mxvault", "smtp", "sig1",
	"mandrill", "mailjet", "everlytickey1", "everlytickey2", "dkim1", "key1", "mta", "mailo",
}

// Options for the mail check.
type Options struct {
	Selectors  []string // DKIM selectors; empty = DefaultSelectors
	Timeout    time.Duration
	UserAgent  string
	SkipRDNS   bool
	MaxMXHosts int
}

type txtAdapter struct{ r *resolver.Resolver }

func (a txtAdapter) TXT(name string) ([]string, error) {
	t, _, err := a.r.TXT(name)
	return t, err
}

// Check adds the mail checks for domain to rep under section.
func Check(r *resolver.Resolver, rep *report.Report, section, domain string, o Options) {
	if o.MaxMXHosts == 0 {
		o.MaxMXHosts = 5
	}
	// MX
	mxs, mxAns, err := r.MXs(domain)
	nullMX := false
	switch {
	case err != nil:
		rep.Add(section, "MX", report.Unknown, "lookup failed", err.Error())
	case mxAns.Rcode == 3:
		rep.Add(section, "MX", report.Fail, "domain does not exist (NXDOMAIN)")
		return
	case len(mxs) == 1 && mxs[0].Host == "":
		nullMX = true
		rep.Add(section, "MX", report.Info, "null MX: this domain accepts no e-mail")
	case len(mxs) == 0:
		rep.Add(section, "MX", report.Fail, "no MX records", "Nobody can send e-mail to this domain (some senders fall back to the A record).",
			"Add the MX records your mail provider gives you.")
	default:
		var hs []string
		for _, m := range mxs {
			hs = append(hs, fmt.Sprintf("%d %s", m.Pref, m.Host))
		}
		rep.Add(section, "MX", report.OK, strings.Join(hs, ", "))
	}
	if !nullMX && !o.SkipRDNS && len(mxs) > 0 {
		checkMXHosts(r, rep, section, mxs, o.MaxMXHosts)
	}

	// SPF
	spf, err := EvaluateSPF(txtAdapter{r}, domain)
	switch {
	case err != nil:
		rep.Add(section, "SPF", report.Unknown, "lookup failed", err.Error())
	case spf.Count == 0:
		st, fix := report.Fail, "Publish one TXT record such as \"v=spf1 include:<your provider> -all\" that lists every service sending as "+domain+"."
		if nullMX {
			st, fix = report.Warn, "A domain that sends no mail should publish \"v=spf1 -all\"."
		}
		rep.Add(section, "SPF", st, "missing", "", fix)
	default:
		st := report.OK
		detail := fmt.Sprintf("%d of %d DNS lookups", spf.Lookups, SPFLookupLimit)
		fix := ""
		switch spf.All {
		case "+":
			st, fix = report.Fail, "\"+all\" lets anyone send as "+domain+". End the record with \"~all\" or \"-all\"."
		case "?":
			st, fix = report.Warn, "\"?all\" gives no protection. End the record with \"~all\" or \"-all\"."
		case "":
			if spf.Redirect == "" {
				st, fix = report.Warn, "The record has no \"all\" at the end, so unlisted senders are treated as neutral. Add \"~all\" or \"-all\"."
			}
		}
		if spf.Lookups > 8 && spf.Lookups <= SPFLookupLimit && st == report.OK {
			st = report.Warn
			fix = "Close to the 10-lookup limit: one more include breaks SPF. Flatten or remove unused includes."
		}
		if len(spf.Problems) > 0 {
			st = report.Fail
			detail += "; " + strings.Join(spf.Problems, "; ")
			if fix == "" {
				fix = "Fix the SPF record so it is a single record within 10 DNS lookups."
			}
		}
		rep.Add(section, "SPF", st, spf.Record, detail, fix)
	}

	// DMARC
	checkDMARC(r, rep, section, domain)

	// DKIM
	if !nullMX {
		checkDKIM(r, rep, section, domain, o.Selectors)
	}

	// MTA-STS, TLS-RPT, BIMI
	if !nullMX {
		checkMTASTS(r, rep, section, domain, mxs, o)
		recs, _, err := r.TXT("_smtp._tls." + domain)
		switch {
		case err != nil:
			rep.Add(section, "TLS-RPT", report.Unknown, "lookup failed", err.Error())
		case hasPrefix(recs, "v=TLSRPTv1") != "":
			rep.Add(section, "TLS-RPT", report.OK, hasPrefix(recs, "v=TLSRPTv1"))
		default:
			rep.Add(section, "TLS-RPT", report.Info, "not published (optional: daily reports of TLS failures when others deliver to you)")
		}
		recs, _, err = r.TXT("default._bimi." + domain)
		if err == nil {
			if b := hasPrefix(recs, "v=BIMI1"); b != "" {
				rep.Add(section, "BIMI", report.OK, b)
			} else {
				rep.Add(section, "BIMI", report.Info, "not published (optional: logo in Gmail, Yahoo and Apple Mail; needs DMARC enforcement)")
			}
		}
	}
}

func hasPrefix(recs []string, p string) string {
	for _, t := range recs {
		if strings.HasPrefix(strings.ToLower(strings.TrimSpace(t)), strings.ToLower(p)) {
			return strings.TrimSpace(t)
		}
	}
	return ""
}

func checkMXHosts(r *resolver.Resolver, rep *report.Report, section string, mxs []resolver.MX, max int) {
	type res struct {
		host string
		st   report.Status
		val  string
		det  string
	}
	if len(mxs) > max {
		mxs = mxs[:max]
	}
	out := make([]res, len(mxs))
	var wg sync.WaitGroup
	for i, m := range mxs {
		wg.Add(1)
		go func(i int, host string) {
			defer wg.Done()
			ips, err := r.IPs(host)
			if err != nil || len(ips) == 0 {
				out[i] = res{host, report.Fail, "does not resolve", "The MX host has no A or AAAA record, so mail to it cannot be delivered."}
				return
			}
			var parts []string
			st := report.OK
			det := ""
			for _, ip := range ips {
				if ip.To4() == nil {
					continue // reverse DNS matters most for the IPv4 addresses mail is sent from
				}
				names, err := r.PTR(ip)
				switch {
				case err != nil:
					parts = append(parts, ip.String()+" (PTR lookup failed)")
					if st == report.OK {
						st = report.Unknown
					}
				case len(names) == 0:
					parts = append(parts, ip.String()+" (no PTR)")
					st = report.Warn
					det = "Receivers distrust mail from IPs without reverse DNS. Ask the IP owner (your host) to set a PTR record."
				default:
					back, _ := r.IPs(names[0])
					match := false
					for _, b := range back {
						if b.Equal(ip) {
							match = true
						}
					}
					if match {
						parts = append(parts, ip.String()+" → "+names[0])
					} else {
						parts = append(parts, ip.String()+" → "+names[0]+" (does not resolve back)")
						if st == report.OK {
							st = report.Warn
							det = "Forward-confirmed reverse DNS fails: the PTR name does not resolve back to the IP."
						}
					}
				}
			}
			if len(parts) == 0 {
				parts = []string{"IPv6 only"}
			}
			out[i] = res{host, st, strings.Join(parts, ", "), det}
		}(i, m.Host)
	}
	wg.Wait()
	for _, o := range out {
		rep.Add(section, "MX "+o.host, o.st, o.val, o.det)
	}
}

// OrgDomain returns the registrable domain (example.co.uk for mail.example.co.uk).
func OrgDomain(d string) string {
	if o, err := publicsuffix.EffectiveTLDPlusOne(d); err == nil {
		return o
	}
	return d
}

func checkDMARC(r *resolver.Resolver, rep *report.Report, section, domain string) {
	recs, _, err := r.TXT("_dmarc." + domain)
	if err != nil {
		rep.Add(section, "DMARC", report.Unknown, "lookup failed", err.Error())
		return
	}
	var dm []string
	for _, t := range recs {
		if strings.HasPrefix(strings.ToLower(strings.TrimSpace(t)), "v=dmarc1") {
			dm = append(dm, strings.TrimSpace(t))
		}
	}
	inherited := ""
	if len(dm) == 0 {
		if org := OrgDomain(domain); org != domain {
			if pr, _, err := r.TXT("_dmarc." + org); err == nil {
				for _, t := range pr {
					if strings.HasPrefix(strings.ToLower(strings.TrimSpace(t)), "v=dmarc1") {
						dm = append(dm, strings.TrimSpace(t))
						inherited = org
					}
				}
			}
		}
	}
	if len(dm) == 0 {
		rep.Add(section, "DMARC", report.Fail, "missing", "Gmail and Yahoo require DMARC from bulk senders.",
			"Publish \"v=DMARC1; p=none; rua=mailto:dmarc@"+domain+"\" at _dmarc."+domain+", read the reports, then move to p=quarantine.")
		return
	}
	if len(dm) > 1 {
		rep.Add(section, "DMARC", report.Fail, fmt.Sprintf("%d DMARC records", len(dm)), "Receivers ignore DMARC when more than one record is published.", "Keep exactly one record.")
		return
	}
	tags := map[string]string{}
	for _, p := range strings.Split(dm[0], ";") {
		k, v, ok := strings.Cut(strings.TrimSpace(p), "=")
		if ok {
			tags[strings.ToLower(strings.TrimSpace(k))] = strings.TrimSpace(v)
		}
	}
	pol := strings.ToLower(tags["p"])
	if inherited != "" {
		if sp := strings.ToLower(tags["sp"]); sp != "" {
			pol = sp
		}
	}
	val := dm[0]
	if inherited != "" {
		val += "  (from " + inherited + ")"
	}
	switch pol {
	case "reject", "quarantine":
		st := report.OK
		det := ""
		if pct := tags["pct"]; pct != "" && pct != "100" {
			st, det = report.Warn, "pct="+pct+": the policy applies to only part of the failing mail."
		}
		rep.Add(section, "DMARC", st, val, det)
	case "none":
		rep.Add(section, "DMARC", report.Warn, val, "p=none only monitors: spoofed mail using this domain is still delivered.",
			"Once SPF and DKIM pass for all your senders, move to p=quarantine, then p=reject.")
	default:
		rep.Add(section, "DMARC", report.Fail, val, "The record has no valid p= policy.", "Add p=none, p=quarantine or p=reject.")
	}
	if tags["rua"] == "" {
		rep.Add(section, "DMARC reports", report.Info, "no rua= address: you receive no aggregate reports")
	}
}

func checkDKIM(r *resolver.Resolver, rep *report.Report, section, domain string, selectors []string) {
	custom := len(selectors) > 0
	if !custom {
		selectors = DefaultSelectors
	}
	type hit struct{ sel, desc string }
	hits := make([]*hit, len(selectors))
	var wg sync.WaitGroup
	sem := make(chan struct{}, 8)
	for i, s := range selectors {
		wg.Add(1)
		go func(i int, s string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			recs, _, err := r.TXT(s + "._domainkey." + domain)
			if err != nil {
				return
			}
			for _, t := range recs {
				if d := dkimDescribe(t); d != "" {
					hits[i] = &hit{s, d}
					return
				}
			}
		}(i, s)
	}
	wg.Wait()
	var found []string
	weak := false
	for _, h := range hits {
		if h != nil {
			found = append(found, h.sel+" ("+h.desc+")")
			if strings.Contains(h.desc, "1024-bit") || strings.Contains(h.desc, "512-bit") || strings.Contains(h.desc, "revoked") {
				weak = true
			}
		}
	}
	switch {
	case len(found) > 0 && weak:
		rep.Add(section, "DKIM", report.Warn, strings.Join(found, ", "), "", "Rotate to a 2048-bit key; 1024-bit keys are considered weak.")
	case len(found) > 0:
		rep.Add(section, "DKIM", report.OK, strings.Join(found, ", "))
	case custom:
		rep.Add(section, "DKIM", report.Fail, "no key at selector(s) "+strings.Join(selectors, ", "), "", "Publish the DKIM key your mail provider gives you, or check the selector in a message's DKIM-Signature header (s=).")
	default:
		rep.Add(section, "DKIM", report.Info, "no key under common selectors", "DKIM needs the selector name; find it in the DKIM-Signature header (s=) of a sent message and run with --selector NAME.")
	}
}

// dkimDescribe returns "RSA 2048-bit" etc. for a DKIM key record, or "" when t is not one.
func dkimDescribe(t string) string {
	tags := map[string]string{}
	for _, p := range strings.Split(t, ";") {
		k, v, ok := strings.Cut(strings.TrimSpace(p), "=")
		if ok {
			tags[strings.ToLower(strings.TrimSpace(k))] = strings.Join(strings.Fields(v), "")
		}
	}
	p, ok := tags["p"]
	if !ok {
		return ""
	}
	if v := tags["v"]; v != "" && !strings.EqualFold(v, "DKIM1") {
		return ""
	}
	if p == "" {
		return "revoked (empty p=)"
	}
	kt := strings.ToLower(tags["k"])
	if kt == "ed25519" {
		return "Ed25519"
	}
	der, err := base64.StdEncoding.DecodeString(p)
	if err != nil {
		return "RSA, key not decodable"
	}
	if pub, err := x509.ParsePKIXPublicKey(der); err == nil {
		if k, ok := pub.(*rsa.PublicKey); ok {
			return fmt.Sprintf("RSA %d-bit", k.N.BitLen())
		}
		return "key found"
	}
	if k, err := x509.ParsePKCS1PublicKey(der); err == nil {
		return fmt.Sprintf("RSA %d-bit", k.N.BitLen())
	}
	return "key found"
}

func checkMTASTS(r *resolver.Resolver, rep *report.Report, section, domain string, mxs []resolver.MX, o Options) {
	recs, _, err := r.TXT("_mta-sts." + domain)
	if err != nil {
		rep.Add(section, "MTA-STS", report.Unknown, "lookup failed", err.Error())
		return
	}
	txt := hasPrefix(recs, "v=STSv1")
	if txt == "" {
		rep.Add(section, "MTA-STS", report.Info, "not published (optional: makes senders use encrypted TLS to reach you)")
		return
	}
	pol, err := fetchPolicy(domain, o)
	if err != nil {
		rep.Add(section, "MTA-STS", report.Fail, txt, "The TXT record exists but the policy file cannot be fetched: "+err.Error(),
			"Serve the policy at https://mta-sts."+domain+"/.well-known/mta-sts.txt with a valid certificate.")
		return
	}
	mode := pol["mode"]
	val := "mode=" + mode + ", max_age=" + pol["max_age"]
	var bad []string
	for _, m := range mxs {
		if m.Host != "" && !mxMatches(m.Host, pol["mx"]) {
			bad = append(bad, m.Host)
		}
	}
	switch {
	case len(bad) > 0:
		rep.Add(section, "MTA-STS", report.Fail, val, "MX host(s) not covered by the policy: "+strings.Join(bad, ", "), "Add the MX hosts to the mx: lines of the policy file.")
	case mode == "enforce":
		rep.Add(section, "MTA-STS", report.OK, val)
	case mode == "testing":
		rep.Add(section, "MTA-STS", report.Info, val+" (testing: failures are reported, not blocked)")
	default:
		rep.Add(section, "MTA-STS", report.Warn, val, "Mode is not enforce or testing.")
	}
}

func fetchPolicy(domain string, o Options) (map[string]string, error) {
	c := &http.Client{Timeout: o.Timeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	req, _ := http.NewRequest("GET", "https://mta-sts."+domain+"/.well-known/mta-sts.txt", nil)
	req.Header.Set("User-Agent", o.UserAgent)
	resp, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	pol := map[string]string{}
	var mx []string
	for _, l := range strings.Split(string(b), "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(l), ":")
		if !ok {
			continue
		}
		k, v = strings.ToLower(strings.TrimSpace(k)), strings.TrimSpace(v)
		if k == "mx" {
			mx = append(mx, strings.ToLower(v))
		} else {
			pol[k] = v
		}
	}
	if pol["version"] != "STSv1" {
		return nil, fmt.Errorf("policy file has no \"version: STSv1\" line")
	}
	pol["mx"] = strings.Join(mx, " ")
	return pol, nil
}

func mxMatches(host, patterns string) bool {
	host = strings.ToLower(host)
	for _, p := range strings.Fields(patterns) {
		if p == host {
			return true
		}
		if strings.HasPrefix(p, "*.") {
			if ok, _ := path.Match("*"+p[1:], host); ok && strings.Count(host, ".") == strings.Count(p, ".") {
				return true
			}
		}
	}
	return false
}

// IPsOfMX returns the IPv4 addresses of a domain's MX hosts (used by the blacklist check).
func IPsOfMX(r *resolver.Resolver, domain string, max int) []net.IP {
	mxs, _, err := r.MXs(domain)
	if err != nil {
		return nil
	}
	var out []net.IP
	seen := map[string]bool{}
	for i, m := range mxs {
		if i >= max || m.Host == "" {
			break
		}
		ips, _ := r.IPs(m.Host)
		for _, ip := range ips {
			if ip.To4() != nil && !seen[ip.String()] {
				seen[ip.String()] = true
				out = append(out, ip)
			}
		}
	}
	return out
}
