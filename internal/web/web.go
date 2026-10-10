// Package web checks a website: the redirect chain, HTTP to HTTPS upgrade, response and security headers.
package web

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/srvscripts/srvs-cli/internal/report"
)

// Options for the web check.
type Options struct {
	Timeout   time.Duration
	UserAgent string
	Insecure  bool // follow HTTPS even when the certificate is invalid (the TLS check reports it)
}

// Hop is one step of a redirect chain.
type Hop struct {
	URL    string
	Status int
	Proto  string
	Header http.Header
	Took   time.Duration
	Err    error
}

// Follow requests u and follows up to 10 redirects by hand, recording every hop.
func Follow(u string, o Options) []Hop {
	tr := &http.Transport{
		Proxy:               http.ProxyFromEnvironment,
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: o.Insecure}, //nolint:gosec // opt-in
		TLSHandshakeTimeout: o.Timeout,
		ForceAttemptHTTP2:   true,
	}
	c := &http.Client{Transport: tr, Timeout: o.Timeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	var hops []Hop
	seen := map[string]bool{}
	for i := 0; i < 11; i++ {
		req, err := http.NewRequest("GET", u, nil)
		if err != nil {
			hops = append(hops, Hop{URL: u, Err: err})
			return hops
		}
		req.Header.Set("User-Agent", o.UserAgent)
		req.Header.Set("Accept", "text/html,*/*;q=0.8")
		t0 := time.Now()
		resp, err := c.Do(req)
		took := time.Since(t0)
		if err != nil {
			hops = append(hops, Hop{URL: u, Err: err, Took: took})
			return hops
		}
		resp.Body.Close()
		hops = append(hops, Hop{URL: u, Status: resp.StatusCode, Proto: resp.Proto, Header: resp.Header, Took: took})
		if resp.StatusCode < 300 || resp.StatusCode > 399 {
			return hops
		}
		loc := resp.Header.Get("Location")
		if loc == "" {
			return hops
		}
		next, err := url.Parse(loc)
		if err != nil {
			return hops
		}
		base, _ := url.Parse(u)
		u = base.ResolveReference(next).String()
		if seen[u] {
			hops = append(hops, Hop{URL: u, Err: fmt.Errorf("redirect loop")})
			return hops
		}
		seen[u] = true
	}
	return hops
}

// Normalize turns "example.com" into "https://example.com/" and returns the host.
func Normalize(s string) (string, string, error) {
	s = strings.TrimSpace(s)
	if !strings.Contains(s, "://") {
		s = "https://" + s
	}
	u, err := url.Parse(s)
	if err != nil || u.Host == "" {
		return "", "", fmt.Errorf("not a website address: %q", s)
	}
	if u.Path == "" {
		u.Path = "/"
	}
	return u.String(), u.Hostname(), nil
}

// Check runs the website checks for target and adds them to rep.
func Check(rep *report.Report, section, target string, o Options) {
	u, host, err := Normalize(target)
	if err != nil {
		rep.Add(section, "Address", report.Unknown, err.Error())
		return
	}
	pu, _ := url.Parse(u)

	// 1. Plain HTTP should redirect to HTTPS.
	if pu.Scheme == "https" {
		hu := *pu
		hu.Scheme = "http"
		hops := Follow(hu.String(), o)
		first := hops[0]
		switch {
		case first.Err != nil:
			rep.Add(section, "HTTP → HTTPS", report.Info, "port 80 not reachable ("+short(first.Err)+")")
		case first.Status >= 300 && first.Status < 400:
			last := hops[len(hops)-1]
			if strings.HasPrefix(last.URL, "https://") {
				st := report.OK
				det := ""
				if first.Status != 301 && first.Status != 308 {
					st, det = report.Info, fmt.Sprintf("Uses %d; a permanent 301 or 308 is better for search engines.", first.Status)
				}
				rep.Add(section, "HTTP → HTTPS", st, fmt.Sprintf("redirects (%d)", first.Status), det)
			} else {
				rep.Add(section, "HTTP → HTTPS", report.Fail, "redirects, but not to HTTPS", "", "Redirect every http:// request to https:// with a 301.")
			}
		default:
			rep.Add(section, "HTTP → HTTPS", report.Fail, fmt.Sprintf("no redirect (status %d)", first.Status), "", "Redirect every http:// request to https:// with a 301.")
		}
	}

	// 2. The address itself.
	hops := Follow(u, o)
	last := hops[len(hops)-1]
	if len(hops) > 1 {
		var chain []string
		for _, h := range hops {
			if h.Status > 0 {
				chain = append(chain, strconv.Itoa(h.Status)+" "+h.URL)
			}
		}
		st := report.OK
		if len(hops) > 3 {
			st = report.Warn
		}
		rep.Add(section, "Redirects", st, fmt.Sprintf("%d hop(s)", len(hops)-1), strings.Join(chain, " → "))
	}
	if last.Err != nil {
		rep.Add(section, "Status", report.Fail, "no response: "+short(last.Err), "",
			"Check that the web server is running and that DNS points to the right server.")
		return
	}
	var total time.Duration
	for _, h := range hops {
		total += h.Took
	}
	switch {
	case last.Status >= 200 && last.Status < 300:
		rep.Add(section, "Status", report.OK, fmt.Sprintf("%d %s · %s · %d ms", last.Status, http.StatusText(last.Status), last.Proto, total.Milliseconds()))
	case last.Status == 401 || last.Status == 403:
		rep.Add(section, "Status", report.Warn, fmt.Sprintf("%d %s", last.Status, http.StatusText(last.Status)), "The server answers but refuses the request (password protection, firewall or WAF rule).")
	default:
		rep.Add(section, "Status", report.Fail, fmt.Sprintf("%d %s", last.Status, http.StatusText(last.Status)), "", "See https://srvscripts.com/guides/website-error-codes/ for what the code means.")
	}
	if total > 3*time.Second {
		rep.Add(section, "Speed", report.Warn, fmt.Sprintf("%d ms to the final response", total.Milliseconds()))
	}
	if sv := last.Header.Get("Server"); sv != "" {
		rep.Add(section, "Server", report.Info, sv)
	}
	if !strings.HasPrefix(last.URL, "https://") {
		rep.Add(section, "HTTPS", report.Fail, "the final page is served over plain HTTP", "", "Install a certificate and redirect to https://.")
		return
	}
	headers(rep, section, host, last.Header)
}

func headers(rep *report.Report, section, host string, h http.Header) {
	hsts := h.Get("Strict-Transport-Security")
	switch {
	case hsts == "":
		rep.Add(section, "HSTS", report.Warn, "missing", "", "Add Strict-Transport-Security: max-age=31536000 (add includeSubDomains once every subdomain has HTTPS).")
	default:
		age := 0
		for _, p := range strings.Split(hsts, ";") {
			k, v, _ := strings.Cut(strings.TrimSpace(p), "=")
			if strings.EqualFold(k, "max-age") {
				age, _ = strconv.Atoi(strings.Trim(v, `"`))
			}
		}
		if age < 15552000 {
			rep.Add(section, "HSTS", report.Warn, hsts, "max-age is under 180 days.", "Use max-age=31536000.")
		} else {
			rep.Add(section, "HSTS", report.OK, hsts)
		}
	}
	csp := h.Get("Content-Security-Policy")
	if csp == "" {
		if ro := h.Get("Content-Security-Policy-Report-Only"); ro != "" {
			rep.Add(section, "CSP", report.Info, "report-only (not enforced)")
		} else {
			rep.Add(section, "CSP", report.Warn, "missing", "", "Add a Content-Security-Policy; start with Content-Security-Policy-Report-Only to find what would break.")
		}
	} else {
		v := csp
		if len(v) > 90 {
			v = v[:87] + "…"
		}
		rep.Add(section, "CSP", report.OK, v)
	}
	if strings.EqualFold(strings.TrimSpace(h.Get("X-Content-Type-Options")), "nosniff") {
		rep.Add(section, "X-Content-Type-Options", report.OK, "nosniff")
	} else {
		rep.Add(section, "X-Content-Type-Options", report.Warn, "missing", "", "Add X-Content-Type-Options: nosniff.")
	}
	xfo := h.Get("X-Frame-Options")
	switch {
	case xfo != "":
		rep.Add(section, "Framing", report.OK, "X-Frame-Options: "+xfo)
	case strings.Contains(strings.ToLower(csp), "frame-ancestors"):
		rep.Add(section, "Framing", report.OK, "CSP frame-ancestors")
	default:
		rep.Add(section, "Framing", report.Warn, "not restricted", "Other sites can embed this site in a frame (clickjacking).", "Add X-Frame-Options: SAMEORIGIN or CSP frame-ancestors 'self'.")
	}
	if rp := h.Get("Referrer-Policy"); rp != "" {
		rep.Add(section, "Referrer-Policy", report.OK, rp)
	} else {
		rep.Add(section, "Referrer-Policy", report.Info, "missing (browsers default to strict-origin-when-cross-origin)")
	}
	if pp := h.Get("Permissions-Policy"); pp != "" {
		v := pp
		if len(v) > 80 {
			v = v[:77] + "…"
		}
		rep.Add(section, "Permissions-Policy", report.OK, v)
	} else {
		rep.Add(section, "Permissions-Policy", report.Info, "missing (optional: turns off browser features you do not use)")
	}
}

func short(err error) string {
	s := err.Error()
	if i := strings.LastIndex(s, ": "); i > 0 && len(s) > 90 {
		s = s[i+2:]
	}
	return s
}
