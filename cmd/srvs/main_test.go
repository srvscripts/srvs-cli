package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/srvscripts/srvs-cli/internal/tlscheck"
	"github.com/srvscripts/srvs-cli/internal/web"
)

func TestCleanDomain(t *testing.T) {
	for in, want := range map[string]string{
		"Example.COM":                "example.com",
		"https://example.com/path?x": "example.com",
		"user@mail.example.org":      "mail.example.org",
		"example.com.":               "example.com",
		"example.com:443":            "example.com",
	} {
		if got := cleanDomain(in); got != want {
			t.Errorf("cleanDomain(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestParseTLSTarget(t *testing.T) {
	cases := []struct {
		in   string
		host string
		port int
	}{
		{"example.com", "example.com", 443},
		{"mail.example.com:587", "mail.example.com", 587},
		{"https://Example.com/x", "example.com", 443},
		{"[2001:db8::1]:993", "2001:db8::1", 993},
	}
	for _, c := range cases {
		h, p, err := tlscheck.ParseTarget(c.in)
		if err != nil || h != c.host || p != c.port {
			t.Errorf("ParseTarget(%q) = %q %d %v", c.in, h, p, err)
		}
	}
	if _, _, err := tlscheck.ParseTarget("example.com:99999"); err == nil {
		t.Error("bad port accepted")
	}
	if tlscheck.StartTLSFor(587) != "smtp" || tlscheck.StartTLSFor(993) != "none" || tlscheck.StartTLSFor(143) != "imap" {
		t.Error("STARTTLS port mapping")
	}
}

func TestNormalizeURL(t *testing.T) {
	u, h, err := web.Normalize("example.com")
	if err != nil || u != "https://example.com/" || h != "example.com" {
		t.Errorf("Normalize: %q %q %v", u, h, err)
	}
}

func TestSummarizeCAA(t *testing.T) {
	got := summarizeCAA([]string{`0 issue "letsencrypt.org"`, `0 issuewild ";"`, `0 iodef "mailto:a@b.test"`, `0 issue "pki.goog; cansignhttpexchanges=yes"`})
	want := `iodef: mailto:a@b.test · issue: letsencrypt.org, pki.goog · issuewild: none allowed`
	want = strings.NewReplacer("iodef:", "reports:", "issuewild:", "wildcard:").Replace(want)
	if got != want {
		t.Errorf("summarizeCAA = %q\nwant          %q", got, want)
	}
}

func TestUsageAndErrors(t *testing.T) {
	var out, errb bytes.Buffer
	if code := run([]string{}, &out, &errb); code != 0 || !strings.Contains(out.String(), "srvs check") {
		t.Errorf("usage: %d %q", code, out.String())
	}
	out.Reset()
	if code := run([]string{"version"}, &out, &errb); code != 0 || !strings.HasPrefix(out.String(), "srvs ") {
		t.Errorf("version: %d %q", code, out.String())
	}
	if code := run([]string{"ssl"}, &out, &errb); code != 2 {
		t.Errorf("missing target should exit 2, got %d", code)
	}
	if code := run([]string{"nope", "x"}, &out, &errb); code != 2 {
		t.Errorf("unknown command should exit 2, got %d", code)
	}
}

// The process exit status and the JSON "exit" field come from the same value (audit CLI-01/02). An unresolvable
// .invalid target is "unknown" without needing the network.
func TestRunExitMatchesJSON(t *testing.T) {
	for _, args := range [][]string{
		{"ssl", "does-not-exist.invalid:443", "--json", "--timeout", "2s"},
		{"ssl", "does-not-exist.invalid:443", "--json", "--timeout", "2s", "--ignore-warnings"},
	} {
		var out, errb bytes.Buffer
		code := run(args, &out, &errb)
		var doc struct{ Exit int }
		if err := json.Unmarshal(out.Bytes(), &doc); err != nil {
			t.Fatalf("%v: bad JSON: %v\n%s", args, err, out.String())
		}
		if code != doc.Exit || code != 2 {
			t.Errorf("%v: process exit %d, JSON exit %d, want both 2", args, code, doc.Exit)
		}
	}
}
