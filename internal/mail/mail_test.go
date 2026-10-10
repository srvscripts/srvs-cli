package mail

import (
	"strings"
	"testing"
)

type fakeTXT map[string][]string

func (f fakeTXT) TXT(name string) ([]string, error) { return f[name], nil }

func TestSPFCountsNestedLookups(t *testing.T) {
	r := fakeTXT{
		"example.com":    {"v=spf1 a mx include:_spf.one.test include:two.test ~all", "google-site-verification=x"},
		"_spf.one.test":  {"v=spf1 include:inner.one.test ip4:192.0.2.0/24 -all"},
		"inner.one.test": {"v=spf1 exists:%{i}.x.test -all"},
		"two.test":       {"v=spf1 ip6:2001:db8::/32 -all"},
	}
	res, err := EvaluateSPF(r, "example.com")
	if err != nil {
		t.Fatal(err)
	}
	// a, mx, include one, include inner, exists, include two = 6
	if res.Lookups != 6 {
		t.Fatalf("lookups = %d, want 6 (tree %v)", res.Lookups, res.Tree)
	}
	if res.All != "~" || res.Count != 1 || len(res.Problems) != 0 {
		t.Fatalf("all=%q count=%d problems=%v", res.All, res.Count, res.Problems)
	}
}

func TestSPFOverLimitAndMissingInclude(t *testing.T) {
	inc := []string{}
	r := fakeTXT{}
	for i := 0; i < 11; i++ {
		n := string(rune('a'+i)) + ".test"
		inc = append(inc, "include:"+n)
		r[n] = []string{"v=spf1 -all"}
	}
	r["big.test"] = []string{"v=spf1 " + strings.Join(inc, " ") + " include:missing.test -all"}
	res, _ := EvaluateSPF(r, "big.test")
	if res.Lookups != 12 {
		t.Fatalf("lookups = %d, want 12", res.Lookups)
	}
	joined := strings.Join(res.Problems, "|")
	if !strings.Contains(joined, "over the limit") || !strings.Contains(joined, "missing.test has no SPF") {
		t.Fatalf("problems = %v", res.Problems)
	}
}

func TestSPFMultipleRecordsAndRedirect(t *testing.T) {
	r := fakeTXT{
		"multi.test":      {"v=spf1 -all", "v=spf1 ~all"},
		"redir.test":      {"v=spf1 redirect=_spf.redir.test"},
		"_spf.redir.test": {"v=spf1 ip4:198.51.100.1 -all"},
		"both.test":       {"v=spf1 -all redirect=_spf.redir.test"},
		"loop.test":       {"v=spf1 include:loop.test -all"},
	}
	if res, _ := EvaluateSPF(r, "multi.test"); res.Count != 2 || len(res.Problems) == 0 {
		t.Fatalf("multiple records not reported: %+v", res)
	}
	if res, _ := EvaluateSPF(r, "redir.test"); res.All != "-" || res.Redirect != "_spf.redir.test" || res.Lookups != 1 {
		t.Fatalf("redirect: %+v", res)
	}
	if res, _ := EvaluateSPF(r, "both.test"); res.Lookups != 0 || !strings.Contains(strings.Join(res.Problems, ""), "ignored") {
		t.Fatalf("redirect with all should be ignored: %+v", res)
	}
	if res, _ := EvaluateSPF(r, "loop.test"); !strings.Contains(strings.Join(res.Problems, ""), "loop") {
		t.Fatalf("loop not detected: %+v", res)
	}
	if res, _ := EvaluateSPF(r, "none.test"); res.Count != 0 {
		t.Fatalf("none: %+v", res)
	}
}

func TestIsSPF(t *testing.T) {
	for in, want := range map[string]bool{"v=spf1 -all": true, "V=SPF1 mx -all": true, "v=spf1": true, "v=spf10 -all": false, "spf1": false} {
		if IsSPF(in) != want {
			t.Errorf("IsSPF(%q) = %v", in, !want)
		}
	}
}

func TestDKIMDescribe(t *testing.T) {
	// 1024-bit RSA public key (SubjectPublicKeyInfo) from RFC 6376 examples style.
	k1024 := "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDwIRP/UC3SBsEmGqZ9ZJW3/DkMoGeLnQg1fWn7/zYtIxN2SnFCjxOCKG9v3b4jYfcTNh5ijSsq631uBItLa7od+v/RtdC2UzJ1lWT947qR+Rcac2gbto/NMqJ0fzfVjH4OuKhitdY9tf6mcwGjaNBcWToIMmPSPDdQPNUYckcQ2QIDAQAB"
	cases := map[string]string{
		"v=DKIM1; k=rsa; p=" + k1024: "RSA 1024-bit",
		"v=DKIM1; p=":                "revoked (empty p=)",
		"v=DKIM1; k=ed25519; p=11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=": "Ed25519",
		"v=spf1 -all":    "",
		"v=DKIM2; p=abc": "",
	}
	for in, want := range cases {
		if got := dkimDescribe(in); got != want {
			t.Errorf("dkimDescribe(%.30q) = %q, want %q", in, got, want)
		}
	}
}

func TestMXMatches(t *testing.T) {
	pats := "mail.example.com *.mx.example.net"
	for host, want := range map[string]bool{
		"mail.example.com":   true,
		"a.mx.example.net":   true,
		"a.b.mx.example.net": false,
		"mx.example.net":     false,
		"other.example.com":  false,
	} {
		if mxMatches(host, pats) != want {
			t.Errorf("mxMatches(%q) = %v", host, !want)
		}
	}
}

func TestOrgDomain(t *testing.T) {
	for in, want := range map[string]string{"mail.example.co.uk": "example.co.uk", "example.com": "example.com", "a.b.example.org": "example.org"} {
		if got := OrgDomain(in); got != want {
			t.Errorf("OrgDomain(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestSPFSameIncludeTwiceIsNotALoop(t *testing.T) {
	r := fakeTXT{
		"d.test":      {"v=spf1 include:a.test include:shared.test -all"},
		"a.test":      {"v=spf1 include:shared.test -all"},
		"shared.test": {"v=spf1 ip4:192.0.2.1 -all"},
	}
	res, _ := EvaluateSPF(r, "d.test")
	if len(res.Problems) != 0 || res.Lookups != 3 {
		t.Fatalf("problems=%v lookups=%d", res.Problems, res.Lookups)
	}
}
