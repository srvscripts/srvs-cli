package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestExitCode(t *testing.T) {
	mk := func(sts ...Status) *Report {
		r := New("t", "x")
		for _, s := range sts {
			r.Add("", "c", s, "")
		}
		return r
	}
	cases := []struct {
		r    *Report
		want int
	}{
		{mk(OK, Info), 0},
		{mk(OK, Warn), 1},
		{mk(Fail), 1},
		{mk(OK, Unknown), 2},
		{mk(Unknown, Fail), 1}, // a real failure wins over "could not check"
	}
	for i, c := range cases {
		if got := ExitCode(c.r); got != c.want {
			t.Errorf("case %d: exit %d, want %d", i, got, c.want)
		}
	}
	if ExitCode(mk(OK), mk(Unknown), mk(Warn)) != 1 {
		t.Error("combined reports")
	}
}

func TestTextAndJSON(t *testing.T) {
	r := New("ssl", "example.com")
	r.Add("", "Expires", Warn, "in 5 days", "", "Renew soon.")
	r.Add("", "Issuer", Info, "Let's Encrypt")
	var b bytes.Buffer
	r.Text(&b, Style{})
	out := b.String()
	for _, want := range []string{"[WARN] Expires", "→ Renew soon.", "0 passed · 1 warning(s)"} {
		if !strings.Contains(out, want) {
			t.Errorf("text output misses %q:\n%s", want, out)
		}
	}
	b.Reset()
	r.Text(&b, Style{Quiet: true})
	if strings.Contains(b.String(), "Issuer") {
		t.Error("quiet mode printed an info line")
	}
	b.Reset()
	if err := JSON(&b, []*Report{r}); err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Exit    int
		Reports []Report
	}
	if err := json.Unmarshal(b.Bytes(), &doc); err != nil || doc.Exit != 1 || doc.Reports[0].Checks[0].Status != Warn {
		t.Fatalf("json: %v %+v", err, doc)
	}
}
