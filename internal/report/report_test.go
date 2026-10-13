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
	if err := JSON(&b, Exit(false, r), []*Report{r}); err != nil {
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

// CLI-01/02 (audit 13 Oct 2026): one exit code per run, with and without --ignore-warnings, and the JSON "exit"
// field always equal to it.
func TestExitPolicyAndJSONAgreement(t *testing.T) {
	mk := func(sts ...Status) *Report {
		r := New("t", "x")
		for _, s := range sts {
			r.Add("", "c", s, "")
		}
		return r
	}
	cases := []struct {
		name         string
		reps         []*Report
		plain, ignor int
	}{
		{"ok", []*Report{mk(OK, Info)}, 0, 0},
		{"warn only", []*Report{mk(OK, Warn)}, 1, 0},
		{"unknown only", []*Report{mk(Unknown)}, 2, 2},
		{"warn + unknown", []*Report{mk(Warn, Unknown)}, 1, 2},
		{"fail", []*Report{mk(Fail)}, 1, 1},
		{"fail + unknown", []*Report{mk(Fail, Unknown)}, 1, 1},
		{"fail + warn", []*Report{mk(Warn, Fail)}, 1, 1},
		{"targets: warn, unknown", []*Report{mk(OK, Warn), mk(Unknown)}, 1, 2},
		{"targets: warn, fail, unknown", []*Report{mk(Warn), mk(Fail), mk(Unknown)}, 1, 1},
		{"targets: ok, warn", []*Report{mk(OK), mk(Warn)}, 1, 0},
	}
	for _, c := range cases {
		for _, ign := range []bool{false, true} {
			want := c.plain
			if ign {
				want = c.ignor
			}
			code := Exit(ign, c.reps...)
			if code != want {
				t.Errorf("%s (ignore-warnings=%v): exit %d, want %d", c.name, ign, code, want)
			}
			var b bytes.Buffer
			if err := JSON(&b, code, c.reps); err != nil {
				t.Fatal(err)
			}
			var got struct{ Exit int }
			if err := json.Unmarshal(b.Bytes(), &got); err != nil || got.Exit != code {
				t.Errorf("%s (ignore-warnings=%v): JSON exit %d, process exit %d (%v)", c.name, ign, got.Exit, code, err)
			}
		}
	}
}
