package dnsbl

import (
	"net"
	"strings"
	"testing"

	"github.com/srvscripts/srvs-cli/internal/report"
)

func TestReverse(t *testing.T) {
	if got := Reverse(net.ParseIP("192.0.2.10")); got != "10.2.0.192" {
		t.Errorf("IPv4: %q", got)
	}
	got := Reverse(net.ParseIP("2001:db8::1"))
	want := "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2"
	if got != want {
		t.Errorf("IPv6: %q", got)
	}
}

func TestRefused(t *testing.T) {
	zen := IPLists[0]
	if refused(zen, "127.255.255.254") == "" || refused(zen, "127.0.0.2") != "" {
		t.Error("Spamhaus refusal codes")
	}
	uribl := DomainLists[2]
	if refused(uribl, "127.0.0.1") == "" {
		t.Error("URIBL refusal code")
	}
}

func TestWithKey(t *testing.T) {
	if withKey(IPLists[0], "abc").Zone != "abc.zen.dq.spamhaus.net" || withKey(DomainLists[0], "abc").Zone != "abc.dbl.dq.spamhaus.net" {
		t.Error("DQS zones")
	}
	if withKey(IPLists[1], "abc").Zone != IPLists[1].Zone {
		t.Error("non-Spamhaus list changed")
	}
}

func TestListsAreUnique(t *testing.T) {
	seen := map[string]bool{}
	for _, l := range append(append([]List{}, IPLists...), DomainLists...) {
		if seen[l.Zone] {
			t.Errorf("duplicate zone %s", l.Zone)
		}
		seen[l.Zone] = true
		if l.Weight < 1 || l.Weight > 3 {
			t.Errorf("%s weight %d", l.Name, l.Weight)
		}
	}
}

func TestSPFBLOnlySpamCodeIsAListing(t *testing.T) {
	var spfbl *List
	for i := range IPLists {
		if IPLists[i].Zone == "dnsbl.spfbl.net" {
			spfbl = &IPLists[i]
		}
	}
	if spfbl == nil || spfbl.Match == nil {
		t.Fatal("SPFBL must have a Match pattern")
	}
	if !spfbl.Match.MatchString("127.0.0.2") {
		t.Error("127.0.0.2 (spam complaints) must count as listed")
	}
	for _, code := range []string{"127.0.0.3", "127.0.0.4", "127.0.0.5"} {
		if spfbl.Match.MatchString(code) {
			t.Errorf("%s must not count as listed", code)
		}
		if Notes[spfbl.Zone][code] == "" {
			t.Errorf("%s needs a note", code)
		}
	}
}

func TestNoteIsInfoAndKeepsExitZero(t *testing.T) {
	spfbl := List{Name: "SPFBL", Zone: "dnsbl.spfbl.net", Info: "https://spfbl.net/en/delist/", Weight: 1}
	rep := report.New("bl", "192.0.2.1")
	addResults(rep, "Blacklists", "192.0.2.1", []Result{
		{List: spfbl, Answer: "127.0.0.5", Note: Notes["dnsbl.spfbl.net"]["127.0.0.5"]},
		{List: List{Name: "Other", Zone: "x.test", Weight: 2}},
	}, false)
	var note *report.Check
	for i := range rep.Checks {
		if strings.Contains(rep.Checks[i].Name, "SPFBL") {
			note = &rep.Checks[i]
		}
	}
	if note == nil || note.Status != report.Info || !strings.Contains(note.Value, "127.0.0.5") {
		t.Fatalf("note not reported as info: %+v", rep.Checks)
	}
	if !strings.Contains(rep.Checks[len(rep.Checks)-1].Value, "not listed on 2 of 2 lists") {
		t.Errorf("summary: %+v", rep.Checks[len(rep.Checks)-1])
	}
	if code := report.ExitCode(rep); code != 0 {
		t.Errorf("exit code %d, want 0", code)
	}
}
