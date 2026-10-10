package dnsbl

import (
	"net"
	"testing"
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
