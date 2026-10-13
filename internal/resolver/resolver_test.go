package resolver

import (
	"net"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"testing"
	"time"
)

func TestServersFromResolvConf(t *testing.T) {
	p := filepath.Join(t.TempDir(), "resolv.conf")
	if err := os.WriteFile(p, []byte("# test\nsearch example.com\nnameserver 10.0.0.2\nnameserver 2001:db8::53\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	want := []string{"10.0.0.2:53", "[2001:db8::53]:53"}
	if got := serversFromResolvConf(p); !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
	if got := serversFromResolvConf(filepath.Join(t.TempDir(), "missing")); got != nil {
		t.Errorf("missing file gave %v", got)
	}
}

func TestUsableDNS(t *testing.T) {
	in := []net.IP{net.ParseIP("192.168.1.1"), net.ParseIP("fec0:0:0:ffff::1"), net.ParseIP("fe80::1"), net.ParseIP("0.0.0.0"),
		net.ParseIP("192.168.1.1"), net.ParseIP("2001:db8::53"), nil}
	want := []string{"192.168.1.1:53", "[2001:db8::53]:53"}
	if got := usableDNS(in); !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestNewSources(t *testing.T) {
	if r := New("9.9.9.9", time.Second); r.Source != "flag" || r.Servers[0] != "9.9.9.9:53" {
		t.Errorf("flag: %+v", r)
	}
	r := New("", time.Second)
	if len(r.Servers) == 0 || (r.Source != "system" && r.Source != "fallback") {
		t.Errorf("default: %+v", r)
	}
	if r.Source == "fallback" && r.Label("1.1.1.1:53") == "1.1.1.1:53" {
		t.Error("fallback is not labelled")
	}
}

// On the CI runners (Linux, macOS, Windows) the operating system has DNS servers configured, so discovery must find them
// instead of using the public fallback.
func TestSystemServersFound(t *testing.T) {
	if os.Getenv("CI") == "" {
		t.Skip("only asserted on CI runners, where DNS is known to be configured")
	}
	s := systemServers()
	if len(s) == 0 {
		t.Fatalf("no system DNS servers found on %s", runtime.GOOS)
	}
	t.Logf("%s system resolvers: %v", runtime.GOOS, s)
}
