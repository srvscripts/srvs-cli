package tlscheck

import (
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/srvscripts/srvs-cli/internal/report"
)

// A self-signed local test server: the check must connect, report the chain as untrusted and the name as mismatched.
func TestSelfSignedServer(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()
	host, port, _ := net.SplitHostPort(srv.Listener.Addr().String())
	p, _ := strconv.Atoi(port)
	rep := report.New("ssl", "local")
	Check(rep, "", Options{Host: "example.test", Addr: host, Port: p, StartTLS: "none", Timeout: 5 * time.Second})
	got := map[string]report.Status{}
	for _, c := range rep.Checks {
		got[c.Name] = c.Status
	}
	if got["Trusted"] != report.Fail {
		t.Errorf("Trusted = %q, want fail (%+v)", got["Trusted"], rep.Checks)
	}
	if got["Hostname"] != report.Fail {
		t.Errorf("Hostname = %q, want fail", got["Hostname"])
	}
	if got["Protocol"] != report.OK {
		t.Errorf("Protocol = %q, want ok", got["Protocol"])
	}
	if report.ExitCode(rep) != 1 {
		t.Error("exit code should be 1")
	}
}

func TestConnectionRefusedIsUnknown(t *testing.T) {
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()
	rep := report.New("ssl", "closed")
	Check(rep, "", Options{Host: "localhost", Addr: "127.0.0.1", Port: port, StartTLS: "none", Timeout: 2 * time.Second})
	if len(rep.Checks) != 1 || rep.Checks[0].Status != report.Unknown {
		t.Fatalf("got %+v", rep.Checks)
	}
}
