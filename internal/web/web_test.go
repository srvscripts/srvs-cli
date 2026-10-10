package web

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/srvscripts/srvs-cli/internal/report"
)

func statuses(rep *report.Report) map[string]report.Status {
	m := map[string]report.Status{}
	for _, c := range rep.Checks {
		m[c.Name] = c.Status
	}
	return m
}

func TestHeadersAndRedirects(t *testing.T) {
	good := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			http.Redirect(w, r, "/home", http.StatusMovedPermanently)
			return
		}
		h := w.Header()
		h.Set("Strict-Transport-Security", "max-age=31536000")
		h.Set("Content-Security-Policy", "default-src 'self'; frame-ancestors 'self'")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		w.WriteHeader(200)
	}))
	defer good.Close()
	rep := report.New("http", good.URL)
	Check(rep, "", good.URL, Options{Timeout: 5 * time.Second, UserAgent: "test", Insecure: true})
	st := statuses(rep)
	for name, want := range map[string]report.Status{"Status": report.OK, "HSTS": report.OK, "CSP": report.OK, "Framing": report.OK, "X-Content-Type-Options": report.OK, "Redirects": report.OK} {
		if st[name] != want {
			t.Errorf("%s = %q, want %q (%+v)", name, st[name], want, rep.Checks)
		}
	}

	bare := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(503) }))
	defer bare.Close()
	rep = report.New("http", bare.URL)
	Check(rep, "", bare.URL, Options{Timeout: 5 * time.Second, UserAgent: "test", Insecure: true})
	st = statuses(rep)
	if st["Status"] != report.Fail {
		t.Errorf("503 should fail: %+v", rep.Checks)
	}
	if st["HSTS"] != report.Warn || st["Framing"] != report.Warn {
		t.Errorf("missing headers should warn: %+v", rep.Checks)
	}
}

func TestRedirectLoop(t *testing.T) {
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, srv.URL+"/a", http.StatusFound)
	}))
	defer srv.Close()
	hops := Follow(srv.URL+"/", Options{Timeout: 3 * time.Second})
	if last := hops[len(hops)-1]; last.Err == nil {
		t.Fatalf("expected a loop error, got %d hops", len(hops))
	}
}
