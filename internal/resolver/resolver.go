// Package resolver is a small DNS client: system resolver by default, TCP fallback, EDNS0 with the DO bit so the
// DNSSEC "authenticated data" flag comes back, and typed helpers for the record types the checks need.
package resolver

import (
	"errors"
	"fmt"
	"net"
	"sort"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// Resolver sends queries to one or more recursive servers in order.
type Resolver struct {
	Servers []string // host:port
	Timeout time.Duration
	client  *dns.Client
	tcp     *dns.Client
}

// Fallback servers when no system resolver is configured (Windows, containers without resolv.conf).
var Fallback = []string{"1.1.1.1:53", "8.8.8.8:53"}

// publicResolvers answer for everyone; some blacklists (Spamhaus) refuse queries that come through them.
var publicResolvers = map[string]bool{
	"1.1.1.1": true, "1.0.0.1": true, "8.8.8.8": true, "8.8.4.4": true, "9.9.9.9": true, "149.112.112.112": true,
	"208.67.222.222": true, "208.67.220.220": true, "94.140.14.14": true, "94.140.15.15": true,
	"2606:4700:4700::1111": true, "2001:4860:4860::8888": true,
}

// New builds a resolver. server may be "", "1.1.1.1", "1.1.1.1:53" or "[2606:4700:4700::1111]:53".
func New(server string, timeout time.Duration) *Resolver {
	r := &Resolver{Timeout: timeout}
	if server != "" {
		if _, _, err := net.SplitHostPort(server); err != nil {
			server = net.JoinHostPort(strings.Trim(server, "[]"), "53")
		}
		r.Servers = []string{server}
	} else if cfg, err := dns.ClientConfigFromFile("/etc/resolv.conf"); err == nil && len(cfg.Servers) > 0 {
		for _, s := range cfg.Servers {
			r.Servers = append(r.Servers, net.JoinHostPort(s, cfg.Port))
		}
	} else {
		r.Servers = append(r.Servers, Fallback...)
	}
	r.client = &dns.Client{Net: "udp", Timeout: timeout, UDPSize: 1232}
	r.tcp = &dns.Client{Net: "tcp", Timeout: timeout}
	return r
}

// UsesPublicResolver reports whether the first server is a well-known public resolver.
func (r *Resolver) UsesPublicResolver() bool {
	if len(r.Servers) == 0 {
		return false
	}
	h, _, _ := net.SplitHostPort(r.Servers[0])
	return publicResolvers[h]
}

// Describe returns the server list for notes.
func (r *Resolver) Describe() string { return strings.Join(r.Servers, ", ") }

// Answer is the result of one query.
type Answer struct {
	RRs    []dns.RR
	Rcode  int
	AD     bool // resolver validated the answer with DNSSEC
	Server string
}

// RcodeName is "NOERROR", "NXDOMAIN", "SERVFAIL"...
func (a *Answer) RcodeName() string { return dns.RcodeToString[a.Rcode] }

// ErrNoServers is returned when every server failed.
var ErrNoServers = errors.New("no DNS server answered")

// Query sends one question, falling back to TCP when the UDP answer is truncated and to the next server on error.
func (r *Resolver) Query(name string, qtype uint16) (*Answer, error) {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), qtype)
	m.RecursionDesired = true
	m.SetEdns0(1232, true)
	var lastErr error
	for _, srv := range r.Servers {
		in, _, err := r.client.Exchange(m, srv)
		if err == nil && in.Truncated {
			in, _, err = r.tcp.Exchange(m, srv)
		}
		if err != nil {
			lastErr = err
			continue
		}
		return &Answer{RRs: in.Answer, Rcode: in.Rcode, AD: in.AuthenticatedData, Server: srv}, nil
	}
	if lastErr == nil {
		lastErr = ErrNoServers
	}
	return nil, fmt.Errorf("%s %s: %w", name, dns.TypeToString[qtype], lastErr)
}

// rrs returns only the records of the asked type (an answer may also hold CNAMEs).
func rrs[T dns.RR](a *Answer) []T {
	var out []T
	for _, rr := range a.RRs {
		if v, ok := rr.(T); ok {
			out = append(out, v)
		}
	}
	return out
}

// TXT returns the TXT strings of name, each record's parts joined. NXDOMAIN gives an empty list and no error.
func (r *Resolver) TXT(name string) ([]string, *Answer, error) {
	a, err := r.Query(name, dns.TypeTXT)
	if err != nil {
		return nil, nil, err
	}
	if a.Rcode != dns.RcodeSuccess && a.Rcode != dns.RcodeNameError {
		return nil, a, fmt.Errorf("%s TXT: %s", name, a.RcodeName())
	}
	var out []string
	for _, t := range rrs[*dns.TXT](a) {
		out = append(out, strings.Join(t.Txt, ""))
	}
	return out, a, nil
}

// IPs returns the A and AAAA addresses of name (A first).
func (r *Resolver) IPs(name string) ([]net.IP, error) {
	var out []net.IP
	var firstErr error
	for _, t := range []uint16{dns.TypeA, dns.TypeAAAA} {
		a, err := r.Query(name, t)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		for _, rr := range a.RRs {
			switch v := rr.(type) {
			case *dns.A:
				out = append(out, v.A)
			case *dns.AAAA:
				out = append(out, v.AAAA)
			}
		}
	}
	if len(out) == 0 && firstErr != nil {
		return nil, firstErr
	}
	return out, nil
}

// MX is one mail exchanger.
type MX struct {
	Pref uint16
	Host string // without the trailing dot; "" for a null MX ("0 .")
}

// MXs returns the MX records sorted by preference.
func (r *Resolver) MXs(name string) ([]MX, *Answer, error) {
	a, err := r.Query(name, dns.TypeMX)
	if err != nil {
		return nil, nil, err
	}
	var out []MX
	for _, m := range rrs[*dns.MX](a) {
		out = append(out, MX{Pref: m.Preference, Host: strings.TrimSuffix(m.Mx, ".")})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Pref < out[j].Pref })
	return out, a, nil
}

// NS returns the name servers of a zone.
func (r *Resolver) NS(name string) ([]string, *Answer, error) {
	a, err := r.Query(name, dns.TypeNS)
	if err != nil {
		return nil, nil, err
	}
	var out []string
	for _, n := range rrs[*dns.NS](a) {
		out = append(out, strings.TrimSuffix(n.Ns, "."))
	}
	sort.Strings(out)
	return out, a, nil
}

// CAA returns the CAA records as "flag tag value".
func (r *Resolver) CAA(name string) ([]string, error) {
	a, err := r.Query(name, dns.TypeCAA)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, c := range rrs[*dns.CAA](a) {
		out = append(out, fmt.Sprintf("%d %s %q", c.Flag, c.Tag, c.Value))
	}
	return out, nil
}

// HasDS reports whether the parent zone publishes a DS record (the zone is signed).
func (r *Resolver) HasDS(name string) (bool, error) {
	a, err := r.Query(name, dns.TypeDS)
	if err != nil {
		return false, err
	}
	return len(rrs[*dns.DS](a)) > 0, nil
}

// PTR returns the reverse names of an IP.
func (r *Resolver) PTR(ip net.IP) ([]string, error) {
	arpa, err := dns.ReverseAddr(ip.String())
	if err != nil {
		return nil, err
	}
	a, err := r.Query(arpa, dns.TypePTR)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, p := range rrs[*dns.PTR](a) {
		out = append(out, strings.TrimSuffix(p.Ptr, "."))
	}
	return out, nil
}

// Format renders one record compactly: "TYPE TTL value".
func Format(rr dns.RR) (typ string, ttl uint32, value string) {
	h := rr.Header()
	s := rr.String()
	// rr.String() is "name ttl class type rdata"; keep the rdata.
	parts := strings.SplitN(s, "\t", 5)
	if len(parts) == 5 {
		value = parts[4]
	} else {
		value = s
	}
	return dns.TypeToString[h.Rrtype], h.Ttl, value
}

// TypeByName converts "MX" to dns.TypeMX (0 when unknown).
func TypeByName(s string) uint16 { return dns.StringToType[strings.ToUpper(s)] }
