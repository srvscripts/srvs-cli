// Package tlscheck connects to a TLS service (directly or with STARTTLS) and checks its certificate and protocol.
package tlscheck

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/srvscripts/srvs-cli/internal/report"
)

// Options for a TLS check.
type Options struct {
	Host     string // name used for SNI and certificate matching
	Port     int
	Addr     string // optional IP to connect to instead of resolving Host
	StartTLS string // "auto", "smtp", "imap", "pop3" or "none"
	WarnDays int    // warn when the certificate expires within this many days
	Timeout  time.Duration
	Legacy   bool // also test whether TLS 1.0/1.1 are accepted
}

// ParseTarget splits "host", "host:port" or "[v6]:port" (default port 443).
func ParseTarget(s string) (string, int, error) {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(strings.TrimPrefix(s, "https://"), "http://")
	if i := strings.IndexAny(s, "/?#"); i >= 0 {
		s = s[:i]
	}
	host, port := s, 443
	if h, p, err := net.SplitHostPort(s); err == nil {
		n, err := strconv.Atoi(p)
		if err != nil || n < 1 || n > 65535 {
			return "", 0, fmt.Errorf("bad port %q", p)
		}
		host, port = h, n
	}
	host = strings.Trim(host, "[]")
	if host == "" {
		return "", 0, errors.New("empty host")
	}
	return strings.ToLower(host), port, nil
}

// StartTLSFor returns the protocol to use for a port when StartTLS is "auto".
func StartTLSFor(port int) string {
	switch port {
	case 25, 587, 2525:
		return "smtp"
	case 143:
		return "imap"
	case 110:
		return "pop3"
	}
	return "none"
}

func dial(o Options, cfg *tls.Config) (*tls.Conn, error) {
	addr := o.Addr
	if addr == "" {
		addr = o.Host
	}
	d := &net.Dialer{Timeout: o.Timeout}
	raw, err := d.Dial("tcp", net.JoinHostPort(addr, strconv.Itoa(o.Port)))
	if err != nil {
		return nil, err
	}
	_ = raw.SetDeadline(time.Now().Add(o.Timeout * 2))
	proto := o.StartTLS
	if proto == "" || proto == "auto" {
		proto = StartTLSFor(o.Port)
	}
	if proto != "none" {
		if err := startTLS(raw, proto); err != nil {
			raw.Close()
			return nil, err
		}
	}
	c := tls.Client(raw, cfg)
	if err := c.Handshake(); err != nil {
		raw.Close()
		return nil, err
	}
	return c, nil
}

func startTLS(c net.Conn, proto string) error {
	rd := bufio.NewReader(c)
	readSMTP := func() (string, error) {
		var last string
		for {
			l, err := rd.ReadString('\n')
			if err != nil {
				return last, err
			}
			last += l
			if len(l) < 4 || l[3] != '-' {
				return last, nil
			}
		}
	}
	switch proto {
	case "smtp":
		g, err := readSMTP()
		if err != nil || !strings.HasPrefix(g, "220") {
			return fmt.Errorf("SMTP greeting: %q %v", strings.TrimSpace(g), err)
		}
		fmt.Fprintf(c, "EHLO srvs-cli.invalid\r\n")
		e, err := readSMTP()
		if err != nil || !strings.HasPrefix(e, "250") {
			return fmt.Errorf("EHLO: %q %v", strings.TrimSpace(e), err)
		}
		if !strings.Contains(strings.ToUpper(e), "STARTTLS") {
			return errors.New("the server does not offer STARTTLS")
		}
		fmt.Fprintf(c, "STARTTLS\r\n")
		s, err := readSMTP()
		if err != nil || !strings.HasPrefix(s, "220") {
			return fmt.Errorf("STARTTLS: %q %v", strings.TrimSpace(s), err)
		}
	case "imap":
		g, err := rd.ReadString('\n')
		if err != nil || !strings.HasPrefix(g, "* OK") {
			return fmt.Errorf("IMAP greeting: %q %v", strings.TrimSpace(g), err)
		}
		fmt.Fprintf(c, "a1 STARTTLS\r\n")
		for {
			l, err := rd.ReadString('\n')
			if err != nil {
				return err
			}
			if strings.HasPrefix(l, "a1 ") {
				if !strings.HasPrefix(l, "a1 OK") {
					return fmt.Errorf("STARTTLS: %q", strings.TrimSpace(l))
				}
				break
			}
		}
	case "pop3":
		g, err := rd.ReadString('\n')
		if err != nil || !strings.HasPrefix(g, "+OK") {
			return fmt.Errorf("POP3 greeting: %q %v", strings.TrimSpace(g), err)
		}
		fmt.Fprintf(c, "STLS\r\n")
		l, err := rd.ReadString('\n')
		if err != nil || !strings.HasPrefix(l, "+OK") {
			return fmt.Errorf("STLS: %q %v", strings.TrimSpace(l), err)
		}
	default:
		return fmt.Errorf("unknown STARTTLS protocol %q", proto)
	}
	return nil
}

// Check runs the TLS check and adds the results to rep.
func Check(rep *report.Report, section string, o Options) {
	if o.WarnDays == 0 {
		o.WarnDays = 14
	}
	where := net.JoinHostPort(o.Host, strconv.Itoa(o.Port))
	if o.Addr != "" {
		where += " via " + o.Addr
	}
	cfg := &tls.Config{ServerName: o.Host, InsecureSkipVerify: true, MinVersion: tls.VersionTLS12} //nolint:gosec // verified below so details can be reported
	conn, err := dial(o, cfg)
	if err != nil {
		st := report.Fail
		det := ""
		var ne net.Error
		// "connection refused" (Linux, macOS) or "actively refused it" (Windows): the port is closed, so not checked.
		if errors.As(err, &ne) && ne.Timeout() || strings.Contains(err.Error(), "refused") || strings.Contains(err.Error(), "no such host") {
			st = report.Unknown
			if o.Port == 25 {
				det = "Many home and cloud networks block outgoing port 25. Try from a server, or check port 587/465."
			}
		}
		if strings.Contains(err.Error(), "protocol version") || strings.Contains(err.Error(), "handshake failure") {
			det = "No TLS 1.2 or 1.3 handshake was possible. The server may only offer old protocols or no TLS at all."
		}
		rep.Add(section, "Connection", st, where+": "+err.Error(), det)
		return
	}
	defer conn.Close()
	cs := conn.ConnectionState()
	certs := cs.PeerCertificates
	if len(certs) == 0 {
		rep.Add(section, "Certificate", report.Fail, "the server sent no certificate")
		return
	}
	leaf := certs[0]
	now := time.Now()

	// Chain of trust.
	inter := x509.NewCertPool()
	for _, c := range certs[1:] {
		inter.AddCert(c)
	}
	roots, _ := x509.SystemCertPool()
	_, verr := leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: inter, CurrentTime: now})
	switch {
	case verr == nil:
		rep.Add(section, "Trusted", report.OK, "yes, chain is valid")
	case errors.As(verr, new(x509.UnknownAuthorityError)):
		det := "The certificate is self-signed or issued by an unknown CA, or the server does not send the intermediate certificate."
		if len(certs) == 1 && leaf.Issuer.String() != leaf.Subject.String() {
			det = "The server sends only its own certificate; the intermediate certificate is missing from the chain."
		}
		rep.Add(section, "Trusted", report.Fail, "no: "+verr.Error(), det, "Install the full chain (certificate + intermediates) on the server.")
	default:
		rep.Add(section, "Trusted", report.Fail, "no: "+verr.Error())
	}

	// Name match.
	if err := leaf.VerifyHostname(o.Host); err != nil {
		rep.Add(section, "Hostname", report.Fail, "does not match "+o.Host, "Certificate names: "+strings.Join(names(leaf), ", "), "Issue a certificate that includes "+o.Host+".")
	} else {
		rep.Add(section, "Hostname", report.OK, "matches "+o.Host)
	}

	// Expiry.
	days := int(leaf.NotAfter.Sub(now).Hours() / 24)
	exp := leaf.NotAfter.UTC().Format("2006-01-02 15:04 UTC")
	switch {
	case now.After(leaf.NotAfter):
		rep.Add(section, "Expires", report.Fail, fmt.Sprintf("%s (expired %d days ago)", exp, -days), "", "Renew the certificate now.")
	case now.Before(leaf.NotBefore):
		rep.Add(section, "Expires", report.Fail, "not valid until "+leaf.NotBefore.UTC().Format("2006-01-02 15:04 UTC"))
	case days < o.WarnDays:
		rep.Add(section, "Expires", report.Warn, fmt.Sprintf("%s (%d days left)", exp, days), "", "Renew soon; check that automatic renewal (AutoSSL, certbot, acme.sh) is working.")
	default:
		rep.Add(section, "Expires", report.OK, fmt.Sprintf("%s (%d days left)", exp, days))
	}

	rep.Add(section, "Issuer", report.Info, issuer(leaf))
	rep.Add(section, "Key", report.Info, keyDesc(leaf)+" · "+leaf.SignatureAlgorithm.String())
	proto := tls.VersionName(cs.Version)
	st := report.OK
	if cs.Version < tls.VersionTLS12 {
		st = report.Fail
	}
	rep.Add(section, "Protocol", st, proto+" · "+tls.CipherSuiteName(cs.CipherSuite))
	if len(names(leaf)) > 1 {
		n := names(leaf)
		v := strings.Join(n, ", ")
		if len(n) > 6 {
			v = strings.Join(n[:6], ", ") + fmt.Sprintf(" +%d more", len(n)-6)
		}
		rep.Add(section, "Names", report.Info, v)
	}

	if o.Legacy {
		lo := o
		lcfg := &tls.Config{ServerName: o.Host, InsecureSkipVerify: true, MinVersion: tls.VersionTLS10, MaxVersion: tls.VersionTLS11} //nolint:gosec
		if lc, err := dial(lo, lcfg); err == nil {
			v := tls.VersionName(lc.ConnectionState().Version)
			lc.Close()
			rep.Add(section, "Old protocols", report.Warn, "accepts "+v, "TLS 1.0 and 1.1 are deprecated (RFC 8996).", "Disable TLS 1.0 and 1.1 in the server configuration.")
		} else {
			rep.Add(section, "Old protocols", report.OK, "TLS 1.0 and 1.1 refused")
		}
	}
}

func names(c *x509.Certificate) []string {
	n := append([]string{}, c.DNSNames...)
	for _, ip := range c.IPAddresses {
		n = append(n, ip.String())
	}
	if len(n) == 0 && c.Subject.CommonName != "" {
		n = []string{c.Subject.CommonName}
	}
	return n
}

func issuer(c *x509.Certificate) string {
	org := strings.Join(c.Issuer.Organization, ", ")
	if org == "" {
		return c.Issuer.CommonName
	}
	if c.Issuer.CommonName != "" && c.Issuer.CommonName != org {
		return org + " (" + c.Issuer.CommonName + ")"
	}
	return org
}

func keyDesc(c *x509.Certificate) string {
	switch k := c.PublicKey.(type) {
	case *rsa.PublicKey:
		return fmt.Sprintf("RSA %d-bit", k.N.BitLen())
	case *ecdsa.PublicKey:
		return fmt.Sprintf("ECDSA %d-bit", k.Curve.Params().BitSize)
	case ed25519.PublicKey:
		return "Ed25519"
	}
	return c.PublicKeyAlgorithm.String()
}
