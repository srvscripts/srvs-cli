// Package dnsbl checks IP addresses and domains against DNS blacklists, with the same lists as the
// srvscripts.com blacklist tool.
package dnsbl

import (
	"fmt"
	"net"
	"regexp"
	"sort"
	"strings"
	"sync"

	"github.com/miekg/dns"
	"github.com/srvscripts/srvs-cli/internal/report"
	"github.com/srvscripts/srvs-cli/internal/resolver"
)

// List is one blacklist.
type List struct {
	Name   string
	Zone   string
	Info   string
	Weight int            // 3 = blocks at major mailbox providers, 2 = widely used, 1 = informational
	Match  *regexp.Regexp // listed only when the answer matches (nil = any 127.0.0.0/8 answer)
	IPv6   bool           // the list answers IPv6 queries
	Test   string         // test entry the list must report as listed (RFC 5782); "" = 127.0.0.2 for IP lists
}

// IPLists are the IP blacklists (kept in step with srvs_dnsbl_lists() on srvscripts.com).
var IPLists = []List{
	{"Spamhaus ZEN", "zen.spamhaus.org", "https://check.spamhaus.org/", 3, nil, true, ""},
	{"Spamcop", "bl.spamcop.net", "https://www.spamcop.net/bl.shtml", 3, nil, false, ""},
	{"Barracuda", "b.barracudacentral.org", "https://www.barracudacentral.org/rbl/removal-request", 3, nil, false, ""},
	{"UCEPROTECT L1", "dnsbl-1.uceprotect.net", "https://www.uceprotect.net/en/rblcheck.php", 2, nil, false, ""},
	{"UCEPROTECT L2", "dnsbl-2.uceprotect.net", "https://www.uceprotect.net/en/rblcheck.php", 1, nil, false, ""},
	{"UCEPROTECT L3", "dnsbl-3.uceprotect.net", "https://www.uceprotect.net/en/rblcheck.php", 1, nil, false, ""},
	{"PSBL", "psbl.surriel.com", "https://psbl.org/remove", 2, nil, false, ""},
	{"DroneBL", "dnsbl.dronebl.org", "https://dronebl.org/lookup", 2, nil, true, ""},
	{"Mailspike BL", "bl.mailspike.net", "https://mailspike.org/iplookup.html", 2, nil, false, ""},
	{"Mailspike Z", "z.mailspike.net", "https://mailspike.org/iplookup.html", 1, nil, false, ""},
	{"Hostkarma (black)", "hostkarma.junkemailfilter.com", "https://wiki.junkemailfilter.com/index.php/Spam_DNS_Lists", 2, regexp.MustCompile(`^127\.0\.0\.2$`), false, ""},
	{"InterServer RBL", "rbl.interserver.net", "https://rbl.interserver.net/", 2, nil, false, ""},
	{"Blocklist.de", "bl.blocklist.de", "https://www.blocklist.de/en/delist.html", 2, nil, false, ""},
	{"SpamEatingMonkey", "bl.spameatingmonkey.net", "https://spameatingmonkey.com/lookup", 2, nil, false, ""},
	{"0spam", "bl.0spam.org", "https://0spam.org/", 1, nil, false, ""},
	{"SPFBL", "dnsbl.spfbl.net", "https://spfbl.net/en/delist/", 1, nil, true, ""},
	{"Scientific Spam", "bl.scientificspam.net", "https://www.scientificspam.net/", 1, nil, false, ""},
	{"Swinog", "dnsrbl.swinog.ch", "https://antispam.imp.ch/", 1, nil, false, ""},
	{"Suomispam", "bl.suomispam.net", "https://suomispam.net/", 1, nil, false, ""},
	{"ZapBL", "dnsbl.zapbl.net", "https://zapbl.net/", 1, nil, false, ""},
	{"Nordspam", "bl.nordspam.com", "https://www.nordspam.com/delist/", 1, nil, false, ""},
	{"S5H", "all.s5h.net", "https://www.usenix.org.uk/content/rbl.html", 1, nil, false, ""},
	{"JustSpam", "dnsbl.justspam.org", "http://www.justspam.org/", 1, nil, false, ""},
	{"NoSolicitado", "bl.nosolicitado.org", "https://www.nosolicitado.org/", 1, nil, false, ""},
	{"Truncate (GBUdb)", "truncate.gbudb.net", "https://www.gbudb.com/truncate/", 1, nil, false, ""},
	{"Anonmails", "spam.dnsbl.anonmails.de", "https://anonmails.de/dnsbl.php", 1, nil, false, ""},
	{"SpamSources (fabel)", "spamsources.fabel.dk", "https://www.fabel.dk/", 1, nil, false, ""},
	{"Backscatterer", "ips.backscatterer.org", "https://www.backscatterer.org/", 1, nil, false, ""},
	{"SEM Backscatter", "backscatter.spameatingmonkey.net", "https://spameatingmonkey.com/lookup", 1, nil, false, ""},
}

// DomainLists are domain (URI) blacklists.
var DomainLists = []List{
	{"Spamhaus DBL", "dbl.spamhaus.org", "https://check.spamhaus.org/", 3, regexp.MustCompile(`^127\.0\.1\.\d+$`), false, "dbltest.com"},
	{"SURBL", "multi.surbl.org", "https://surbl.org/surbl-analysis", 2, nil, false, "test.surbl.org"},
	{"URIBL", "multi.uribl.com", "https://admin.uribl.com/", 2, regexp.MustCompile(`^127\.0\.0\.(2|4|8|14)$`), false, "test.uribl.com"},
}

// Result for one list.
type Result struct {
	List    List
	Listed  bool
	Unknown string // why it could not be checked
	Answer  string
	Reason  string // TXT explanation, if the list gives one
}

// Spamhaus and some others answer 127.255.255.x or (URIBL) 127.0.0.1 when they refuse the query.
func refused(l List, ans string) string {
	switch {
	case strings.HasPrefix(ans, "127.255.255."):
		return "query refused by the list (public or unregistered resolver, or rate limit)"
	case l.Zone == "multi.uribl.com" && ans == "127.0.0.1":
		return "query refused by URIBL (public resolver)"
	}
	return ""
}

// Spamhaus key for the free Data Query Service: zones become <key>.zen.dq.spamhaus.net.
func withKey(l List, key string) List {
	if key == "" {
		return l
	}
	switch l.Zone {
	case "zen.spamhaus.org":
		l.Zone = key + ".zen.dq.spamhaus.net"
	case "dbl.spamhaus.org":
		l.Zone = key + ".dbl.dq.spamhaus.net"
	}
	return l
}

// Reverse returns the DNSBL query label for an IP (4.3.2.1 for 1.2.3.4, nibbles for IPv6).
func Reverse(ip net.IP) string {
	if v4 := ip.To4(); v4 != nil {
		return fmt.Sprintf("%d.%d.%d.%d", v4[3], v4[2], v4[1], v4[0])
	}
	a, _ := dns.ReverseAddr(ip.String())
	return strings.TrimSuffix(strings.TrimSuffix(a, "ip6.arpa."), ".")
}

// canary caches, per zone, whether the list answered its own test entry through this resolver.
var canary sync.Map // zone -> string ("" = test entry listed, else the reason results cannot be trusted)

func testLabel(l List) string {
	if l.Test != "" {
		return l.Test
	}
	return "2.0.0.127"
}

// selfTest queries the list's test entry. Some resolvers (Google Public DNS for Spamhaus) silently answer NXDOMAIN
// for every blacklist query, which would make every address look clean; a list that does not report its own test
// entry as listed is therefore marked "not checked" instead of "not listed".
func selfTest(r *resolver.Resolver, l, lk List) string {
	if v, ok := canary.Load(lk.Zone); ok {
		return v.(string)
	}
	why := ""
	a, err := r.Query(testLabel(l)+"."+lk.Zone, dns.TypeA)
	switch {
	case err != nil:
		why = "no answer (" + err.Error() + ")"
	case a.Rcode != dns.RcodeSuccess:
		why = "the list did not report its own test entry through your resolver (" + a.Server + "), so a clean result cannot be trusted; it probably blocks this resolver"
	default:
		got := false
		for _, rr := range a.RRs {
			if v, ok := rr.(*dns.A); ok {
				if w := refused(l, v.A.String()); w != "" {
					why = w
				}
				got = true
			}
		}
		if !got && why == "" {
			why = "the list did not report its own test entry through your resolver, so a clean result cannot be trusted"
		}
	}
	canary.Store(lk.Zone, why)
	return why
}

// Lookup checks one query name against the lists in parallel.
func lookup(r *resolver.Resolver, label string, lists []List, key string) []Result {
	out := make([]Result, len(lists))
	var wg sync.WaitGroup
	sem := make(chan struct{}, 12)
	for i, l := range lists {
		wg.Add(1)
		go func(i int, l List) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			lk := withKey(l, key)
			res := Result{List: l}
			a, err := r.Query(label+"."+lk.Zone, dns.TypeA)
			if err != nil {
				res.Unknown = "no answer (" + err.Error() + ")"
				out[i] = res
				return
			}
			if a.Rcode == dns.RcodeNameError {
				if why := selfTest(r, l, lk); why != "" {
					res.Unknown = why
				}
				out[i] = res
				return
			}
			if a.Rcode != dns.RcodeSuccess {
				res.Unknown = "list answered " + a.RcodeName()
				out[i] = res
				return
			}
			for _, rr := range a.RRs {
				if v, ok := rr.(*dns.A); ok {
					ans := v.A.String()
					res.Answer = ans
					if why := refused(l, ans); why != "" {
						res.Unknown = why
						break
					}
					if !strings.HasPrefix(ans, "127.") {
						res.Unknown = "unexpected answer " + ans + " (the list may be shut down or wildcarding)"
						break
					}
					if l.Match == nil || l.Match.MatchString(ans) {
						res.Listed = true
						break
					}
				}
			}
			if res.Listed {
				if txts, _, err := r.TXT(label + "." + lk.Zone); err == nil && len(txts) > 0 {
					res.Reason = txts[0]
				}
			} else if res.Unknown == "" {
				if why := selfTest(r, l, lk); why != "" {
					res.Unknown = why
				}
			}
			out[i] = res
		}(i, l)
	}
	wg.Wait()
	return out
}

// CheckIP checks one IP and adds the results to rep. verbose adds a line for every clean list.
func CheckIP(r *resolver.Resolver, rep *report.Report, section string, ip net.IP, key string, verbose bool) {
	lists := IPLists
	if ip.To4() == nil {
		lists = nil
		for _, l := range IPLists {
			if l.IPv6 {
				lists = append(lists, l)
			}
		}
	}
	addResults(rep, section, ip.String(), lookup(r, Reverse(ip), lists, key), verbose)
	if ip.To4() == nil {
		rep.Add(section, ip.String(), report.Info, "most blacklists only list IPv4; checked the "+fmt.Sprint(len(lists))+" that support IPv6")
	}
}

// CheckDomain checks a domain name against the domain lists.
func CheckDomain(r *resolver.Resolver, rep *report.Report, section, domain, key string, verbose bool) {
	addResults(rep, section, domain, lookup(r, domain, DomainLists, key), verbose)
}

func addResults(rep *report.Report, section, target string, res []Result, verbose bool) {
	sort.SliceStable(res, func(i, j int) bool { return res[i].List.Weight > res[j].List.Weight })
	clean, unknown := 0, 0
	for _, x := range res {
		switch {
		case x.Listed:
			st := report.Warn
			if x.List.Weight >= 2 {
				st = report.Fail
			}
			det := "Answer " + x.Answer
			if x.Reason != "" {
				det += ": " + x.Reason
			}
			fix := "Fix the cause first (open relay, compromised account, bad list), then request removal: " + x.List.Info
			if strings.HasPrefix(x.List.Zone, "dnsbl-2.") || strings.HasPrefix(x.List.Zone, "dnsbl-3.") {
				fix = "This lists your provider's whole network, not this IP. Major mailbox providers do not use it; ask your host only if mail is actually rejected."
			}
			rep.Add(section, target+" · "+x.List.Name, st, "LISTED", det, fix)
		case x.Unknown != "":
			unknown++
			// The same list is usually unreachable for every address (blocked resolver): say it once per report.
			name := x.List.Name
			dup := false
			for _, c := range rep.Checks {
				if c.Name == name && c.Status == report.Unknown {
					dup = true
				}
			}
			if !dup {
				rep.Add(section, name, report.Unknown, "not checked", x.Unknown)
			}
		default:
			clean++
			if verbose {
				rep.Add(section, target+" · "+x.List.Name, report.OK, "not listed")
			}
		}
	}
	if !verbose {
		rep.Add(section, target, report.OK, fmt.Sprintf("not listed on %d of %d lists", clean, len(res)))
	}
}
