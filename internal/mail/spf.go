// Package mail checks a domain's mail records: MX, SPF, DMARC, DKIM, MTA-STS, TLS-RPT and BIMI.
package mail

import (
	"fmt"
	"strings"
)

// TXTLookup is what the SPF walker needs from a resolver (an interface so tests can use fixed answers).
type TXTLookup interface {
	TXT(name string) ([]string, error)
}

// SPFResult is the outcome of evaluating a domain's SPF policy tree.
type SPFResult struct {
	Record   string   // the domain's own SPF record
	Count    int      // number of SPF records at the domain (more than one is a PermError)
	Lookups  int      // DNS-querying terms counted under RFC 7208 §4.6.4 (limit 10)
	Voids    int      // lookups that returned no record (limit 2)
	All      string   // qualifier of the final "all" ("-", "~", "?", "+") or "" when missing
	Redirect string   // redirect= target, if any
	Problems []string // PermErrors and other faults
	Tree     []string // include/redirect chain, indented, for --verbose
}

// SPFLookupLimit and SPFVoidLimit are the RFC 7208 limits.
const (
	SPFLookupLimit = 10
	SPFVoidLimit   = 2
)

// IsSPF reports whether a TXT string is an SPF record.
func IsSPF(t string) bool {
	t = strings.ToLower(strings.TrimSpace(t))
	return t == "v=spf1" || strings.HasPrefix(t, "v=spf1 ")
}

// EvaluateSPF fetches and walks the SPF record of domain, counting DNS lookups across includes and redirects.
func EvaluateSPF(r TXTLookup, domain string) (*SPFResult, error) {
	res := &SPFResult{}
	recs, err := spfRecords(r, domain)
	if err != nil {
		return nil, err
	}
	res.Count = len(recs)
	if len(recs) == 0 {
		return res, nil
	}
	res.Record = recs[0]
	if len(recs) > 1 {
		res.Problems = append(res.Problems, fmt.Sprintf("%d SPF records published; receivers treat this as a PermError", len(recs)))
	}
	seen := map[string]bool{strings.ToLower(domain): true}
	walk(r, domain, recs[0], 0, res, seen, true)
	if res.Lookups > SPFLookupLimit {
		res.Problems = append(res.Problems, fmt.Sprintf("%d DNS lookups, over the limit of %d (PermError)", res.Lookups, SPFLookupLimit))
	}
	if res.Voids > SPFVoidLimit {
		res.Problems = append(res.Problems, fmt.Sprintf("%d void lookups, over the limit of %d (PermError)", res.Voids, SPFVoidLimit))
	}
	return res, nil
}

func spfRecords(r TXTLookup, domain string) ([]string, error) {
	txts, err := r.TXT(domain)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, t := range txts {
		if IsSPF(t) {
			out = append(out, strings.TrimSpace(t))
		}
	}
	return out, nil
}

func walk(r TXTLookup, domain, rec string, depth int, res *SPFResult, seen map[string]bool, top bool) {
	if depth > 10 {
		res.Problems = append(res.Problems, "include chain deeper than 10 levels")
		return
	}
	terms := strings.Fields(rec)[1:]
	var redirect string
	hasAll := false
	for _, raw := range terms {
		t := strings.ToLower(raw)
		q := ""
		if strings.ContainsAny(t[:1], "+-~?") {
			q, t = t[:1], t[1:]
		}
		name, arg, _ := strings.Cut(t, ":")
		if strings.HasPrefix(t, "redirect=") {
			redirect = strings.TrimPrefix(t, "redirect=")
			continue
		}
		switch {
		case name == "all":
			hasAll = true
			if top {
				if q == "" {
					q = "+"
				}
				res.All = q
			}
		case name == "include":
			res.Lookups++
			res.Tree = append(res.Tree, strings.Repeat("  ", depth)+"include:"+arg)
			if seen[arg] { // arg is one of its own ancestors: a real loop
				res.Problems = append(res.Problems, "include loop at "+arg)
				continue
			}
			recs, err := spfRecords(r, arg)
			if err != nil {
				res.Problems = append(res.Problems, "include:"+arg+" could not be looked up ("+err.Error()+")")
				continue
			}
			if len(recs) == 0 {
				res.Voids++
				res.Problems = append(res.Problems, "include:"+arg+" has no SPF record (PermError)")
				continue
			}
			seen[arg] = true
			walk(r, arg, recs[0], depth+1, res, seen, false)
			delete(seen, arg)
		case name == "a" || strings.HasPrefix(name, "a/"), name == "mx" || strings.HasPrefix(name, "mx/"), name == "ptr", name == "exists":
			res.Lookups++
			if name == "ptr" {
				res.Problems = append(res.Problems, "uses the ptr mechanism, which RFC 7208 says not to use")
			}
		}
	}
	// RFC 7208 §6.1: redirect= is ignored when the record has an "all" mechanism.
	if redirect != "" && hasAll {
		res.Problems = append(res.Problems, "redirect="+redirect+" is ignored because the record also has an all mechanism")
		redirect = ""
	}
	if redirect != "" {
		res.Lookups++
		if top {
			res.Redirect = redirect
		}
		res.Tree = append(res.Tree, strings.Repeat("  ", depth)+"redirect="+redirect)
		if seen[redirect] {
			res.Problems = append(res.Problems, "redirect loop at "+redirect)
			return
		}
		recs, err := spfRecords(r, redirect)
		if err != nil || len(recs) == 0 {
			res.Voids++
			res.Problems = append(res.Problems, "redirect="+redirect+" has no SPF record (PermError)")
			return
		}
		before := res.All
		seen[redirect] = true
		walk(r, redirect, recs[0], depth+1, res, seen, top)
		delete(seen, redirect)
		if top && res.All == "" {
			res.All = before
		}
	}
}
