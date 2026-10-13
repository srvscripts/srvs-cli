// Package report holds check results and renders them as text or JSON.
package report

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"unicode/utf8"
)

// Status of a single check.
type Status string

const (
	OK      Status = "ok"      // passed
	Info    Status = "info"    // informational, never affects the exit code
	Warn    Status = "warn"    // works, but should be fixed
	Fail    Status = "fail"    // broken or missing
	Unknown Status = "unknown" // could not be checked (timeout, refused, network)
)

// Check is one line of a report.
type Check struct {
	Section string `json:"section,omitempty"`
	Name    string `json:"name"`
	Status  Status `json:"status"`
	Value   string `json:"value"`
	Detail  string `json:"detail,omitempty"`
	Fix     string `json:"fix,omitempty"`
}

// Report is the result of one command for one target.
type Report struct {
	Command string   `json:"command"`
	Target  string   `json:"target"`
	Checks  []Check  `json:"checks"`
	Notes   []string `json:"notes,omitempty"`
	Listing bool     `json:"-"` // a plain listing (dns): no pass/fail summary line
}

// New starts an empty report.
func New(command, target string) *Report { return &Report{Command: command, Target: target} }

// Add appends a check.
func (r *Report) Add(section, name string, st Status, value string, detail ...string) *Check {
	c := Check{Section: section, Name: name, Status: st, Value: value}
	if len(detail) > 0 {
		c.Detail = detail[0]
	}
	if len(detail) > 1 {
		c.Fix = detail[1]
	}
	r.Checks = append(r.Checks, c)
	return &r.Checks[len(r.Checks)-1]
}

// Note adds a free-text note printed under the checks.
func (r *Report) Note(s string) { r.Notes = append(r.Notes, s) }

// Counts returns how many checks have each status.
func (r *Report) Counts() map[Status]int {
	m := map[Status]int{}
	for _, c := range r.Checks {
		m[c.Status]++
	}
	return m
}

// ExitCode follows the srvScripts convention used by the other scripts:
// 0 = everything checked passed, 1 = at least one warning or failure, 2 = something could not be checked
// and nothing failed. A failure always wins over "unknown", so a monitor never misses a real problem.
func ExitCode(reports ...*Report) int {
	problem, unknown := false, false
	for _, r := range reports {
		for _, c := range r.Checks {
			switch c.Status {
			case Warn, Fail:
				problem = true
			case Unknown:
				unknown = true
			}
		}
	}
	if problem {
		return 1
	}
	if unknown {
		return 2
	}
	return 0
}

// ExitCodeIgnoringWarnings is the exit code for --ignore-warnings: a failure is 1, anything that could not be
// checked is 2 (even when warnings are also present, so exit-only monitoring never mistakes it for success),
// otherwise 0. Warnings alone give 0.
func ExitCodeIgnoringWarnings(reports ...*Report) int {
	unknown := false
	for _, r := range reports {
		for _, c := range r.Checks {
			switch c.Status {
			case Fail:
				return 1
			case Unknown:
				unknown = true
			}
		}
	}
	if unknown {
		return 2
	}
	return 0
}

// Exit is the one exit code for a run: the process exit and the "exit" field of the JSON output both use it.
func Exit(ignoreWarnings bool, reports ...*Report) int {
	if ignoreWarnings {
		return ExitCodeIgnoringWarnings(reports...)
	}
	return ExitCode(reports...)
}

// Style controls the text output.
type Style struct {
	Color   bool // ANSI colours
	Unicode bool // ✓ ! ✗ symbols instead of [OK] tags
	Quiet   bool // only print warnings, failures and unknowns
}

func (s Style) mark(st Status) string {
	sym := map[Status][2]string{
		OK:      {"✓", "[ OK ]"},
		Info:    {"•", "[INFO]"},
		Warn:    {"!", "[WARN]"},
		Fail:    {"✗", "[FAIL]"},
		Unknown: {"?", "[ ?? ]"},
	}[st]
	m := sym[1]
	if s.Unicode {
		m = sym[0]
	}
	if !s.Color {
		return m
	}
	col := map[Status]string{OK: "32", Info: "90", Warn: "33", Fail: "31", Unknown: "35"}[st]
	return "\x1b[" + col + "m" + m + "\x1b[0m"
}

func (s Style) bold(t string) string {
	if !s.Color {
		return t
	}
	return "\x1b[1m" + t + "\x1b[0m"
}

func (s Style) dim(t string) string {
	if !s.Color {
		return t
	}
	return "\x1b[90m" + t + "\x1b[0m"
}

// Text writes a human-readable report.
func (r *Report) Text(w io.Writer, s Style) {
	fmt.Fprintf(w, "%s %s\n", s.bold(r.Command+":"), s.bold(r.Target))
	width := 0
	for _, c := range r.Checks {
		if len(c.Name) > width {
			width = len(c.Name)
		}
	}
	if width > 26 {
		width = 26
	}
	section := ""
	for _, c := range r.Checks {
		if s.Quiet && (c.Status == OK || c.Status == Info) {
			continue
		}
		if c.Section != "" && c.Section != section {
			section = c.Section
			fmt.Fprintf(w, "\n  %s\n", s.bold(section))
		}
		fmt.Fprintf(w, "  %s %-*s  %s\n", s.mark(c.Status), width, c.Name, c.Value)
		if c.Detail != "" {
			for _, l := range wrap(c.Detail, 76) {
				fmt.Fprintf(w, "  %*s  %s\n", width+utf8.RuneCountInString(stripANSI(s.mark(c.Status)))+1, "", s.dim(l))
			}
		}
		if c.Fix != "" && (c.Status == Warn || c.Status == Fail) {
			for i, l := range wrap(c.Fix, 74) {
				p := "  "
				if i == 0 {
					p = "→ "
				}
				fmt.Fprintf(w, "  %*s  %s%s\n", width+utf8.RuneCountInString(stripANSI(s.mark(c.Status)))+1, "", p, l)
			}
		}
	}
	cn := r.Counts()
	if r.Listing {
		fmt.Fprintln(w)
	} else {
		fmt.Fprintf(w, "\n  %d passed · %d warning(s) · %d failed · %d not checked\n", cn[OK], cn[Warn], cn[Fail], cn[Unknown])
	}
	for _, n := range r.Notes {
		for _, l := range wrap(n, 78) {
			fmt.Fprintf(w, "  %s\n", s.dim(l))
		}
	}
}

// JSON writes one or more reports as a JSON document. exit is the run's exit code (from Exit), so the "exit"
// field always equals the process exit status.
func JSON(w io.Writer, exit int, reports []*Report) error {
	type out struct {
		Tool    string    `json:"tool"`
		Version string    `json:"version"`
		Exit    int       `json:"exit"`
		Reports []*Report `json:"reports"`
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(out{Tool: "srvs", Version: Version, Exit: exit, Reports: reports})
}

// Version is set at build time (-ldflags "-X github.com/srvscripts/srvs-cli/internal/report.Version=v1.0.0").
var Version = "dev"

func wrap(s string, n int) []string {
	var out []string
	for _, para := range strings.Split(s, "\n") {
		indent := para[:len(para)-len(strings.TrimLeft(para, " "))] // keep tree indentation
		words := strings.Fields(para)
		line := ""
		for _, wd := range words {
			if line != "" && len(line)+1+len(wd) > n {
				out = append(out, line)
				line = wd
				continue
			}
			if line == "" {
				line = indent + wd
			} else {
				line += " " + wd
			}
		}
		if line != "" {
			out = append(out, line)
		}
	}
	return out
}

func stripANSI(s string) string {
	var b strings.Builder
	esc := false
	for _, r := range s {
		if r == '\x1b' {
			esc = true
			continue
		}
		if esc {
			if r == 'm' {
				esc = false
			}
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}
