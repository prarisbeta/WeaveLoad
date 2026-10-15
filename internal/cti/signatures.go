// Package cti holds the gateway's built-in threat intelligence: a curated set
// of attack signatures matched against HTTP request targets, each mapped to a
// threat name, severity, MITRE ATT&CK technique and a recommended response.
// It is pure and offline — it never makes a network call and never blocks
// anything; callers (internal/security) turn matches into detections.
package cti

import (
	"net/url"
	"regexp"
	"sort"
	"strings"
)

// maxTargetLen bounds how much of a request target is inspected, so a
// hostile multi-kilobyte URL cannot make one log line expensive.
const maxTargetLen = 4096

// Match is one signature that fired on a request target.
type Match struct {
	ID       string   // stable key, e.g. "sql_injection"
	Name     string   // human-readable threat name
	Severity string   // "medium", "high" or "critical"
	Action   string   // recommended response, e.g. "BLOCK_IP"
	MITRE    []string // ATT&CK technique IDs
}

type signature struct {
	Match
	re []*regexp.Regexp
}

func compile(patterns ...string) []*regexp.Regexp {
	out := make([]*regexp.Regexp, len(patterns))
	for i, p := range patterns {
		out[i] = regexp.MustCompile(p)
	}
	return out
}

// signatures run against the lower-cased, URL-decoded request target. The
// patterns are deliberately specific: bare keywords such as "xss" or "rfi"
// would flag harmless URLs, and a false positive here feeds the risk score.
var signatures = []signature{
	{Match{"shellshock", "Shellshock Exploit (CVE-2014-6271)", "critical", "IMMEDIATE_BLOCK", []string{"T1190"}},
		compile(`\(\s*\)\s*\{\s*[^}]*\}\s*;`)},
	{Match{"log4shell", "Log4Shell JNDI Injection (CVE-2021-44228)", "critical", "IMMEDIATE_BLOCK", []string{"T1190"}},
		compile(`\$\{\s*(jndi|lower|upper|env|sys)\s*:`)},
	{Match{"reverse_shell", "Reverse Shell Attempt", "critical", "IMMEDIATE_BLOCK", []string{"T1059.004"}},
		compile(`/dev/tcp/`, `\bbash\s+-i\b`, `\bmkfifo\b`, `\bnc(at)?\b[^&]*\s-e\b`)},
	{Match{"command_injection", "Command Injection", "critical", "IMMEDIATE_BLOCK", []string{"T1059"}},
		compile(
			`(;|\||&&|\$\(|`+"`"+`)\s*(cat|ls|id|whoami|uname|wget|curl|nc|bash|sh|python[0-9.]*|perl|powershell)(\s|$|;|\||&|\))`,
			`/bin/(ba|z|da)?sh\b`, `cmd(\.exe)?\s*/c\b`, `\b(eval|system|passthru|shell_exec|base64_decode)\s*\(`)},
	{Match{"sql_injection", "SQL Injection Attempt", "high", "BLOCK_IP", []string{"T1190"}},
		compile(
			`union(\s|/\*.*?\*/)+(all\s+)?select\b`,
			`\b(or|and)\s+['"]?\d+['"]?\s*=\s*['"]?\d+`,
			`['"]\s*(or|and)\s+['"]`,
			`\b(sleep|benchmark|pg_sleep|waitfor\s+delay)\b\s*[\(']`,
			`information_schema`, `;\s*(drop|alter|truncate)\s+table\b`)},
	{Match{"path_traversal", "Path Traversal / LFI", "high", "BLOCK_IP", []string{"T1190", "T1083"}},
		compile(`\.\./`, `\.\.\\`, `/etc/(passwd|shadow)`, `/proc/self/`, `\b(boot|win)\.ini\b`)},
	{Match{"rfi", "Remote File Inclusion", "high", "BLOCK_IP", []string{"T1190"}},
		compile(`[?&](file|page|include|inc|path|template|doc|document|folder|root|dir|load|read|view)=(https?|ftp)://`, `\b(php|expect|data)://`)},
	{Match{"xss", "Cross-Site Scripting", "medium", "BLOCK_IP", []string{"T1059.007"}},
		compile(`<\s*script`, `javascript\s*:`, `\bon(error|load|mouseover|focus)\s*=`, `<\s*(svg|img|iframe)[^>]*\son\w+\s*=`)},
}

// decode returns the lower-cased target after up to two rounds of URL
// decoding, which unwraps the usual double-encoding evasion ("%252e%252e%252f").
func decode(target string) string {
	if len(target) > maxTargetLen {
		target = target[:maxTargetLen]
	}
	for i := 0; i < 2; i++ {
		d, err := url.QueryUnescape(target)
		if err != nil || d == target {
			break
		}
		target = d
	}
	return strings.ToLower(target)
}

// Detect returns every distinct signature the request target matches, most
// severe first. An empty or benign target returns nil.
func Detect(target string) []Match {
	if target == "" {
		return nil
	}
	t := decode(target)
	var out []Match
	for _, s := range signatures {
		for _, re := range s.re {
			if re.MatchString(t) {
				out = append(out, s.Match)
				break
			}
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return Rank(out[i].Severity) > Rank(out[j].Severity) })
	return out
}

// Rank orders severities: medium < high < critical.
func Rank(severity string) int {
	switch severity {
	case "critical":
		return 3
	case "high":
		return 2
	case "medium":
		return 1
	}
	return 0
}

// Lookup returns the signature with the given ID.
func Lookup(id string) (Match, bool) {
	for _, s := range signatures {
		if s.ID == id {
			return s.Match, true
		}
	}
	return Match{}, false
}
