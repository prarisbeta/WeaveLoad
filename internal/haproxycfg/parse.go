// Package haproxycfg reads the structure of haproxy.cfg — pools (backend and
// listen sections) and their member servers — and makes small, targeted,
// line-preserving edits to it (add or remove one server line). It never
// reformats the file: every line it doesn't touch comes back byte-for-byte,
// comments included, so a diff of any edit is exactly one line.
package haproxycfg

import (
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// sectionKeywords start a new top-level section in haproxy.cfg.
var sectionKeywords = map[string]bool{
	"global": true, "defaults": true, "frontend": true, "backend": true, "listen": true,
	"userlist": true, "peers": true, "resolvers": true, "mailers": true, "program": true,
	"http-errors": true, "ring": true, "cache": true, "log-forward": true, "fcgi-app": true,
	"crt-store": true, "traces": true,
}

// Member is one "server" line inside a pool.
type Member struct {
	Name     string
	Address  string   // as written, e.g. "192.168.200.108:443"
	Host     string   // address without port
	Port     string   // empty when the line has no explicit port
	Params   []string // every token after the address, comments stripped
	Weight   string
	Maxconn  string
	Backup   bool
	Disabled bool
	Indent   string // leading whitespace, reused for new lines
	Line     int    // 0-based line index in the file
	Raw      string // trimmed line text, as it appears in the file
}

// Pool is one backend or listen section — what F5 calls a pool.
type Pool struct {
	Name        string
	Kind        string // "backend" or "listen"
	Balance     string // "roundrobin" when not set explicitly
	HealthCheck string // the "http-check send ..." arguments, if any
	Cookie      bool   // true when the section has a "cookie" directive
	Members     []Member

	headerLine   int // line index of the "backend <name>" line
	lastBodyLine int // last non-blank, non-comment line of the section
}

// Config is the parsed structure of one haproxy.cfg.
type Config struct {
	Pools []Pool
}

// Pool looks up one pool by name.
func (c Config) Pool(name string) (Pool, bool) {
	for _, p := range c.Pools {
		if p.Name == name {
			return p, true
		}
	}
	return Pool{}, false
}

// Parse extracts every pool and its members from content. It is lenient:
// anything it doesn't understand is skipped, never an error, because
// "haproxy -c" — not this parser — is the authority on validity.
func Parse(content string) Config {
	var cfg Config
	var cur *Pool

	closePool := func() {
		if cur != nil {
			cfg.Pools = append(cfg.Pools, *cur)
			cur = nil
		}
	}

	for i, raw := range strings.Split(content, "\n") {
		text := strings.TrimRight(raw, "\r")
		tokens := tokenize(text)
		if len(tokens) == 0 {
			continue
		}

		if sectionKeywords[tokens[0]] {
			closePool()
			if (tokens[0] == "backend" || tokens[0] == "listen") && len(tokens) > 1 {
				cur = &Pool{Name: tokens[1], Kind: tokens[0], Balance: "roundrobin", headerLine: i, lastBodyLine: i}
			}
			continue
		}
		if cur == nil {
			continue
		}
		cur.lastBodyLine = i

		switch tokens[0] {
		case "server":
			if m, ok := parseMember(text, tokens, i); ok {
				cur.Members = append(cur.Members, m)
			}
		case "balance":
			if len(tokens) > 1 {
				cur.Balance = strings.Join(tokens[1:], " ")
			}
		case "cookie":
			cur.Cookie = true
		case "http-check":
			if len(tokens) > 1 && tokens[1] == "send" {
				cur.HealthCheck = strings.Join(tokens[2:], " ")
			}
		}
	}
	closePool()
	return cfg
}

func parseMember(text string, tokens []string, line int) (Member, bool) {
	if len(tokens) < 3 {
		return Member{}, false
	}
	host, port := splitAddress(tokens[2])
	m := Member{
		Name:    tokens[1],
		Address: tokens[2],
		Host:    host,
		Port:    port,
		Params:  append([]string(nil), tokens[3:]...),
		Indent:  text[:len(text)-len(strings.TrimLeft(text, " \t"))],
		Line:    line,
		Raw:     strings.Join(tokens, " "),
	}
	for j := 0; j < len(m.Params); j++ {
		switch m.Params[j] {
		case "backup":
			m.Backup = true
		case "disabled":
			m.Disabled = true
		case "weight":
			if j+1 < len(m.Params) {
				m.Weight = m.Params[j+1]
			}
		case "maxconn":
			if j+1 < len(m.Params) {
				m.Maxconn = m.Params[j+1]
			}
		}
	}
	return m, true
}

// tokenize splits one config line into words the way HAProxy reads them
// closely enough for structure: whitespace separates words, except inside
// quotes or parentheses (e.g. "str(a b)"), and an unquoted '#' starts a
// comment that runs to the end of the line.
func tokenize(line string) []string {
	var tokens []string
	var cur strings.Builder
	var quote rune
	depth := 0
	flush := func() {
		if cur.Len() > 0 {
			tokens = append(tokens, cur.String())
			cur.Reset()
		}
	}
	for _, r := range line {
		switch {
		case quote != 0:
			cur.WriteRune(r)
			if r == quote {
				quote = 0
			}
		case r == '"' || r == '\'':
			quote = r
			cur.WriteRune(r)
		case r == '(':
			depth++
			cur.WriteRune(r)
		case r == ')':
			if depth > 0 {
				depth--
			}
			cur.WriteRune(r)
		case r == '#' && depth == 0 && cur.Len() == 0:
			flush()
			return tokens
		case (r == ' ' || r == '\t') && depth == 0:
			flush()
		default:
			cur.WriteRune(r)
		}
	}
	flush()
	return tokens
}

// splitAddress separates "host:port" into its parts. A bare IPv6 address
// (more than one colon, no brackets) is treated as having no port.
func splitAddress(addr string) (host, port string) {
	if strings.HasPrefix(addr, "[") {
		if end := strings.Index(addr, "]"); end > 0 {
			host = addr[1:end]
			return host, strings.TrimPrefix(addr[end+1:], ":")
		}
	}
	if strings.Count(addr, ":") != 1 {
		return addr, ""
	}
	i := strings.LastIndex(addr, ":")
	return addr[:i], addr[i+1:]
}

// NodeUse is one place a node is used: a member of some pool.
type NodeUse struct {
	Pool   string
	Server string
	Port   string
	Backup bool
}

// Node is one backend host (IP or hostname) — what F5 calls a node — with
// every pool membership that points at it.
type Node struct {
	Host string
	Uses []NodeUse
}

// Nodes groups every member across all pools by host, sorted by host.
func (c Config) Nodes() []Node {
	idx := map[string]int{}
	var nodes []Node
	for _, p := range c.Pools {
		for _, m := range p.Members {
			i, ok := idx[m.Host]
			if !ok {
				i = len(nodes)
				idx[m.Host] = i
				nodes = append(nodes, Node{Host: m.Host})
			}
			nodes[i].Uses = append(nodes[i].Uses, NodeUse{Pool: p.Name, Server: m.Name, Port: m.Port, Backup: m.Backup})
		}
	}
	sort.Slice(nodes, func(i, j int) bool { return nodes[i].Host < nodes[j].Host })
	return nodes
}

var trailingNumberRE = regexp.MustCompile(`^(.*?)(\d+)$`)

// SuggestName proposes the next member name following the pool's existing
// pattern: node01,node02 -> node03; node1 -> node2; web -> web2.
func (p Pool) SuggestName() string {
	if len(p.Members) == 0 {
		return "node01"
	}
	prefix, width, max := "", 0, 0
	for _, m := range p.Members {
		sm := trailingNumberRE.FindStringSubmatch(m.Name)
		if sm == nil {
			continue
		}
		n, _ := strconv.Atoi(sm[2])
		if n >= max {
			prefix, width, max = sm[1], len(sm[2]), n
		}
	}
	if width == 0 {
		return p.Members[0].Name + "2"
	}
	name := prefix + padNumber(max+1, width)
	for p.hasMember(name) {
		max++
		name = prefix + padNumber(max+1, width)
	}
	return name
}

func padNumber(n, width int) string {
	s := strconv.Itoa(n)
	for len(s) < width {
		s = "0" + s
	}
	return s
}

func (p Pool) hasMember(name string) bool {
	for _, m := range p.Members {
		if m.Name == name {
			return true
		}
	}
	return false
}

// FirstPort returns the port of the pool's first member that has one, so
// the "add member" form can default to it.
func (p Pool) FirstPort() string {
	for _, m := range p.Members {
		if m.Port != "" {
			return m.Port
		}
	}
	return ""
}
