package haproxycfg

import (
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
)

// MemberSpec is what the "add member" form submits.
type MemberSpec struct {
	Name     string
	Host     string // IPv4 address or hostname
	Port     string
	Weight   string // optional, 0-256
	Maxconn  string // optional, >= 1
	Backup   bool
	Disabled bool
	// CloneFrom names an existing member whose settings (ssl, sni, check,
	// check-sni, inter/rise/fall, check port, ...) the new member copies —
	// the pool's health check and TLS details live on each server line in
	// HAProxy, not on the pool as in F5. Empty means the first member.
	CloneFrom string
}

var (
	nameRE     = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)
	hostnameRE = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$`)
)

// perMemberParams are settings that belong to one specific server and so
// are never copied from the template member: backup/disabled/weight/maxconn/
// cookie/id are per-member by definition, and addr/agent-addr/redir/track
// point at one particular server (e.g. a health-check override address) —
// copying any of these onto a new member would silently misconfigure it or
// point its health check at the wrong host.
var perMemberParams = map[string]int{ // keyword -> number of value tokens
	"backup": 0, "disabled": 0, "enabled": 0,
	"weight": 1, "maxconn": 1, "cookie": 1, "id": 1,
	"addr": 1, "agent-addr": 1, "redir": 1, "track": 1, "guid": 1, "port": 1,
}

// AddMember returns content with one new server line appended to pool,
// right after its last existing server, plus the line itself (unindented)
// for previews and audit logs.
func AddMember(content, pool string, spec MemberSpec) (string, string, error) {
	p, ok := Parse(content).Pool(pool)
	if !ok {
		return "", "", fmt.Errorf("kelompok %q tidak ditemukan di konfigurasi", pool)
	}
	if err := validateSpec(p, spec); err != nil {
		return "", "", err
	}

	template, err := pickTemplate(p, spec.CloneFrom)
	if err != nil {
		return "", "", err
	}
	line := buildLine(p, spec, template)

	indent, after := "        ", p.lastBodyLine
	if n := len(p.Members); n > 0 {
		indent, after = p.Members[n-1].Indent, p.Members[n-1].Line
	}
	return insertLine(content, after, indent+line), line, nil
}

// validateSpec checks a brand-new member: no name in the pool may match it,
// and no member's address may match it.
func validateSpec(p Pool, s MemberSpec) error {
	return validateMemberSpec(p, s, "")
}

// validateMemberSpec is the shared field/uniqueness validation for adding or
// editing a member. exclude is the current name of the member being edited
// (empty for a brand-new one) — its own name and address don't count as
// conflicts against the very row being changed.
func validateMemberSpec(p Pool, s MemberSpec, exclude string) error {
	if !nameRE.MatchString(s.Name) {
		return fmt.Errorf("nama anggota hanya boleh huruf, angka, titik, garis bawah, dan tanda minus (maks. 64)")
	}
	if s.Name != exclude && p.hasMember(s.Name) {
		return fmt.Errorf("nama %q sudah dipakai di kelompok %s", s.Name, p.Name)
	}
	if ip := net.ParseIP(s.Host); ip != nil {
		if ip.To4() == nil {
			return fmt.Errorf("alamat IPv6 belum didukung, gunakan IPv4 atau nama host")
		}
	} else if !hostnameRE.MatchString(s.Host) {
		return fmt.Errorf("alamat node harus IPv4 atau nama host yang valid")
	}
	if err := checkRange("port", s.Port, 1, 65535, true); err != nil {
		return err
	}
	if err := checkRange("bobot", s.Weight, 0, 256, false); err != nil {
		return err
	}
	if err := checkRange("batas koneksi", s.Maxconn, 1, 1000000, false); err != nil {
		return err
	}
	for _, m := range p.Members {
		if m.Name == exclude {
			continue
		}
		if m.Host == s.Host && m.Port == s.Port {
			return fmt.Errorf("%s:%s sudah menjadi anggota (%s)", s.Host, s.Port, m.Name)
		}
	}
	return nil
}

// EditMember replaces the pool's member currently named currentName with a
// new server line built from spec, in place — same line number, same
// indent. Every setting the edit form doesn't expose (ssl, sni, check,
// check-sni, inter/rise/fall, ...) is kept exactly as it was on that
// member's own line, using the member itself as its own template. spec.Name
// may differ from currentName to rename the member.
func EditMember(content, pool, currentName string, spec MemberSpec) (string, string, error) {
	p, ok := Parse(content).Pool(pool)
	if !ok {
		return "", "", fmt.Errorf("kelompok %q tidak ditemukan di konfigurasi", pool)
	}
	var current *Member
	for i := range p.Members {
		if p.Members[i].Name == currentName {
			current = &p.Members[i]
			break
		}
	}
	if current == nil {
		return "", "", fmt.Errorf("anggota %q tidak ada di kelompok %s", currentName, pool)
	}
	if err := validateMemberSpec(p, spec, currentName); err != nil {
		return "", "", err
	}
	line := buildLine(p, spec, current)
	return replaceLine(content, current.Line, current.Indent+line), line, nil
}

// digitsRE requires a plain unsigned decimal number: no leading "+"/"-", no
// leading zeros beyond a bare "0", no whitespace. strconv.Atoi alone accepts
// "+80", which HAProxy parses as a port *offset* ("+80" means "listen port
// plus 80") rather than the literal port 80 the form intended, and "0080"
// would also pass Atoi while still being a distinct, unnormalized string
// that could produce a spurious "different but not really" duplicate-member
// case elsewhere.
var digitsRE = regexp.MustCompile(`^(0|[1-9][0-9]*)$`)

func checkRange(label, v string, min, max int, required bool) error {
	if v == "" {
		if required {
			return fmt.Errorf("%s wajib diisi", label)
		}
		return nil
	}
	if !digitsRE.MatchString(v) {
		return fmt.Errorf("%s harus angka %d-%d", label, min, max)
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < min || n > max {
		return fmt.Errorf("%s harus angka %d-%d", label, min, max)
	}
	return nil
}

func pickTemplate(p Pool, cloneFrom string) (*Member, error) {
	if cloneFrom == "" {
		if len(p.Members) == 0 {
			return nil, nil
		}
		return &p.Members[0], nil
	}
	for i := range p.Members {
		if p.Members[i].Name == cloneFrom {
			return &p.Members[i], nil
		}
	}
	return nil, fmt.Errorf("anggota contoh %q tidak ada di kelompok %s", cloneFrom, p.Name)
}

func buildLine(p Pool, s MemberSpec, template *Member) string {
	parts := []string{"server", s.Name, s.Host + ":" + s.Port}
	if s.Weight != "" {
		parts = append(parts, "weight", s.Weight)
	}
	if s.Maxconn != "" {
		parts = append(parts, "maxconn", s.Maxconn)
	}
	if p.Cookie {
		parts = append(parts, "cookie", s.Name)
	}
	if template == nil {
		parts = append(parts, "check")
	} else {
		parts = append(parts, inheritedParams(template.Params)...)
	}
	if s.Backup {
		parts = append(parts, "backup")
	}
	if s.Disabled {
		parts = append(parts, "disabled")
	}
	return strings.Join(parts, " ")
}

func inheritedParams(params []string) []string {
	var out []string
	for i := 0; i < len(params); i++ {
		if skip, isPerMember := perMemberParams[params[i]]; isPerMember {
			i += skip
			continue
		}
		out = append(out, params[i])
	}
	return out
}

// PoolSpec is what the "create new pool" wizard submits: a brand-new
// backend or listen section with protocol templates (Web, MySQL, Postgres, Redis, TCP).
type PoolSpec struct {
	Name string
	// Profile: web | mysql | postgres | redis | tcp
	Profile string
	// Balance is "roundrobin", "leastconn", "first", "source", etc.
	Balance string
	// HealthCheckType: httpchk | mysql-check | pgsql-check | redis-check | tcp-check | none
	HealthCheckType string
	// HealthCheckPath, if set with httpchk (e.g. /health.txt or /).
	HealthCheckPath string
	// HealthCheckUser (for mysql-check or pgsql-check, e.g. haproxy_check or postgres).
	HealthCheckUser string
	// HealthCheckHost (for HTTP Host header check).
	HealthCheckHost string
	// Mode is "http" or "tcp".
	Mode string
	// ListenPort, if set, creates a `listen` block with `bind *:<port>`.
	// If empty, creates a `backend` block.
	ListenPort string
	// Timeouts
	TimeoutClient string
	TimeoutServer string
	// ForwardFor adds `option forwardfor except 127.0.0.0/8`
	ForwardFor bool
	// TrustCloudflare extracts real visitor IP from CF-Connecting-IP and sets X-Forwarded-For
	TrustCloudflare bool
	// CookieSticky adds `cookie SERVERID insert indirect nocache`
	CookieSticky bool
	// Domain optionally binds a public web domain (e.g. app.cni.net.id) to this pool
	Domain string
	// Member represents the primary/first member.
	Member MemberSpec
	// Members allows specifying multiple initial members.
	Members []MemberSpec
}

// CloudflareCIDRs contains all official Cloudflare IPv4 & IPv6 CIDR blocks.
const CloudflareCIDRs = "173.245.48.0/20 103.21.244.0/22 103.22.200.0/22 103.31.4.0/22 141.101.64.0/18 108.162.192.0/18 190.93.240.0/20 188.114.96.0/20 197.234.240.0/22 198.41.128.0/17 162.158.0.0/15 104.16.0.0/13 104.24.0.0/14 172.64.0.0/13 131.0.72.0/22 2400:cb00::/32 2606:4700::/32 2803:f800::/32 2405:b500::/32 2405:8100::/32 2a06:98c0::/29 2c0f:f248::/32"

// AddPool returns content with one new backend or listen section appended at the end,
// containing the configured members and protocol health checks.
func AddPool(content string, spec PoolSpec) (string, string, error) {
	cfg := Parse(content)
	if !nameRE.MatchString(spec.Name) {
		return "", "", fmt.Errorf("nama pool hanya boleh huruf, angka, titik, garis bawah, dan tanda minus (maks. 64)")
	}
	if sectionKeywords[spec.Name] {
		return "", "", fmt.Errorf("%q adalah kata kunci HAProxy, tidak bisa dipakai sebagai nama pool", spec.Name)
	}
	if _, ok := cfg.Pool(spec.Name); ok {
		return "", "", fmt.Errorf("pool %q sudah ada", spec.Name)
	}

	members := spec.Members
	if len(members) == 0 {
		if spec.Member.Host == "" && spec.Member.Name == "" {
			return "", "", fmt.Errorf("setidaknya satu anggota server wajib diisi")
		}
		members = []MemberSpec{spec.Member}
	}

	for i := range members {
		members[i].CloneFrom = ""
		if err := validateMemberSpec(Pool{Name: spec.Name}, members[i], ""); err != nil {
			return "", "", err
		}
	}

	balance := strings.TrimSpace(spec.Balance)

	var lines []string
	if spec.ListenPort != "" {
		lines = append(lines, "listen "+spec.Name)
		lines = append(lines, "        bind *:"+spec.ListenPort)
	} else {
		lines = append(lines, "backend "+spec.Name)
	}
	if spec.Mode != "" {
		lines = append(lines, "        mode "+spec.Mode)
	}
	if balance != "" && balance != "roundrobin" {
		lines = append(lines, "        balance "+balance)
	}
	if spec.TimeoutClient != "" {
		lines = append(lines, "        timeout client "+spec.TimeoutClient)
	}
	if spec.TimeoutServer != "" {
		lines = append(lines, "        timeout server "+spec.TimeoutServer)
	}
	if spec.TrustCloudflare && (spec.Mode == "http" || spec.Mode == "") {
		lines = append(lines, "        http-request set-header X-Forwarded-For %[req.hdr(CF-Connecting-IP)] if { req.hdr(CF-Connecting-IP) -m found }")
	}
	if spec.ForwardFor && (spec.Mode == "http" || spec.Mode == "") {
		lines = append(lines, "        option forwardfor except 127.0.0.0/8")
	}
	if spec.CookieSticky && (spec.Mode == "http" || spec.Mode == "") {
		lines = append(lines, "        cookie SERVERID insert indirect nocache")
	}

	// Health Checks
	switch spec.HealthCheckType {
	case "mysql-check":
		if spec.HealthCheckUser != "" {
			lines = append(lines, "        option mysql-check user "+spec.HealthCheckUser)
		} else {
			lines = append(lines, "        option mysql-check")
		}
	case "pgsql-check":
		if spec.HealthCheckUser != "" {
			lines = append(lines, "        option pgsql-check user "+spec.HealthCheckUser)
		} else {
			lines = append(lines, "        option pgsql-check")
		}
	case "redis-check":
		lines = append(lines, "        option tcp-check")
		lines = append(lines, "        tcp-check send PING\\r\\n")
		lines = append(lines, "        tcp-check expect string +PONG")
	case "tcp-check":
		lines = append(lines, "        option tcp-check")
	default:
		// Default or httpchk
		if spec.HealthCheckPath != "" {
			lines = append(lines, "        option httpchk")
			if spec.HealthCheckHost != "" {
				lines = append(lines, "        http-check send meth GET uri "+spec.HealthCheckPath+" ver HTTP/1.1 hdr Host "+spec.HealthCheckHost)
				lines = append(lines, "        http-check expect rstatus ^[234]")
			} else {
				lines = append(lines, "        http-check send meth GET uri "+spec.HealthCheckPath)
			}
		}
	}

	for _, m := range members {
		memberLine := "server " + m.Name + " " + m.Host + ":" + m.Port
		if spec.CookieSticky && (spec.Mode == "http" || spec.Mode == "") {
			memberLine += " cookie " + m.Name
		}
		if m.Weight != "" {
			memberLine += " weight " + m.Weight
		}
		if m.Maxconn != "" {
			memberLine += " maxconn " + m.Maxconn
		}
		memberLine += " check"
		if m.Backup {
			memberLine += " backup"
		}
		if m.Disabled {
			memberLine += " disabled"
		}
		lines = append(lines, "        "+memberLine)
	}

	block := strings.Join(lines, "\n")

	nl := "\n"
	if strings.Contains(content, "\r\n") {
		nl = "\r\n"
	}
	updated := strings.TrimRight(content, "\r\n") + nl + nl + strings.Join(lines, nl) + nl
	return updated, block, nil
}

// RemoveMember returns content without pool's server line for member, plus
// the removed line. It refuses to empty a pool: a backend with no servers
// answers every request with 503, which is never what "remove" means.
func RemoveMember(content, pool, member string) (string, string, error) {
	p, ok := Parse(content).Pool(pool)
	if !ok {
		return "", "", fmt.Errorf("kelompok %q tidak ditemukan di konfigurasi", pool)
	}
	for _, m := range p.Members {
		if m.Name != member {
			continue
		}
		if len(p.Members) == 1 {
			return "", "", fmt.Errorf("%s adalah anggota terakhir %s; kelompok tidak boleh kosong", member, pool)
		}
		return deleteLine(content, m.Line), m.Raw, nil
	}
	return "", "", fmt.Errorf("anggota %q tidak ada di kelompok %s", member, pool)
}

// RateLimitSpec is what the "rate limit" form submits.
type RateLimitSpec struct {
	RPS              int
	Action           string // "deny" (reject with 429) or "tarpit" (hold the connection open, then 429)
	IgnoreCloudflare bool   // bypass Cloudflare proxy IPs and track client real IP from CF-Connecting-IP
	ExcludeStatic    bool   // static files (see StaticExtensions) are never counted or rejected
}

// StaticExtensions are the file suffixes ExcludeStatic leaves out of the limit.
// A page load fetches dozens of these, so counting them would trip any
// sensible limit on the first visit. Dynamic endpoints (.json, .php, ...) are
// deliberately not listed.
const StaticExtensions = ".css .js .mjs .map .png .jpg .jpeg .gif .webp .avif .svg .ico .bmp " +
	".woff .woff2 .ttf .otf .eot .mp4 .webm .mp3 .ogg .wav"

// rateLimitLines renders spec as the 6 or 8 line block SetRateLimit/RemoveRateLimit
// recognize by its leading marker comment — see RateLimit in parse.go.
//
// The rate check runs BEFORE track-sc0 and reads the table without touching
// it (table_http_req_rate), so a request that is rejected never counts toward
// the rate. Otherwise a visitor on the waiting page keeps feeding the counter
// with every retry and never drops back under the limit.
func rateLimitLines(indent string, spec RateLimitSpec) []string {
	const allow = "!{ src -f /etc/haproxy/maps/allowlist_ip.lst }"
	// notStatic is appended to every condition that counts or rejects requests.
	notStatic, marker := "", ""
	var staticACL []string
	if spec.ExcludeStatic {
		notStatic = " !rl_static"
		marker = " exclude_static=true"
		staticACL = []string{indent + "acl rl_static path_end -i " + StaticExtensions}
	}
	if spec.IgnoreCloudflare {
		lines := []string{
			indent + fmt.Sprintf("# haproxy-gui:rate-limit rps=%d action=%s ignore_cf=true%s", spec.RPS, spec.Action, marker),
			indent + "acl is_cloudflare src " + CloudflareCIDRs,
		}
		lines = append(lines, staticACL...)
		return append(lines,
			indent+"http-request deny deny_status 403 if { src -f /etc/haproxy/maps/blocklist_ip.lst } !is_cloudflare",
			indent+"http-request deny deny_status 429 if { hdr(host) -i -f /etc/haproxy/maps/ratelimit_host.map }",
			indent+"stick-table type ip size 100k expire 30s store http_req_rate(10s)",
			indent+fmt.Sprintf("http-request %s deny_status 429 if is_cloudflare%s { req.hdr(CF-Connecting-IP),table_http_req_rate() gt %d } %s || !is_cloudflare%s { src,table_http_req_rate() gt %d } %s", spec.Action, notStatic, spec.RPS, allow, notStatic, spec.RPS, allow),
			indent+"http-request track-sc0 req.hdr(CF-Connecting-IP) if is_cloudflare { req.hdr(CF-Connecting-IP) -m found }"+notStatic,
			indent+"http-request track-sc0 src if !is_cloudflare"+notStatic,
		)
	}
	lines := []string{indent + fmt.Sprintf("# haproxy-gui:rate-limit rps=%d action=%s%s", spec.RPS, spec.Action, marker)}
	lines = append(lines, staticACL...)
	return append(lines,
		indent+"http-request deny deny_status 403 if { src -f /etc/haproxy/maps/blocklist_ip.lst }",
		indent+"http-request deny deny_status 429 if { hdr(host) -i -f /etc/haproxy/maps/ratelimit_host.map }",
		indent+"stick-table type ip size 100k expire 30s store http_req_rate(10s)",
		indent+fmt.Sprintf("http-request %s deny_status 429 if%s { src,table_http_req_rate() gt %d } %s", spec.Action, notStatic, spec.RPS, allow),
		indent+"http-request track-sc0 src"+func() string {
			if notStatic != "" {
				return " if" + notStatic
			}
			return ""
		}(),
	)
}

// SetRateLimit adds pool's per-source-IP request rate limit, or replaces the
// one already there. Requests from one IP over spec.RPS in a 10s window are
// rejected (deny) or held open then rejected (tarpit) with HTTP 429.
func SetRateLimit(content, pool string, spec RateLimitSpec) (string, string, error) {
	p, ok := Parse(content).Pool(pool)
	if !ok {
		return "", "", fmt.Errorf("kelompok %q tidak ditemukan di konfigurasi", pool)
	}
	if spec.Action != "deny" && spec.Action != "tarpit" {
		return "", "", fmt.Errorf(`aksi harus "deny" atau "tarpit"`)
	}
	if spec.RPS < 1 || spec.RPS > 100000 {
		return "", "", fmt.Errorf("batas permintaan/detik harus 1-100000")
	}

	indent := "        "
	if len(p.Members) > 0 {
		indent = p.Members[0].Indent
	}
	lines := rateLimitLines(indent, spec)
	block := strings.Join(lines, "\n")

	if p.RateLimit != nil {
		return replaceLines(content, p.RateLimit.markerLine, p.RateLimit.LineCount(), lines), block, nil
	}
	return insertLines(content, p.headerLine, lines), block, nil
}

// RemoveRateLimit deletes pool's rate limit block. Errors if it has none.
func RemoveRateLimit(content, pool string) (string, error) {
	p, ok := Parse(content).Pool(pool)
	if !ok {
		return "", fmt.Errorf("kelompok %q tidak ditemukan di konfigurasi", pool)
	}
	if p.RateLimit == nil {
		return "", fmt.Errorf("kelompok %s tidak memiliki batas laju yang aktif", pool)
	}
	return deleteLines(content, p.RateLimit.markerLine, p.RateLimit.LineCount()), nil
}

func insertLine(content string, after int, text string) string {
	lines := strings.Split(content, "\n")
	if after < len(lines) && strings.HasSuffix(lines[after], "\r") {
		text += "\r"
	}
	out := make([]string, 0, len(lines)+1)
	out = append(out, lines[:after+1]...)
	out = append(out, text)
	out = append(out, lines[after+1:]...)
	return strings.Join(out, "\n")
}

func replaceLine(content string, idx int, text string) string {
	lines := strings.Split(content, "\n")
	if idx < len(lines) && strings.HasSuffix(lines[idx], "\r") {
		text += "\r"
	}
	lines[idx] = text
	return strings.Join(lines, "\n")
}

func deleteLine(content string, idx int) string {
	lines := strings.Split(content, "\n")
	out := make([]string, 0, len(lines)-1)
	out = append(out, lines[:idx]...)
	out = append(out, lines[idx+1:]...)
	return strings.Join(out, "\n")
}

// insertLines is insertLine for a whole block at once, so a multi-line
// insert stays one edit (and one \r-detection) instead of N chained calls.
func insertLines(content string, after int, newLines []string) string {
	lines := strings.Split(content, "\n")
	cr := after < len(lines) && strings.HasSuffix(lines[after], "\r")
	ins := make([]string, len(newLines))
	for i, l := range newLines {
		if cr {
			l += "\r"
		}
		ins[i] = l
	}
	out := make([]string, 0, len(lines)+len(ins))
	out = append(out, lines[:after+1]...)
	out = append(out, ins...)
	out = append(out, lines[after+1:]...)
	return strings.Join(out, "\n")
}

// replaceLines swaps out count lines starting at start for newLines.
func replaceLines(content string, start, count int, newLines []string) string {
	lines := strings.Split(content, "\n")
	cr := start < len(lines) && strings.HasSuffix(lines[start], "\r")
	rep := make([]string, len(newLines))
	for i, l := range newLines {
		if cr {
			l += "\r"
		}
		rep[i] = l
	}
	out := make([]string, 0, len(lines)-count+len(rep))
	out = append(out, lines[:start]...)
	out = append(out, rep...)
	out = append(out, lines[start+count:]...)
	return strings.Join(out, "\n")
}

// deleteLines removes count lines starting at start.
func deleteLines(content string, start, count int) string {
	lines := strings.Split(content, "\n")
	out := make([]string, 0, len(lines)-count)
	out = append(out, lines[:start]...)
	out = append(out, lines[start+count:]...)
	return strings.Join(out, "\n")
}

// SetPoolDisabled adds or removes the "disabled" directive in the pool's section.
func SetPoolDisabled(content, pool string, disabled bool) (string, error) {
	p, ok := Parse(content).Pool(pool)
	if !ok {
		return "", fmt.Errorf("kelompok %q tidak ditemukan di konfigurasi", pool)
	}
	if disabled {
		if p.Disabled {
			return content, nil
		}
		return insertLine(content, p.headerLine, "        disabled"), nil
	}
	if !p.Disabled {
		return content, nil
	}
	return deleteLine(content, p.disabledLine), nil
}

// DeletePool removes the entire backend or listen block corresponding to pool.
func DeletePool(content, pool string) (string, error) {
	p, ok := Parse(content).Pool(pool)
	if !ok {
		return "", fmt.Errorf("kelompok %q tidak ditemukan di konfigurasi", pool)
	}
	lines := strings.Split(content, "\n")
	start := p.headerLine
	end := p.lastBodyLine

	for end+1 < len(lines) && strings.TrimSpace(lines[end+1]) == "" {
		end++
	}

	count := end - start + 1
	updated := deleteLines(content, start, count)
	return updated, nil
}
