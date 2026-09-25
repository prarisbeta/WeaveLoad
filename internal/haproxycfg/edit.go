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

func validateSpec(p Pool, s MemberSpec) error {
	if !nameRE.MatchString(s.Name) {
		return fmt.Errorf("nama anggota hanya boleh huruf, angka, titik, garis bawah, dan tanda minus (maks. 64)")
	}
	if p.hasMember(s.Name) {
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
		if m.Host == s.Host && m.Port == s.Port {
			return fmt.Errorf("%s:%s sudah menjadi anggota (%s)", s.Host, s.Port, m.Name)
		}
	}
	return nil
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

func deleteLine(content string, idx int) string {
	lines := strings.Split(content, "\n")
	out := make([]string, 0, len(lines)-1)
	out = append(out, lines[:idx]...)
	out = append(out, lines[idx+1:]...)
	return strings.Join(out, "\n")
}
