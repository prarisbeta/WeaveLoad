package errorpages

import (
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
)

// Wiring says whether HAProxy's configuration actually uses the page saved for
// one status code. A page that is saved but not referenced by an errorfile
// line is never shown: HAProxy answers with its plain built-in page instead.
type Wiring struct {
	Code       int
	Referenced bool   // some "errorfile <code> <path>" line exists
	Path       string // path of the first such line
	// PathMatches is true when one of those lines points at the file this
	// manager writes (<dir>/<code>.http).
	PathMatches bool
}

// Directive is the config line that wires code to the page this manager saves.
func (m *Manager) Directive(code int) string {
	return fmt.Sprintf("errorfile %d %s", code, filepath.Join(m.Dir, fmt.Sprintf("%d.http", code)))
}

// CheckWiring scans haproxy.cfg text for errorfile directives. It looks at the
// whole file, not at which proxies inherit a given "defaults" section, so a
// directive placed in only one proxy still counts as present.
func (m *Manager) CheckWiring(config string) map[int]Wiring {
	out := map[int]Wiring{}
	for _, raw := range strings.Split(config, "\n") {
		line := strings.TrimSpace(strings.TrimSuffix(raw, "\r"))
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		f := strings.Fields(line)
		if len(f) < 3 || f[0] != "errorfile" {
			continue
		}
		code, err := strconv.Atoi(f[1])
		if err != nil {
			continue
		}
		w := out[code]
		w.Code = code
		if !w.Referenced {
			w.Path = f[2]
		}
		w.Referenced = true
		if filepath.Clean(f[2]) == filepath.Clean(filepath.Join(m.Dir, fmt.Sprintf("%d.http", code))) {
			w.PathMatches = true
		}
		out[code] = w
	}
	return out
}
