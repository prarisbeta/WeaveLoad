package errorpages

import "testing"

const wiringCfg = `defaults
        errorfile 400 /etc/haproxy/errors/400.http
        errorfile 503 /etc/haproxy/errors/503.http
        # errorfile 429 /etc/haproxy/errors/429.http
        errorfile 504 /var/www/other/504.http
        errorfile bogus /x
        errorfile 500
`

func TestCheckWiring(t *testing.T) {
	m := NewManager("/etc/haproxy/errors")
	w := m.CheckWiring(wiringCfg)

	if got := w[503]; !got.Referenced || !got.PathMatches {
		t.Errorf("503 = %+v, want referenced and pointing at the managed file", got)
	}
	if got := w[429]; got.Referenced {
		t.Errorf("429 = %+v: a commented-out line must not count as wired", got)
	}
	if got := w[504]; !got.Referenced || got.PathMatches || got.Path != "/var/www/other/504.http" {
		t.Errorf("504 = %+v, want referenced but pointing at a different file", got)
	}
	if _, ok := w[500]; ok {
		t.Error("an errorfile line with no path is not a reference")
	}
}

func TestCheckWiringAnyMatchingLineCounts(t *testing.T) {
	m := NewManager("/etc/haproxy/errors")
	w := m.CheckWiring("backend a\n errorfile 429 /tmp/old.http\nbackend b\n\terrorfile 429 /etc/haproxy/errors/429.http\r\n")
	if got := w[429]; !got.Referenced || !got.PathMatches || got.Path != "/tmp/old.http" {
		t.Errorf("429 = %+v, want referenced, matching via the second line, first path reported", got)
	}
}

func TestDirective(t *testing.T) {
	if got := NewManager("/etc/haproxy/errors").Directive(429); got != "errorfile 429 /etc/haproxy/errors/429.http" {
		t.Errorf("Directive = %q", got)
	}
}

func TestCheckWiringEmptyConfig(t *testing.T) {
	if got := NewManager("/e").CheckWiring(""); len(got) != 0 {
		t.Errorf("got %v, want nothing", got)
	}
}
