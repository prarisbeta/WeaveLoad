package errorpages

import (
	"os"
	"strings"
	"testing"
)

// Both waiting pages must retry even when scripts do not run (a strict CSP, an
// extension): a meta refresh as the safety net, and the script as the normal,
// jittered path that fires first.
func checkRetryPage(t *testing.T, name, page string) {
	t.Helper()
	if !strings.Contains(page, `http-equiv="refresh" content="45"`) {
		t.Errorf("%s: no meta-refresh safety net, so a blocked script leaves the visitor stuck", name)
	}
	if strings.Contains(page, `http-equiv="refresh" content="5"`) {
		t.Errorf("%s: a fixed 5s refresh brings every waiting visitor back at the same moment", name)
	}
	for _, want := range []string{"Math.random()", "location.replace(", "sessionStorage"} {
		if !strings.Contains(page, want) {
			t.Errorf("%s: missing %q in the retry script", name, want)
		}
	}
	if strings.Contains(page, "location.reload()") {
		t.Errorf("%s: location.reload() would resubmit a POST; use location.replace", name)
	}
}

func TestPreset429RetriesWithoutRelyingOnScript(t *testing.T) {
	checkRetryPage(t, "GetPreset(429)", GetPreset(429))
}

func TestShippedErrorfile429RetriesWithoutRelyingOnScript(t *testing.T) {
	b, err := os.ReadFile("../../deploy/errors/429.http")
	if err != nil {
		t.Skip("deploy/errors/429.http not available:", err)
	}
	checkRetryPage(t, "deploy/errors/429.http", string(b))
}
