package haproxycfg

import (
	"strings"
	"testing"
)

func TestAddMember_ClonesSiblingSettings(t *testing.T) {
	out, line, err := AddMember(sampleCfg, "https_oms", MemberSpec{
		Name: "node03", Host: "192.168.200.120", Port: "443", CloneFrom: "node02",
	})
	if err != nil {
		t.Fatal(err)
	}
	want := "server node03 192.168.200.120:443 cookie node03 ssl verify none sni str(oms.cni.net.id) check check-sni oms.cni.net.id"
	if line != want {
		t.Errorf("line =\n %q\nwant\n %q", line, want)
	}

	// Inserted right after the pool's last server, with the same indent.
	lines := strings.Split(out, "\n")
	for i, l := range lines {
		if strings.Contains(l, "server node02 192.168.200.118:443") {
			if lines[i+1] != "        "+want {
				t.Errorf("line after node02 = %q", lines[i+1])
			}
			return
		}
	}
	t.Fatal("node02 not found in output")
}

func TestAddMember_FlagsWeightMaxconn(t *testing.T) {
	_, line, err := AddMember(sampleCfg, "http_oms", MemberSpec{
		Name: "node4", Host: "10.1.1.4", Port: "8080", Weight: "20", Maxconn: "500",
		Backup: true, Disabled: true, CloneFrom: "node3",
	})
	if err != nil {
		t.Fatal(err)
	}
	want := "server node4 10.1.1.4:8080 weight 20 maxconn 500 check backup disabled"
	if line != want {
		t.Errorf("line = %q, want %q", line, want)
	}
}

func TestAddMember_DoesNotCopyPerServerAddrOrPort(t *testing.T) {
	cfg := "backend b\n  server s1 10.0.0.1:443 check addr 10.0.0.9 port 8080 agent-addr 10.0.0.9 track b2/other\n"
	_, line, err := AddMember(cfg, "b", MemberSpec{Name: "s2", Host: "10.0.0.2", Port: "443", CloneFrom: "s1"})
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"addr", "10.0.0.9", "agent-addr", "track", "port 8080"} {
		if strings.Contains(line, bad) {
			t.Errorf("line %q must not inherit per-server setting %q", line, bad)
		}
	}
	if !strings.Contains(line, "check") {
		t.Errorf("line %q should still inherit plain check", line)
	}
}

func TestAddMember_DefaultsToFirstMemberAsTemplate(t *testing.T) {
	_, line, err := AddMember(sampleCfg, "https_oms", MemberSpec{Name: "n3", Host: "10.0.0.3", Port: "443"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(line, "inter 3000") {
		t.Errorf("expected node01's settings to be cloned, got %q", line)
	}
}

func TestAddMember_EmptyPoolGetsCheckAndGoesAfterLastLine(t *testing.T) {
	out, line, err := AddMember(sampleCfg, "empty_pool", MemberSpec{Name: "s1", Host: "app.internal", Port: "80"})
	if err != nil {
		t.Fatal(err)
	}
	if line != "server s1 app.internal:80 check" {
		t.Errorf("line = %q", line)
	}
	if !strings.Contains(out, "timeout server 10s\n        server s1 app.internal:80 check\n") {
		t.Errorf("not inserted after the pool body:\n%s", out)
	}
}

func TestAddMember_RejectsBadInput(t *testing.T) {
	base := MemberSpec{Name: "ok", Host: "10.0.0.9", Port: "80"}
	cases := map[string]func(*MemberSpec){
		"bad name":        func(s *MemberSpec) { s.Name = "a b" },
		"newline name":    func(s *MemberSpec) { s.Name = "a\nserver x" },
		"dup name":        func(s *MemberSpec) { s.Name = "node1" },
		"bad host":        func(s *MemberSpec) { s.Host = "10.0.0.1 check" },
		"ipv6 host":       func(s *MemberSpec) { s.Host = "2001:db8::1" },
		"empty host":      func(s *MemberSpec) { s.Host = "" },
		"port zero":       func(s *MemberSpec) { s.Port = "0" },
		"port too high":   func(s *MemberSpec) { s.Port = "70000" },
		"port text":       func(s *MemberSpec) { s.Port = "http" },
		"weight too high": func(s *MemberSpec) { s.Weight = "300" },
		"maxconn zero":    func(s *MemberSpec) { s.Maxconn = "0" },
		"dup address":     func(s *MemberSpec) { s.Host = "192.168.200.108" },
		"unknown clone":   func(s *MemberSpec) { s.CloneFrom = "nope" },
		"signed port":     func(s *MemberSpec) { s.Port = "+80" },
		"leading zero":    func(s *MemberSpec) { s.Port = "0080" },
		"signed weight":   func(s *MemberSpec) { s.Weight = "+10" },
	}
	for name, mutate := range cases {
		spec := base
		mutate(&spec)
		if _, _, err := AddMember(sampleCfg, "http_oms", spec); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
	if _, _, err := AddMember(sampleCfg, "no_such_pool", base); err == nil {
		t.Error("unknown pool: expected error")
	}
}

func TestRemoveMember(t *testing.T) {
	out, removed, err := RemoveMember(sampleCfg, "http_oms", "node2")
	if err != nil {
		t.Fatal(err)
	}
	if removed != "server node2 192.168.200.118:80 check" {
		t.Errorf("removed = %q", removed)
	}
	if strings.Contains(out, "192.168.200.118:80") {
		t.Error("line still present")
	}
	// Other pools untouched.
	if !strings.Contains(out, "server node02 192.168.200.118:443") {
		t.Error("https_oms node02 must not be touched")
	}
	if len(strings.Split(out, "\n")) != len(strings.Split(sampleCfg, "\n"))-1 {
		t.Error("exactly one line should be removed")
	}
}

func TestRemoveMember_Errors(t *testing.T) {
	if _, _, err := RemoveMember(sampleCfg, "http_oms", "ghost"); err == nil {
		t.Error("unknown member: expected error")
	}
	if _, _, err := RemoveMember(sampleCfg, "ghost", "node1"); err == nil {
		t.Error("unknown pool: expected error")
	}
	single := "backend b\n  server only 10.0.0.1:80 check\n"
	if _, _, err := RemoveMember(single, "b", "only"); err == nil {
		t.Error("removing the last member must be refused")
	}
}

func TestEditMember_ChangesWeightKeepsAdvancedSettings(t *testing.T) {
	out, line, err := EditMember(sampleCfg, "https_oms", "node02", MemberSpec{
		Name: "node02", Host: "192.168.200.118", Port: "443", Weight: "75", Maxconn: "100",
	})
	if err != nil {
		t.Fatal(err)
	}
	want := "server node02 192.168.200.118:443 weight 75 maxconn 100 cookie node02 ssl verify none sni str(oms.cni.net.id) check check-sni oms.cni.net.id"
	if line != want {
		t.Errorf("line =\n %q\nwant\n %q", line, want)
	}
	if strings.Contains(line, "disabled") {
		t.Errorf("disabled flag should be gone once the form submits without it: %q", line)
	}
	if !strings.Contains(out, want) {
		t.Errorf("updated content missing new line:\n%s", out)
	}
	if strings.Contains(out, "weight 50 maxconn 100 cookie node02") {
		t.Error("old line should be replaced, not left in place")
	}
	// The other member (node01) and the pool's own settings must survive untouched.
	if !strings.Contains(out, "server node01 192.168.200.108:443 inter 3000 cookie node01") {
		t.Errorf("node01 must not be touched:\n%s", out)
	}
	if !strings.Contains(out, "cookie SERVERID insert indirect nocache") {
		t.Error("pool-level cookie directive must survive")
	}
}

func TestEditMember_CanRenameAndChangeAddress(t *testing.T) {
	out, line, err := EditMember(sampleCfg, "http_oms", "node1", MemberSpec{
		Name: "node1b", Host: "10.0.0.9", Port: "8080",
	})
	if err != nil {
		t.Fatal(err)
	}
	if line != "server node1b 10.0.0.9:8080 check" {
		t.Errorf("line = %q", line)
	}
	if strings.Contains(out, "server node1 192.168.200.108:80") {
		t.Error("old line should be gone")
	}
	if !strings.Contains(out, "server node1b 10.0.0.9:8080 check") {
		t.Errorf("renamed line missing:\n%s", out)
	}
}

func TestEditMember_KeepingOwnNameOrAddressIsNotADuplicate(t *testing.T) {
	// Submitting the form unchanged (same name, same address) must not trip
	// the "already a member" / "name already used" self-conflict checks.
	_, _, err := EditMember(sampleCfg, "http_oms", "node1", MemberSpec{
		Name: "node1", Host: "192.168.200.108", Port: "80",
	})
	if err != nil {
		t.Fatalf("unchanged resubmit should succeed, got: %v", err)
	}
}

func TestEditMember_RejectsConflictsWithOtherMembers(t *testing.T) {
	cases := map[string]MemberSpec{
		"rename to another member's name": {Name: "node2", Host: "10.0.0.9", Port: "80"},
		"address of another member":       {Name: "node1", Host: "192.168.200.118", Port: "80"},
	}
	for name, spec := range cases {
		if _, _, err := EditMember(sampleCfg, "http_oms", "node1", spec); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
}

func TestEditMember_RejectsBadInput(t *testing.T) {
	base := MemberSpec{Name: "node1", Host: "10.0.0.9", Port: "80"}
	cases := map[string]func(*MemberSpec){
		"bad name":      func(s *MemberSpec) { s.Name = "a b" },
		"bad host":      func(s *MemberSpec) { s.Host = "10.0.0.1 check" },
		"empty host":    func(s *MemberSpec) { s.Host = "" },
		"port zero":     func(s *MemberSpec) { s.Port = "0" },
		"signed port":   func(s *MemberSpec) { s.Port = "+80" },
		"leading zero":  func(s *MemberSpec) { s.Port = "0080" },
		"signed weight": func(s *MemberSpec) { s.Weight = "+10" },
	}
	for name, mutate := range cases {
		spec := base
		mutate(&spec)
		if _, _, err := EditMember(sampleCfg, "http_oms", "node1", spec); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
}

func TestEditMember_UnknownPoolOrMember_Errors(t *testing.T) {
	if _, _, err := EditMember(sampleCfg, "no_such_pool", "node1", MemberSpec{Name: "node1", Host: "1.2.3.4", Port: "80"}); err == nil {
		t.Error("unknown pool: expected error")
	}
	if _, _, err := EditMember(sampleCfg, "http_oms", "ghost", MemberSpec{Name: "ghost", Host: "1.2.3.4", Port: "80"}); err == nil {
		t.Error("unknown member: expected error")
	}
}

func TestEditMember_PreservesCRLF(t *testing.T) {
	crlf := strings.ReplaceAll("backend b\n  server s1 10.0.0.1:80 check\n", "\n", "\r\n")
	out, _, err := EditMember(crlf, "b", "s1", MemberSpec{Name: "s1", Host: "10.0.0.1", Port: "8080"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "  server s1 10.0.0.1:8080 check\r\n") {
		t.Errorf("CRLF not preserved: %q", out)
	}
}

func TestAddPool_CreatesMinimalBackendWithFirstMember(t *testing.T) {
	out, block, err := AddPool(sampleCfg, PoolSpec{
		Name:   "http_new",
		Member: MemberSpec{Name: "node1", Host: "10.0.0.5", Port: "80"},
	})
	if err != nil {
		t.Fatal(err)
	}
	wantBlock := "backend http_new\n        server node1 10.0.0.5:80 check"
	if block != wantBlock {
		t.Errorf("block =\n%q\nwant\n%q", block, wantBlock)
	}
	if !strings.HasSuffix(strings.TrimRight(out, "\n"), wantBlock) {
		t.Errorf("new backend must be appended at the end:\n%s", out)
	}
	// Nothing before it should be touched.
	if !strings.Contains(out, "backend http_oms") {
		t.Error("existing backend must survive")
	}
}

func TestAddPool_WithHealthCheckPath(t *testing.T) {
	_, block, err := AddPool(sampleCfg, PoolSpec{
		Name:            "http_new",
		HealthCheckPath: "/health.txt",
		Member:          MemberSpec{Name: "node1", Host: "10.0.0.5", Port: "80"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(block, "option httpchk") || !strings.Contains(block, "http-check send meth GET uri /health.txt") {
		t.Errorf("block missing health check directives: %q", block)
	}
	if !strings.Contains(block, "server node1 10.0.0.5:80 check") {
		t.Errorf("server line should still end in check: %q", block)
	}
}

func TestAddPool_NonDefaultBalance(t *testing.T) {
	_, block, err := AddPool(sampleCfg, PoolSpec{
		Name:    "http_new",
		Balance: "leastconn",
		Member:  MemberSpec{Name: "node1", Host: "10.0.0.5", Port: "80"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(block, "balance leastconn") {
		t.Errorf("block missing balance directive: %q", block)
	}
}

func TestAddPool_DefaultBalanceOmitsDirective(t *testing.T) {
	_, block, err := AddPool(sampleCfg, PoolSpec{
		Name:   "http_new",
		Member: MemberSpec{Name: "node1", Host: "10.0.0.5", Port: "80"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(block, "balance") {
		t.Errorf("roundrobin is HAProxy's default, no need to spell it out: %q", block)
	}
}

func TestAddPool_RejectsBadInput(t *testing.T) {
	cases := map[string]PoolSpec{
		"duplicate pool name": {Name: "http_oms", Member: MemberSpec{Name: "n1", Host: "10.0.0.5", Port: "80"}},
		"reserved keyword":    {Name: "backend", Member: MemberSpec{Name: "n1", Host: "10.0.0.5", Port: "80"}},
		"bad pool name":       {Name: "http new", Member: MemberSpec{Name: "n1", Host: "10.0.0.5", Port: "80"}},
		"bad member name":     {Name: "http_new", Member: MemberSpec{Name: "a b", Host: "10.0.0.5", Port: "80"}},
		"bad member host":     {Name: "http_new", Member: MemberSpec{Name: "n1", Host: "", Port: "80"}},
		"bad member port":     {Name: "http_new", Member: MemberSpec{Name: "n1", Host: "10.0.0.5", Port: "0"}},
	}
	for name, spec := range cases {
		if _, _, err := AddPool(sampleCfg, spec); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
}

func TestAddPool_PreservesCRLF(t *testing.T) {
	crlf := strings.ReplaceAll("backend b\n  server s1 10.0.0.1:80 check\n", "\n", "\r\n")
	out, _, err := AddPool(crlf, PoolSpec{Name: "http_new", Member: MemberSpec{Name: "n1", Host: "10.0.0.5", Port: "80"}})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "backend http_new\r\n        server n1 10.0.0.5:80 check\r\n") {
		t.Errorf("CRLF not preserved: %q", out)
	}
}

func TestAddMember_PreservesCRLF(t *testing.T) {
	crlf := strings.ReplaceAll("backend b\n  server s1 10.0.0.1:80 check\n", "\n", "\r\n")
	out, _, err := AddMember(crlf, "b", MemberSpec{Name: "s2", Host: "10.0.0.2", Port: "80"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "  server s2 10.0.0.2:80 check\r\n") {
		t.Errorf("CRLF not preserved: %q", out)
	}
}

func TestSetRateLimit_AddsBlockToPoolWithoutOne(t *testing.T) {
	out, block, err := SetRateLimit(sampleCfg, "http_oms", RateLimitSpec{RPS: 20, Action: "deny"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(block, "rps=20 action=deny") || !strings.Contains(block, "gt 20") {
		t.Errorf("block = %q", block)
	}
	if !strings.Contains(out, "backend http_oms\n        # haproxy-gui:rate-limit rps=20 action=deny\n") {
		t.Errorf("block not inserted right after the backend header:\n%s", out)
	}
	p, _ := Parse(out).Pool("http_oms")
	if p.RateLimit == nil || p.RateLimit.RPS != 20 || p.RateLimit.Action != "deny" {
		t.Errorf("re-parsed RateLimit = %+v", p.RateLimit)
	}
	// The pool's members must still be intact after the insert shifts lines.
	if len(p.Members) != 3 {
		t.Errorf("members = %d, want 3 (unaffected by the insert)", len(p.Members))
	}
}

func TestSetRateLimit_ReplacesExistingBlockInPlace(t *testing.T) {
	withLimit, _, err := SetRateLimit(sampleCfg, "http_oms", RateLimitSpec{RPS: 20, Action: "deny"})
	if err != nil {
		t.Fatal(err)
	}
	out, _, err := SetRateLimit(withLimit, "http_oms", RateLimitSpec{RPS: 50, Action: "tarpit"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(out, "haproxy-gui:rate-limit") != 1 {
		t.Errorf("expected exactly one rate-limit block after replacing, got:\n%s", out)
	}
	p, _ := Parse(out).Pool("http_oms")
	if p.RateLimit == nil || p.RateLimit.RPS != 50 || p.RateLimit.Action != "tarpit" {
		t.Errorf("RateLimit after replace = %+v", p.RateLimit)
	}
}

func TestSetRateLimit_RejectsBadInput(t *testing.T) {
	cases := map[string]RateLimitSpec{
		"bad action": {RPS: 20, Action: "block"},
		"zero rps":   {RPS: 0, Action: "deny"},
		"huge rps":   {RPS: 1000000, Action: "deny"},
	}
	for name, spec := range cases {
		if _, _, err := SetRateLimit(sampleCfg, "http_oms", spec); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
}

func TestSetRateLimit_UnknownPool_Errors(t *testing.T) {
	if _, _, err := SetRateLimit(sampleCfg, "nope", RateLimitSpec{RPS: 20, Action: "deny"}); err == nil {
		t.Error("expected error for unknown pool")
	}
}

func TestRemoveRateLimit_RemovesAllSixLines(t *testing.T) {
	withLimit, _, err := SetRateLimit(sampleCfg, "http_oms", RateLimitSpec{RPS: 20, Action: "deny"})
	if err != nil {
		t.Fatal(err)
	}
	out, err := RemoveRateLimit(withLimit, "http_oms")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, "haproxy-gui:rate-limit") || strings.Contains(out, "sc_http_req_rate") {
		t.Errorf("rate-limit block not fully removed:\n%s", out)
	}
	p, _ := Parse(out).Pool("http_oms")
	if p.RateLimit != nil {
		t.Errorf("RateLimit = %+v, want nil after removal", p.RateLimit)
	}
	if len(p.Members) != 3 {
		t.Errorf("members = %d, want 3 (unaffected by the removal)", len(p.Members))
	}
}

func TestRemoveRateLimit_ErrorsWhenNoneConfigured(t *testing.T) {
	if _, err := RemoveRateLimit(sampleCfg, "http_oms"); err == nil {
		t.Error("expected error removing a rate limit that was never set")
	}
}

func TestRemoveRateLimit_UnknownPool_Errors(t *testing.T) {
	if _, err := RemoveRateLimit(sampleCfg, "nope"); err == nil {
		t.Error("expected error for unknown pool")
	}
}

func TestSetRateLimit_CloudflareSupport(t *testing.T) {
	withLimit, block, err := SetRateLimit(sampleCfg, "http_oms", RateLimitSpec{
		RPS: 50, Action: "deny", IgnoreCloudflare: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(block, "ignore_cf=true") || !strings.Contains(block, "is_cloudflare") {
		t.Errorf("block missing cloudflare integration: %s", block)
	}
	p, _ := Parse(withLimit).Pool("http_oms")
	if p.RateLimit == nil || !p.RateLimit.IgnoreCloudflare || p.RateLimit.RPS != 50 {
		t.Fatalf("parsed RateLimit = %+v", p.RateLimit)
	}
	// Test removal of the 8-line Cloudflare block
	clean, err := RemoveRateLimit(withLimit, "http_oms")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(clean, "is_cloudflare") || strings.Contains(clean, "haproxy-gui:rate-limit") {
		t.Errorf("cloudflare rate limit not cleanly removed:\n%s", clean)
	}
}

func TestAddPool_Profiles(t *testing.T) {
	// 1. Web with Cloudflare & Cookie
	_, blockWeb, err := AddPool(sampleCfg, PoolSpec{
		Name:            "web_app",
		Mode:            "http",
		Balance:         "roundrobin",
		HealthCheckType: "httpchk",
		HealthCheckPath: "/health",
		HealthCheckHost: "example.com",
		ForwardFor:      true,
		TrustCloudflare: true,
		CookieSticky:    true,
		Member: MemberSpec{
			Name: "web01", Host: "192.168.1.50", Port: "8080",
		},
	})
	if err != nil {
		t.Fatalf("AddPool Web failed: %v", err)
	}
	if !strings.Contains(blockWeb, "http-request set-header X-Forwarded-For %[req.hdr(CF-Connecting-IP)]") {
		t.Errorf("web pool missing CF header mapping:\n%s", blockWeb)
	}
	if !strings.Contains(blockWeb, "cookie SERVERID insert indirect nocache") {
		t.Errorf("web pool missing cookie sticky:\n%s", blockWeb)
	}

	// 2. MySQL Profile
	outMySQL, blockMySQL, err := AddPool(sampleCfg, PoolSpec{
		Name:            "mysql_cluster",
		Mode:            "tcp",
		ListenPort:      "3306",
		Balance:         "leastconn",
		HealthCheckType: "mysql-check",
		HealthCheckUser: "haproxy_check",
		TimeoutClient:   "8h",
		TimeoutServer:   "8h",
		Member: MemberSpec{
			Name: "db01", Host: "192.168.1.60", Port: "3306",
		},
	})
	if err != nil {
		t.Fatalf("AddPool MySQL failed: %v", err)
	}
	if !strings.Contains(blockMySQL, "listen mysql_cluster") || !strings.Contains(blockMySQL, "option mysql-check user haproxy_check") {
		t.Errorf("MySQL pool invalid:\n%s", blockMySQL)
	}
	if !strings.Contains(outMySQL, "timeout client 8h") || !strings.Contains(outMySQL, "timeout server 8h") {
		t.Errorf("MySQL pool timeouts missing:\n%s", outMySQL)
	}

	// 3. PostgreSQL Profile
	_, blockPG, err := AddPool(sampleCfg, PoolSpec{
		Name:            "pg_cluster",
		Mode:            "tcp",
		Balance:         "leastconn",
		HealthCheckType: "pgsql-check",
		HealthCheckUser: "postgres",
		Member: MemberSpec{
			Name: "pg01", Host: "192.168.1.70", Port: "5432",
		},
	})
	if err != nil {
		t.Fatalf("AddPool PG failed: %v", err)
	}
	if !strings.Contains(blockPG, "option pgsql-check user postgres") {
		t.Errorf("PG pool invalid:\n%s", blockPG)
	}

	// 4. Redis Profile
	_, blockRedis, err := AddPool(sampleCfg, PoolSpec{
		Name:            "redis_cache",
		Mode:            "tcp",
		Balance:         "first",
		HealthCheckType: "redis-check",
		Member: MemberSpec{
			Name: "redis01", Host: "192.168.1.80", Port: "6379",
		},
	})
	if err != nil {
		t.Fatalf("AddPool Redis failed: %v", err)
	}
	if !strings.Contains(blockRedis, "tcp-check expect string +PONG") {
		t.Errorf("Redis pool check invalid:\n%s", blockRedis)
	}
}

func TestSetRateLimit_PreservesCRLF(t *testing.T) {
	crlf := strings.ReplaceAll("backend b\n  server s1 10.0.0.1:80 check\n", "\n", "\r\n")
	out, _, err := SetRateLimit(crlf, "b", RateLimitSpec{RPS: 10, Action: "deny"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "haproxy-gui:rate-limit rps=10 action=deny\r\n") {
		t.Errorf("CRLF not preserved: %q", out)
	}
}

func TestSetPoolDisabled_Toggle(t *testing.T) {
	cfg := `backend test_pool
        mode http
        server s1 10.0.0.1:80 check
`
	// 1. Disable
	disabledCfg, err := SetPoolDisabled(cfg, "test_pool", true)
	if err != nil {
		t.Fatalf("SetPoolDisabled true: %v", err)
	}
	p := Parse(disabledCfg)
	pool, ok := p.Pool("test_pool")
	if !ok || !pool.Disabled {
		t.Fatalf("expected pool to be disabled:\n%s", disabledCfg)
	}

	// 2. Enable
	enabledCfg, err := SetPoolDisabled(disabledCfg, "test_pool", false)
	if err != nil {
		t.Fatalf("SetPoolDisabled false: %v", err)
	}
	p2 := Parse(enabledCfg)
	pool2, ok := p2.Pool("test_pool")
	if !ok || pool2.Disabled {
		t.Fatalf("expected pool to be enabled:\n%s", enabledCfg)
	}
}

func TestDeletePool(t *testing.T) {
	cfg := `backend pool_a
        mode http
        server a1 10.0.0.1:80 check

backend pool_b
        mode http
        server b1 10.0.0.2:80 check
`
	out, err := DeletePool(cfg, "pool_a")
	if err != nil {
		t.Fatalf("DeletePool: %v", err)
	}
	p := Parse(out)
	if _, ok := p.Pool("pool_a"); ok {
		t.Errorf("pool_a should have been deleted:\n%s", out)
	}
	if _, ok := p.Pool("pool_b"); !ok {
		t.Errorf("pool_b should still exist:\n%s", out)
	}
}

// A rejected request must not feed the rate counter: the check has to run
// before track-sc0 and read the table without touching it, otherwise every
// retry from the waiting page keeps the visitor over the limit.
func TestRateLimitLines_DenyBeforeTrack(t *testing.T) {
	for name, spec := range map[string]RateLimitSpec{
		"plain":      {RPS: 20, Action: "deny"},
		"cloudflare": {RPS: 20, Action: "tarpit", IgnoreCloudflare: true},
	} {
		lines := rateLimitLines("", spec)
		deny, track := -1, -1
		for i, l := range lines {
			if strings.Contains(l, "table_http_req_rate") && deny < 0 {
				deny = i
			}
			if strings.Contains(l, "track-sc0") && track < 0 {
				track = i
			}
		}
		if deny < 0 || track < 0 || deny > track {
			t.Errorf("%s: deny at %d, track-sc0 at %d; the check must come first:\n%s", name, deny, track, strings.Join(lines, "\n"))
		}
		if strings.Contains(strings.Join(lines, "\n"), "sc_http_req_rate") {
			t.Errorf("%s: still uses sc_http_req_rate, which only works after tracking", name)
		}
	}
}

// The reordered block keeps the 6/8 line sizes the parser relies on, so a
// block written by an older release (old order) and a new one both remove cleanly.
func TestRateLimitLines_KeepsParserLineCounts(t *testing.T) {
	if n := len(rateLimitLines("", RateLimitSpec{RPS: 5, Action: "deny"})); n != 6 {
		t.Errorf("plain block has %d lines, parser expects 6", n)
	}
	if n := len(rateLimitLines("", RateLimitSpec{RPS: 5, Action: "deny", IgnoreCloudflare: true})); n != 8 {
		t.Errorf("cloudflare block has %d lines, parser expects 8", n)
	}
}

func TestRemoveRateLimit_RemovesNewOrderBlock(t *testing.T) {
	for _, cf := range []bool{false, true} {
		withLimit, _, err := SetRateLimit(sampleCfg, "http_oms", RateLimitSpec{RPS: 20, Action: "deny", IgnoreCloudflare: cf})
		if err != nil {
			t.Fatal(err)
		}
		out, err := RemoveRateLimit(withLimit, "http_oms")
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(out, "table_http_req_rate") || strings.Contains(out, "track-sc0") {
			t.Errorf("cf=%v: block not fully removed:\n%s", cf, out)
		}
	}
}

// Static files must neither count toward the limit nor be rejected by it: a
// single page load fetches dozens of them, so a limit of a few requests would
// otherwise turn every first visit into a 429.
func TestRateLimitLines_ExcludeStatic(t *testing.T) {
	for name, spec := range map[string]RateLimitSpec{
		"plain":      {RPS: 20, Action: "deny", ExcludeStatic: true},
		"cloudflare": {RPS: 20, Action: "tarpit", IgnoreCloudflare: true, ExcludeStatic: true},
	} {
		lines := rateLimitLines("", spec)
		joined := strings.Join(lines, "\n")
		if !strings.Contains(joined, "acl rl_static path_end -i .css .js") {
			t.Errorf("%s: missing the static ACL:\n%s", name, joined)
		}
		if !strings.Contains(lines[0], "exclude_static=true") {
			t.Errorf("%s: marker must record the option: %q", name, lines[0])
		}
		for _, l := range lines {
			isCheck := strings.Contains(l, "table_http_req_rate")
			isTrack := strings.Contains(l, "track-sc0")
			if (isCheck || isTrack) && !strings.Contains(l, "!rl_static") {
				t.Errorf("%s: %q counts or rejects without excluding static files", name, l)
			}
		}
		// The ACL has to exist before the first line that uses it.
		acl, use := -1, -1
		for i, l := range lines {
			if strings.HasPrefix(l, "acl rl_static") && acl < 0 {
				acl = i
			}
			if strings.Contains(l, "!rl_static") && use < 0 {
				use = i
			}
		}
		if acl < 0 || use < 0 || acl > use {
			t.Errorf("%s: acl at %d, first use at %d", name, acl, use)
		}
	}
}

func TestRateLimitLines_WithoutExcludeStaticIsUnchanged(t *testing.T) {
	joined := strings.Join(rateLimitLines("", RateLimitSpec{RPS: 5, Action: "deny"}), "\n")
	if strings.Contains(joined, "rl_static") || strings.Contains(joined, "exclude_static") {
		t.Errorf("the option is off, but the block mentions it:\n%s", joined)
	}
}

// The marker round-trips and LineCount follows it, so Replace and Remove cut
// exactly the lines written, for every combination, and still handle blocks
// written before this option existed.
func TestSetRateLimit_ExcludeStaticRoundTrip(t *testing.T) {
	for _, tc := range []struct {
		cf, static bool
		lines      int
	}{{false, false, 6}, {false, true, 7}, {true, false, 8}, {true, true, 9}} {
		out, _, err := SetRateLimit(sampleCfg, "http_oms", RateLimitSpec{RPS: 20, Action: "deny", IgnoreCloudflare: tc.cf, ExcludeStatic: tc.static})
		if err != nil {
			t.Fatal(err)
		}
		p, _ := Parse(out).Pool("http_oms")
		if p.RateLimit == nil || p.RateLimit.ExcludeStatic != tc.static || p.RateLimit.IgnoreCloudflare != tc.cf {
			t.Fatalf("cf=%v static=%v: parsed %+v", tc.cf, tc.static, p.RateLimit)
		}
		if p.RateLimit.LineCount() != tc.lines {
			t.Errorf("cf=%v static=%v: LineCount = %d, want %d", tc.cf, tc.static, p.RateLimit.LineCount(), tc.lines)
		}
		if got := len(rateLimitLines("", RateLimitSpec{RPS: 20, Action: "deny", IgnoreCloudflare: tc.cf, ExcludeStatic: tc.static})); got != tc.lines {
			t.Errorf("cf=%v static=%v: generator wrote %d lines, parser expects %d", tc.cf, tc.static, got, tc.lines)
		}
		clean, err := RemoveRateLimit(out, "http_oms")
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(clean, "rl_static") || strings.Contains(clean, "track-sc0") || strings.Contains(clean, "table_http_req_rate") {
			t.Errorf("cf=%v static=%v: block not fully removed:\n%s", tc.cf, tc.static, clean)
		}
		if p2, _ := Parse(clean).Pool("http_oms"); len(p2.Members) != 3 {
			t.Errorf("cf=%v static=%v: members = %d, want 3 untouched", tc.cf, tc.static, len(p2.Members))
		}
	}
}

// Switching the option on for a block written without it replaces that block
// in place instead of leaving a second one behind.
func TestSetRateLimit_UpgradeLegacyBlockToExcludeStatic(t *testing.T) {
	legacy, _, err := SetRateLimit(sampleCfg, "http_oms", RateLimitSpec{RPS: 20, Action: "deny"})
	if err != nil {
		t.Fatal(err)
	}
	out, _, err := SetRateLimit(legacy, "http_oms", RateLimitSpec{RPS: 20, Action: "deny", ExcludeStatic: true})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(out, "haproxy-gui:rate-limit") != 1 || strings.Count(out, "track-sc0") != 1 {
		t.Errorf("expected exactly one block after upgrading:\n%s", out)
	}
	if p, _ := Parse(out).Pool("http_oms"); p.RateLimit == nil || !p.RateLimit.ExcludeStatic {
		t.Errorf("RateLimit = %+v", p.RateLimit)
	}
}
