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
