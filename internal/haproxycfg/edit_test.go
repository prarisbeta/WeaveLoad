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
