package haproxycfg

import (
	"strings"
	"testing"
)

const sampleCfg = `global
        log 127.0.0.1:514 local2
        stats socket /var/lib/haproxy/stats level admin

defaults
        mode http
        option httpchk
        default-server inter 10s

listen stats
        bind *:8088
        stats enable

frontend http_in
        bind :::80 v4v6
        use_backend %[req.hdr(host),lower,map(/etc/haproxy/maps/hosts_http.map)]

backend http_oms
        http-check send meth GET uri / ver HTTP/1.1 hdr Host oms.cni.net.id
        http-check expect rstatus ^[234]
        server node1 192.168.200.108:80 check
        server node2 192.168.200.118:80 check
        server node3 192.168.200.103:80 backup check
        timeout server 30s

# --- comment belonging to the next section ---
backend https_oms
        balance leastconn
        cookie SERVERID insert indirect nocache
        server node01 192.168.200.108:443 inter 3000 cookie node01 ssl verify none sni str(oms.cni.net.id) check check-sni oms.cni.net.id # primary
        server node02 192.168.200.118:443 weight 50 maxconn 100 cookie node02 ssl verify none sni str(oms.cni.net.id) disabled check check-sni oms.cni.net.id

backend empty_pool
        timeout server 10s
`

func TestParse_FindsBackendsAndListensAsPools(t *testing.T) {
	cfg := Parse(sampleCfg)
	var names []string
	for _, p := range cfg.Pools {
		names = append(names, p.Name)
	}
	got := strings.Join(names, ",")
	want := "stats,http_oms,https_oms,empty_pool"
	if got != want {
		t.Fatalf("pools = %q, want %q", got, want)
	}
}

func TestParse_PoolSettings(t *testing.T) {
	cfg := Parse(sampleCfg)

	oms, ok := cfg.Pool("http_oms")
	if !ok {
		t.Fatal("http_oms not found")
	}
	if oms.Balance != "roundrobin" {
		t.Errorf("default balance = %q, want roundrobin", oms.Balance)
	}
	if !strings.Contains(oms.HealthCheck, "Host oms.cni.net.id") {
		t.Errorf("health check = %q", oms.HealthCheck)
	}
	if oms.Cookie {
		t.Error("http_oms has no cookie directive")
	}

	https, _ := cfg.Pool("https_oms")
	if https.Balance != "leastconn" {
		t.Errorf("balance = %q, want leastconn", https.Balance)
	}
	if !https.Cookie {
		t.Error("https_oms should report cookie persistence")
	}
}

func TestParse_Members(t *testing.T) {
	cfg := Parse(sampleCfg)
	oms, _ := cfg.Pool("http_oms")
	if len(oms.Members) != 3 {
		t.Fatalf("members = %d, want 3", len(oms.Members))
	}
	m := oms.Members[2]
	if m.Name != "node3" || m.Host != "192.168.200.103" || m.Port != "80" {
		t.Errorf("member = %+v", m)
	}
	if !m.Backup || m.Disabled {
		t.Errorf("node3 flags backup=%v disabled=%v", m.Backup, m.Disabled)
	}
	if m.Indent != "        " {
		t.Errorf("indent = %q", m.Indent)
	}

	https, _ := cfg.Pool("https_oms")
	n1 := https.Members[0]
	if n1.Weight != "" || n1.Maxconn != "" {
		t.Errorf("node01 weight/maxconn should be empty, got %q/%q", n1.Weight, n1.Maxconn)
	}
	if last := n1.Params[len(n1.Params)-1]; last != "oms.cni.net.id" {
		t.Errorf("trailing comment should be stripped, last param = %q", last)
	}
	n2 := https.Members[1]
	if n2.Weight != "50" || n2.Maxconn != "100" || !n2.Disabled {
		t.Errorf("node02 = %+v", n2)
	}
}

func TestParse_KeepsParenthesisedTokensTogether(t *testing.T) {
	cfg := Parse("backend b\n  server s1 10.0.0.1:443 sni str(a b) check\n")
	b, _ := cfg.Pool("b")
	got := strings.Join(b.Members[0].Params, "|")
	if got != "sni|str(a b)|check" {
		t.Errorf("params = %q", got)
	}
}

func TestSplitAddress(t *testing.T) {
	cases := []struct{ in, host, port string }{
		{"10.0.0.1:80", "10.0.0.1", "80"},
		{"10.0.0.1", "10.0.0.1", ""},
		{"app.local:8080", "app.local", "8080"},
		{"[2001:db8::1]:443", "2001:db8::1", "443"},
		{"2001:db8::1", "2001:db8::1", ""},
	}
	for _, c := range cases {
		h, p := splitAddress(c.in)
		if h != c.host || p != c.port {
			t.Errorf("splitAddress(%q) = %q,%q want %q,%q", c.in, h, p, c.host, c.port)
		}
	}
}

func TestNodes_GroupsMembersByHost(t *testing.T) {
	nodes := Parse(sampleCfg).Nodes()
	if len(nodes) != 3 {
		t.Fatalf("nodes = %d, want 3: %+v", len(nodes), nodes)
	}
	if nodes[0].Host != "192.168.200.103" {
		t.Errorf("nodes should be sorted, first = %q", nodes[0].Host)
	}
	var n108 Node
	for _, n := range nodes {
		if n.Host == "192.168.200.108" {
			n108 = n
		}
	}
	if len(n108.Uses) != 2 {
		t.Fatalf(".108 uses = %d, want 2", len(n108.Uses))
	}
	if n108.Uses[1].Pool != "https_oms" || n108.Uses[1].Port != "443" {
		t.Errorf("use = %+v", n108.Uses[1])
	}
}

func TestSuggestName(t *testing.T) {
	cases := []struct {
		members []string
		want    string
	}{
		{[]string{"node01", "node02"}, "node03"},
		{[]string{"node1", "node2", "node3"}, "node4"},
		{[]string{"1dataid-node01", "1dataid-node02"}, "1dataid-node03"},
		{[]string{"web"}, "web2"},
		{nil, "node01"},
		{[]string{"node01", "node09"}, "node10"},
	}
	for _, c := range cases {
		p := Pool{}
		for _, n := range c.members {
			p.Members = append(p.Members, Member{Name: n})
		}
		if got := p.SuggestName(); got != c.want {
			t.Errorf("SuggestName(%v) = %q, want %q", c.members, got, c.want)
		}
	}
}
