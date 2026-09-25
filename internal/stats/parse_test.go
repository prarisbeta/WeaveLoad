package stats

import "testing"

// fixture is a trimmed but real-shaped "show stat" CSV: one frontend, one
// backend with two servers (one UP with a check, one with no check
// configured, matching what haproxy-cni actually reports today).
const fixture = `# pxname,svname,qcur,qmax,scur,smax,slim,stot,bin,bout,dreq,dresp,ereq,econ,eresp,wretr,wredis,status,weight,act,bck,chkfail,chkdown,lastchg,downtime,qlimit,pid,iid,sid,throttle,lbtot,tracked,type,rate,rate_lim,rate_max,check_status,check_code,check_duration,hrsp_1xx,hrsp_2xx,hrsp_3xx,hrsp_4xx,hrsp_5xx,hrsp_other,hanafail,req_rate,req_rate_max,req_tot,cli_abrt,srv_abrt,comp_in,comp_out,comp_byp,comp_rsp,lastsess,last_chk,last_agt,qtime,ctime,rtime,ttime,
http_in,FRONTEND,,,0,5,20000,120,10000,20000,0,0,0,,,,,OPEN,,,,,,,,,1,1,0,,,,0,1,,10,,,,,100,15,0,0,0,0,,,,,,,,,,,,,,,
http_oms,node1,0,0,0,3,,50,5000,9000,,,,0,0,0,0,UP,1,1,0,0,0,120000,0,,1,2,1,,50,,2,0,,2,L7OK,200,3,,,,,,,,,,,,,,,,,,0,"HTTP/1.1 200",,0,0,0,0,
http_oms,node2,0,0,0,1,,10,1000,2000,,,,0,0,0,0,no check,1,1,0,,,,,,1,2,2,,10,,2,0,,0,,,,,,,,,,,,,,,,,,,,,,,,,,
http_oms,BACKEND,0,0,0,4,,60,6000,11000,0,0,,0,0,0,0,UP,,1,0,0,0,120000,0,,1,2,0,,60,,1,0,,2,,,,,,,,,,,,,,,,,,,,,,,,,,
`

func TestParse_Frontend(t *testing.T) {
	snap, err := Parse(fixture)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(snap.Frontends) != 1 {
		t.Fatalf("frontends = %d, want 1", len(snap.Frontends))
	}
	if snap.Frontends[0].Name != "http_in" || snap.Frontends[0].Status != "OPEN" {
		t.Errorf("frontend = %+v", snap.Frontends[0])
	}
}

func TestParse_BackendWithServers(t *testing.T) {
	snap, err := Parse(fixture)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	b, ok := snap.Backend("http_oms")
	if !ok {
		t.Fatal("backend http_oms not found")
	}
	if b.Status != "UP" {
		t.Errorf("backend status = %q, want UP", b.Status)
	}
	if len(b.Servers) != 2 {
		t.Fatalf("servers = %d, want 2", len(b.Servers))
	}

	node1 := b.Servers[0]
	if node1.Name != "node1" || node1.Status != "UP" || node1.CheckStatus != "L7OK" {
		t.Errorf("node1 = %+v", node1)
	}
	if !node1.Up() || node1.Down() {
		t.Errorf("node1.Up()=%v Down()=%v, want true/false", node1.Up(), node1.Down())
	}

	node2 := b.Servers[1]
	if node2.Status != "no check" {
		t.Errorf("node2 status = %q, want %q", node2.Status, "no check")
	}
	if !node2.Up() {
		t.Error("a server with 'no check' status should count as Up()")
	}
}

func TestParse_DownServer(t *testing.T) {
	body := `# pxname,svname,status,weight,check_status,last_chk,scur
https_ixcni,node01,DOWN,1,L7STS,Layer7 wrong status,0
https_ixcni,BACKEND,UP,,,,0
`
	snap, err := Parse(body)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	b, _ := snap.Backend("https_ixcni")
	if len(b.Servers) != 1 || !b.Servers[0].Down() {
		t.Errorf("servers = %+v, want one DOWN server", b.Servers)
	}
}

func TestParse_MissingRequiredColumn(t *testing.T) {
	_, err := Parse("# pxname,svname\nfoo,BACKEND\n")
	if err == nil {
		t.Fatal("expected error for missing required column")
	}
}

func TestParse_EmptyInput(t *testing.T) {
	if _, err := Parse(""); err == nil {
		t.Fatal("expected error for empty input")
	}
}

func TestBackend_NotFound(t *testing.T) {
	snap, _ := Parse(fixture)
	if _, ok := snap.Backend("does_not_exist"); ok {
		t.Error("expected ok=false for unknown backend")
	}
}

func TestSummary_CountsAcrossFixture(t *testing.T) {
	snap, _ := Parse(fixture)
	sum := snap.Summary()
	if sum.FrontendsUp != 1 || sum.FrontendsTotal != 1 {
		t.Errorf("frontends up/total = %d/%d, want 1/1", sum.FrontendsUp, sum.FrontendsTotal)
	}
	if sum.BackendsUp != 1 || sum.BackendsTotal != 1 {
		t.Errorf("backends up/total = %d/%d, want 1/1", sum.BackendsUp, sum.BackendsTotal)
	}
	if sum.ServersTotal != 2 || sum.ServersDown != 0 {
		t.Errorf("servers total/down = %d/%d, want 2/0", sum.ServersTotal, sum.ServersDown)
	}
	if sum.Sessions != 0 {
		t.Errorf("sessions = %d, want 0", sum.Sessions)
	}
	if !sum.Healthy() {
		t.Error("expected Healthy() true for an all-UP fixture")
	}
}

func TestSummary_UnhealthyWhenAServerIsDown(t *testing.T) {
	body := `# pxname,svname,status,weight,check_status,last_chk,scur
https_ixcni,node01,DOWN,1,L7STS,Layer7 wrong status,0
https_ixcni,BACKEND,UP,,,,0
`
	snap, _ := Parse(body)
	sum := snap.Summary()
	if sum.ServersDown != 1 {
		t.Errorf("servers down = %d, want 1", sum.ServersDown)
	}
	if sum.Healthy() {
		t.Error("expected Healthy() false when a server is down")
	}
}
