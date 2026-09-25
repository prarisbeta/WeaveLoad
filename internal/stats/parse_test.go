package stats

import (
	"fmt"
	"strings"
	"testing"
)

// fixture is a trimmed but real-shaped "show stat" CSV: one frontend, one
// backend with two servers (one UP with a check, one with no check
// configured, matching what haproxy-cni actually reports today).
const fixture = `# pxname,svname,qcur,qmax,scur,smax,slim,stot,bin,bout,dreq,dresp,ereq,econ,eresp,wretr,wredis,status,weight,act,bck,chkfail,chkdown,lastchg,downtime,qlimit,pid,iid,sid,throttle,lbtot,tracked,type,rate,rate_lim,rate_max,check_status,check_code,check_duration,hrsp_1xx,hrsp_2xx,hrsp_3xx,hrsp_4xx,hrsp_5xx,hrsp_other,hanafail,req_rate,req_rate_max,req_tot,cli_abrt,srv_abrt,comp_in,comp_out,comp_byp,comp_rsp,lastsess,last_chk,last_agt,qtime,ctime,rtime,ttime,
http_in,FRONTEND,,,0,5,20000,120,10000,20000,0,0,0,,,,,OPEN,,,,,,,,,1,1,0,,,,0,1,,10,,,,,100,15,0,0,0,0,,,,,,,,,,,,,,,
http_oms,node1,0,0,0,3,,50,5000,9000,,,,0,0,0,0,UP,1,1,0,0,0,120000,0,,1,2,1,,50,,2,0,,2,L7OK,200,3,,,,,,,,,,,,,,,,,,0,"HTTP/1.1 200",,0,0,0,0,
http_oms,node2,0,0,0,1,,10,1000,2000,,,,0,0,0,0,no check,1,1,0,,,,,,1,2,2,,10,,2,0,,0,,,,,,,,,,,,,,,,,,,,,,,,,,
http_oms,BACKEND,0,0,0,4,,60,6000,11000,0,0,,0,0,0,0,UP,,1,0,0,0,120000,0,,1,2,0,,60,,1,0,,2,,,,,,,,,,,,,,,,,,,,,,,,,,
`

func TestServer_IsReadyDrainingMaint(t *testing.T) {
	cases := []struct {
		status              string
		ready, draining, ma bool
	}{
		{"UP", true, false, false},
		{"no check", true, false, false},
		{"DOWN", true, false, false}, // failing its check, but not administratively touched
		{"DOWN (agent)", true, false, false},
		{"DRAIN", false, true, false},
		{"MAINT", false, false, true},
		{"MAINT (via API)", false, false, true},
	}
	for _, c := range cases {
		s := Server{Status: c.status}
		if got := s.IsReady(); got != c.ready {
			t.Errorf("Server{Status:%q}.IsReady() = %v, want %v", c.status, got, c.ready)
		}
		if got := s.IsDraining(); got != c.draining {
			t.Errorf("Server{Status:%q}.IsDraining() = %v, want %v", c.status, got, c.draining)
		}
		if got := s.IsMaint(); got != c.ma {
			t.Errorf("Server{Status:%q}.IsMaint() = %v, want %v", c.status, got, c.ma)
		}
	}
}

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

func TestConnectionsPie_SharesSumToWholeAndAreCumulative(t *testing.T) {
	body := `# pxname,svname,status,weight,check_status,last_chk,scur
quiet,node1,UP,1,L7OK,,10
quiet,BACKEND,UP,,,,10
busy,node1,UP,1,L7OK,,30
busy,node2,UP,1,L7OK,,10
busy,BACKEND,UP,,,,40
`
	snap, err := Parse(body)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	slices := snap.ConnectionsPie()
	if len(slices) != 2 {
		t.Fatalf("slices = %d, want 2", len(slices))
	}
	byName := map[string]PieSlice{}
	for _, s := range slices {
		byName[s.Name] = s
	}
	quiet, busy := byName["quiet"], byName["busy"]
	if quiet.Percent != 20 || busy.Percent != 80 {
		t.Errorf("percents = quiet:%v busy:%v, want 20/80", quiet.Percent, busy.Percent)
	}
	// Slices are ordered busiest-first, so busy (80%) occupies the first
	// cumulative range and quiet (20%) the second.
	if busy.StartPct != 0 || busy.EndPct != 80 {
		t.Errorf("busy cumulative range = %v-%v, want 0-80", busy.StartPct, busy.EndPct)
	}
	if quiet.StartPct != 80 || quiet.EndPct != 100 {
		t.Errorf("quiet cumulative range = %v-%v, want 80-100", quiet.StartPct, quiet.EndPct)
	}
	if quiet.Color == "" || quiet.Color == busy.Color {
		t.Errorf("expected distinct, non-empty colors, got %q and %q", quiet.Color, busy.Color)
	}
}

func TestConnectionsPie_NoSessionsIsAllZeroNotDivideByZero(t *testing.T) {
	snap, _ := Parse(`# pxname,svname,status,weight,check_status,last_chk,scur
http_oms,node1,UP,1,L7OK,,0
http_oms,BACKEND,UP,,,,0
`)
	slices := snap.ConnectionsPie()
	if len(slices) != 1 || slices[0].Percent != 0 {
		t.Errorf("slices = %+v, want one slice at 0%%", slices)
	}
}

func TestConnectionsPie_EmptySnapshotReturnsNoSlices(t *testing.T) {
	var snap Snapshot
	if slices := snap.ConnectionsPie(); len(slices) != 0 {
		t.Errorf("slices = %+v, want none", slices)
	}
}

func TestConnectionsPie_CapsAtEightSlicesPlusOthers(t *testing.T) {
	var body strings.Builder
	body.WriteString("# pxname,svname,status,weight,check_status,last_chk,scur\n")
	// 11 backends: b1=100 down to b10=10 in steps of 10, plus b11=5.
	sessions := []int{100, 90, 80, 70, 60, 50, 40, 30, 20, 10, 5}
	for i, s := range sessions {
		fmt.Fprintf(&body, "b%d,node1,UP,1,L7OK,,%d\n", i+1, s)
		fmt.Fprintf(&body, "b%d,BACKEND,UP,,,,%d\n", i+1, s)
	}
	snap, err := Parse(body.String())
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	slices := snap.ConnectionsPie()
	if len(slices) != 9 {
		t.Fatalf("slices = %d, want 9 (8 busiest + Lainnya)", len(slices))
	}
	for i := 0; i < 8; i++ {
		wantName := fmt.Sprintf("b%d", i+1)
		if slices[i].Name != wantName {
			t.Errorf("slices[%d].Name = %q, want %q", i, slices[i].Name, wantName)
		}
	}
	last := slices[8]
	if last.Name != "Lainnya" || last.Sessions != 20+10+5 {
		t.Errorf("last slice = %+v, want Lainnya with sessions=35 (b9=20 + b10=10 + b11=5)", last)
	}
	if last.EndPct != 100 {
		t.Errorf("last slice EndPct = %v, want 100", last.EndPct)
	}
}

func TestConnectionsByServer_ScalesWithinBackend(t *testing.T) {
	snap, _ := Parse(`# pxname,svname,status,weight,check_status,last_chk,scur
http_oms,node1,UP,1,L7OK,,30
http_oms,node2,UP,1,L7OK,,15
http_oms,BACKEND,UP,,,,45
`)
	b, ok := snap.Backend("http_oms")
	if !ok {
		t.Fatal("backend not found")
	}
	bars := b.ConnectionsByServer()
	if len(bars) != 2 {
		t.Fatalf("bars = %d, want 2", len(bars))
	}
	if bars[0].Sessions != 30 || bars[0].Percent != 100 {
		t.Errorf("node1 = %+v, want sessions=30 percent=100", bars[0])
	}
	if bars[1].Sessions != 15 || bars[1].Percent != 50 {
		t.Errorf("node2 = %+v, want sessions=15 percent=50", bars[1])
	}
}
