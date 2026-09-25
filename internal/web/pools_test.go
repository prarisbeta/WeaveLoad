package web

import (
	"errors"
	"html/template"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"haproxy-gui/internal/cfgfile"
	"haproxy-gui/internal/haproxycfg"
	"haproxy-gui/internal/store"
)

const poolCfg = `global
    daemon

backend web
    cookie SERVERID insert indirect nocache
    server node01 10.0.0.1:443 cookie node01 ssl verify none check
    server node02 10.0.0.2:443 cookie node02 ssl verify none check

backend api
    server a1 10.0.0.1:8080 check
`

const poolStats = `# pxname,svname,status,weight,check_status,last_chk,scur
web,node01,UP,1,L7OK,,3
web,node02,MAINT,1,L7OK,,0
web,BACKEND,UP,,,,3
api,a1,DRAIN,1,L7OK,,2
api,BACKEND,UP,,,,2
`

func poolTemplates(t *testing.T) *template.Template {
	t.Helper()
	return mustParse(t, `
{{define "pools.html"}}{{range .Pools}}[{{.Name}} {{.Up}}/{{len .Members}} s={{.Sessions}}]{{end}}ERR={{.StatsErr}}{{end}}
{{define "pool_detail.html"}}DETAIL {{.Pool.Name}} next={{.Suggested}} prefill={{.Prefill}} admin={{.CanAdmin}} {{template "pool_members.html" .}}{{end}}
{{define "pool_members.html"}}{{range .Pool.Members}}({{.Name}}:{{.Live.Status}}){{end}}{{end}}
{{define "nodes.html"}}{{range .Nodes}}[{{.Host}} {{.Up}}/{{.Total}}]{{end}}{{end}}
{{define "pool_preview.html"}}LINE={{.Line}} OK={{.Validation.OK}} action={{.Action}} current={{.CurrentName}}{{end}}
{{define "pool_result.html"}}RESULT ok={{.OK}} msg={{.Message}}{{end}}
{{define "pool_edit_form.html"}}EDITFORM name={{.Member.Name}} host={{.Member.Host}} port={{.Member.Port}} weight={{.Member.Weight}}{{end}}
{{define "pool_new.html"}}NEWPOOLFORM{{end}}
{{define "pool_new_preview.html"}}NEWPOOL block={{.Block}} OK={{.Validation.OK}}{{end}}
{{define "rate_limit_preview.html"}}RATELIMIT block={{.Block}} OK={{.Validation.OK}} rps={{.Spec.RPS}} action={{.Spec.Action}}{{end}}
`)
}

func newPoolService(t *testing.T, cs *fakeConfigStore, audit *fakeAudit) *PoolService {
	t.Helper()
	return &PoolService{Config: cs, Stats: fakeStats{body: poolStats}, Audit: audit, Templates: poolTemplates(t)}
}

func adminReq(method, target string, form url.Values) *http.Request {
	var req *http.Request
	if form != nil {
		req = httptest.NewRequest(method, target, strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	} else {
		req = httptest.NewRequest(method, target, nil)
	}
	return withUser(req, store.User{Email: "admin@example.com", Role: store.RolePlatformAdmin})
}

func serve(h http.Handler, pattern string, req *http.Request) *httptest.ResponseRecorder {
	mux := http.NewServeMux()
	mux.Handle(pattern, h)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	return rec
}

func TestPoolsHandler_ListsPoolsWithLiveCounts(t *testing.T) {
	svc := newPoolService(t, &fakeConfigStore{active: poolCfg}, &fakeAudit{})
	rec := serve(&PoolsHandler{svc}, "GET /pools", adminReq(http.MethodGet, "/pools", nil))
	body := rec.Body.String()
	if !strings.Contains(body, "[web 1/2 s=3]") || !strings.Contains(body, "[api 0/1 s=2]") {
		t.Errorf("body = %s", body)
	}
}

func TestPoolsHandler_StatsFailureStillRenders(t *testing.T) {
	svc := newPoolService(t, &fakeConfigStore{active: poolCfg}, &fakeAudit{})
	svc.Stats = fakeStats{err: errors.New("socket down")}
	rec := serve(&PoolsHandler{svc}, "GET /pools", adminReq(http.MethodGet, "/pools", nil))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "socket down") {
		t.Errorf("code=%d body=%s", rec.Code, rec.Body.String())
	}
}

func TestPoolDetailHandler(t *testing.T) {
	svc := newPoolService(t, &fakeConfigStore{active: poolCfg}, &fakeAudit{})
	rec := serve(&PoolDetailHandler{svc}, "GET /pools/{name}", adminReq(http.MethodGet, "/pools/web?node=10.9.9.9", nil))
	body := rec.Body.String()
	for _, want := range []string{"DETAIL web", "next=node03", "prefill=10.9.9.9", "admin=true", "(node02:MAINT)"} {
		if !strings.Contains(body, want) {
			t.Errorf("missing %q in %s", want, body)
		}
	}

	req := adminReq(http.MethodGet, "/pools/web", nil)
	req.Header.Set("HX-Request", "true")
	rec = serve(&PoolDetailHandler{svc}, "GET /pools/{name}", req)
	if strings.Contains(rec.Body.String(), "DETAIL") {
		t.Error("htmx request should get only the members fragment")
	}

	rec = serve(&PoolDetailHandler{svc}, "GET /pools/{name}", adminReq(http.MethodGet, "/pools/nope", nil))
	if rec.Code != http.StatusNotFound {
		t.Errorf("unknown pool code = %d", rec.Code)
	}
}

func TestNodesHandler(t *testing.T) {
	svc := newPoolService(t, &fakeConfigStore{active: poolCfg}, &fakeAudit{})
	rec := serve(&NodesHandler{svc}, "GET /nodes", adminReq(http.MethodGet, "/nodes", nil))
	body := rec.Body.String()
	if !strings.Contains(body, "[10.0.0.1 1/2]") || !strings.Contains(body, "[10.0.0.2 0/1]") {
		t.Errorf("body = %s", body)
	}
}

func TestNodeAddRedirect(t *testing.T) {
	rec := httptest.NewRecorder()
	NodeAddRedirect(rec, httptest.NewRequest(http.MethodGet, "/nodes/add-to-pool?pool=web&node=10.0.0.5", nil))
	if loc := rec.Header().Get("Location"); loc != "/pools/web?node=10.0.0.5" {
		t.Errorf("Location = %q", loc)
	}
	rec = httptest.NewRecorder()
	NodeAddRedirect(rec, httptest.NewRequest(http.MethodGet, "/nodes/add-to-pool?pool=../x", nil))
	if rec.Code != http.StatusBadRequest {
		t.Errorf("bad pool code = %d", rec.Code)
	}
}

func memberForm() url.Values {
	return url.Values{"name": {"node03"}, "host": {"10.0.0.3"}, "port": {"443"}, "clone_from": {"node01"}}
}

func TestPoolMemberPreview_ShowsLineAndValidates(t *testing.T) {
	cs := &fakeConfigStore{active: poolCfg, validateRes: cfgfile.ValidateResult{OK: true}}
	svc := newPoolService(t, cs, &fakeAudit{})
	rec := serve(&PoolMemberPreview{svc}, "POST /api/pools/{name}/members/preview",
		adminReq(http.MethodPost, "/api/pools/web/members/preview", memberForm()))
	want := "LINE=server node03 10.0.0.3:443 cookie node03 ssl verify none check OK=true action= current="
	if rec.Body.String() != want {
		t.Errorf("body = %q", rec.Body.String())
	}
	if cs.appliedPath != "" || len(cs.savedDrafts) != 0 {
		t.Error("preview must not stage or apply anything")
	}
}

func TestPoolMemberPreview_InvalidInputShowsReason(t *testing.T) {
	svc := newPoolService(t, &fakeConfigStore{active: poolCfg}, &fakeAudit{})
	form := memberForm()
	form.Set("port", "99999")
	rec := serve(&PoolMemberPreview{svc}, "POST /api/pools/{name}/members/preview",
		adminReq(http.MethodPost, "/api/pools/web/members/preview", form))
	if !strings.Contains(rec.Body.String(), "RESULT ok=false") || !strings.Contains(rec.Body.String(), "port") {
		t.Errorf("body = %q", rec.Body.String())
	}
}

func TestPoolMemberAdd_AppliesAndAudits(t *testing.T) {
	cs := &fakeConfigStore{
		active: poolCfg, validateRes: cfgfile.ValidateResult{OK: true},
		draftPath: "/staging/d.cfg", applyRes: cfgfile.ApplyResult{OK: true},
	}
	audit := &fakeAudit{}
	svc := newPoolService(t, cs, audit)
	rec := serve(&PoolMemberAdd{svc}, "POST /api/pools/{name}/members/add",
		adminReq(http.MethodPost, "/api/pools/web/members/add", memberForm()))

	if !strings.Contains(rec.Body.String(), "RESULT ok=true") {
		t.Fatalf("body = %q", rec.Body.String())
	}
	if rec.Header().Get("HX-Trigger") != memberChangedEvent {
		t.Error("success should trigger a members refresh")
	}
	if len(cs.savedDrafts) != 1 || !strings.Contains(cs.savedDrafts[0], "server node03 10.0.0.3:443") {
		t.Errorf("draft = %v", cs.savedDrafts)
	}
	if cs.appliedPath != "/staging/d.cfg" {
		t.Errorf("applied = %q", cs.appliedPath)
	}
	if len(audit.entries) != 1 || audit.entries[0].Action != "pool.member.add" || audit.entries[0].Target != "web/node03" {
		t.Errorf("audit = %+v", audit.entries)
	}
}

func TestPoolMemberAdd_InvalidConfigNotApplied(t *testing.T) {
	cs := &fakeConfigStore{active: poolCfg, validateRes: cfgfile.ValidateResult{OK: false, Output: "bad"}}
	audit := &fakeAudit{}
	svc := newPoolService(t, cs, audit)
	rec := serve(&PoolMemberAdd{svc}, "POST /api/pools/{name}/members/add",
		adminReq(http.MethodPost, "/api/pools/web/members/add", memberForm()))
	if !strings.Contains(rec.Body.String(), "RESULT ok=false") || cs.appliedPath != "" {
		t.Errorf("body=%q applied=%q", rec.Body.String(), cs.appliedPath)
	}
	if len(audit.entries) != 1 || !strings.HasPrefix(audit.entries[0].Detail, "rejected") {
		t.Errorf("audit = %+v", audit.entries)
	}
}

func TestPoolMemberAdd_ApplyFailureReportsRollback(t *testing.T) {
	cs := &fakeConfigStore{
		active: poolCfg, validateRes: cfgfile.ValidateResult{OK: true},
		draftPath: "/staging/d.cfg", applyRes: cfgfile.ApplyResult{OK: false, Output: "reload failed"},
	}
	svc := newPoolService(t, cs, &fakeAudit{})
	rec := serve(&PoolMemberAdd{svc}, "POST /api/pools/{name}/members/add",
		adminReq(http.MethodPost, "/api/pools/web/members/add", memberForm()))
	if !strings.Contains(rec.Body.String(), "RESULT ok=false") || rec.Header().Get("HX-Trigger") != "" {
		t.Errorf("body=%q", rec.Body.String())
	}
}

func TestPoolMemberAdd_AuditFailureIsAnError(t *testing.T) {
	cs := &fakeConfigStore{
		active: poolCfg, validateRes: cfgfile.ValidateResult{OK: true},
		draftPath: "/staging/d.cfg", applyRes: cfgfile.ApplyResult{OK: true},
	}
	svc := newPoolService(t, cs, &fakeAudit{failErr: errors.New("disk full")})
	rec := serve(&PoolMemberAdd{svc}, "POST /api/pools/{name}/members/add",
		adminReq(http.MethodPost, "/api/pools/web/members/add", memberForm()))
	if rec.Code != http.StatusInternalServerError {
		t.Errorf("code = %d", rec.Code)
	}
}

func TestPoolMemberRemove_RequiresMaintOrEmptyDrain(t *testing.T) {
	ok := func() *fakeConfigStore {
		return &fakeConfigStore{
			active: poolCfg, validateRes: cfgfile.ValidateResult{OK: true},
			draftPath: "/staging/d.cfg", applyRes: cfgfile.ApplyResult{OK: true},
		}
	}
	remove := func(cs *fakeConfigStore, pool, server string) string {
		svc := newPoolService(t, cs, &fakeAudit{})
		rec := serve(&PoolMemberRemove{svc}, "POST /api/pools/{name}/members/remove",
			adminReq(http.MethodPost, "/api/pools/"+pool+"/members/remove", url.Values{"server": {server}}))
		return rec.Body.String()
	}

	// UP member: refused, nothing applied.
	cs := ok()
	if body := remove(cs, "web", "node01"); !strings.Contains(body, "ok=false") || cs.appliedPath != "" {
		t.Errorf("UP member removed: %q", body)
	}

	// DRAIN with sessions: refused.
	cs = ok()
	cs.active += "    server a2 10.0.0.4:8080 check\n"
	if body := remove(cs, "api", "a1"); !strings.Contains(body, "masih melayani") {
		t.Errorf("draining member with sessions removed: %q", body)
	}

	// MAINT member: removed.
	cs = ok()
	body := remove(cs, "web", "node02")
	if !strings.Contains(body, "ok=true") {
		t.Fatalf("MAINT member not removed: %q", body)
	}
	if strings.Contains(cs.savedDrafts[0], "node02") {
		t.Error("node02 still in draft")
	}
}

func TestPoolMemberRemove_StatsDownRefuses(t *testing.T) {
	cs := &fakeConfigStore{active: poolCfg}
	svc := newPoolService(t, cs, &fakeAudit{})
	svc.Stats = fakeStats{err: errors.New("socket down")}
	rec := serve(&PoolMemberRemove{svc}, "POST /api/pools/{name}/members/remove",
		adminReq(http.MethodPost, "/api/pools/web/members/remove", url.Values{"server": {"node02"}}))
	if !strings.Contains(rec.Body.String(), "ok=false") || cs.appliedPath != "" {
		t.Errorf("body = %q", rec.Body.String())
	}
}

func TestPoolMemberEditForm_PrefillsCurrentValues(t *testing.T) {
	svc := newPoolService(t, &fakeConfigStore{active: poolCfg}, &fakeAudit{})
	rec := serve(&PoolMemberEditForm{svc}, "GET /pools/{name}/members/{member}/edit",
		adminReq(http.MethodGet, "/pools/web/members/node01/edit", nil))
	want := "EDITFORM name=node01 host=10.0.0.1 port=443 weight="
	if rec.Body.String() != want {
		t.Errorf("body = %q, want %q", rec.Body.String(), want)
	}
}

func TestPoolMemberEditForm_UnknownMember_404(t *testing.T) {
	svc := newPoolService(t, &fakeConfigStore{active: poolCfg}, &fakeAudit{})
	rec := serve(&PoolMemberEditForm{svc}, "GET /pools/{name}/members/{member}/edit",
		adminReq(http.MethodGet, "/pools/web/members/ghost/edit", nil))
	if rec.Code != http.StatusNotFound {
		t.Errorf("code = %d", rec.Code)
	}
}

func editForm() url.Values {
	return url.Values{"current_name": {"node01"}, "name": {"node01"}, "host": {"10.0.0.1"}, "port": {"443"}, "weight": {"75"}}
}

func TestPoolMemberEditPreview_ShowsLineAndValidates(t *testing.T) {
	cs := &fakeConfigStore{active: poolCfg, validateRes: cfgfile.ValidateResult{OK: true}}
	svc := newPoolService(t, cs, &fakeAudit{})
	rec := serve(&PoolMemberEditPreview{svc}, "POST /api/pools/{name}/members/edit/preview",
		adminReq(http.MethodPost, "/api/pools/web/members/edit/preview", editForm()))
	want := "LINE=server node01 10.0.0.1:443 weight 75 cookie node01 ssl verify none check OK=true action=edit current=node01"
	if rec.Body.String() != want {
		t.Errorf("body = %q", rec.Body.String())
	}
	if cs.appliedPath != "" || len(cs.savedDrafts) != 0 {
		t.Error("preview must not stage or apply anything")
	}
}

func TestPoolMemberEditPreview_UnknownMemberShowsReason(t *testing.T) {
	svc := newPoolService(t, &fakeConfigStore{active: poolCfg}, &fakeAudit{})
	form := editForm()
	form.Set("current_name", "ghost")
	rec := serve(&PoolMemberEditPreview{svc}, "POST /api/pools/{name}/members/edit/preview",
		adminReq(http.MethodPost, "/api/pools/web/members/edit/preview", form))
	if !strings.Contains(rec.Body.String(), "RESULT ok=false") {
		t.Errorf("body = %q", rec.Body.String())
	}
}

func TestPoolMemberEditApply_AppliesAndAudits(t *testing.T) {
	cs := &fakeConfigStore{
		active: poolCfg, validateRes: cfgfile.ValidateResult{OK: true},
		draftPath: "/staging/d.cfg", applyRes: cfgfile.ApplyResult{OK: true},
	}
	audit := &fakeAudit{}
	svc := newPoolService(t, cs, audit)
	rec := serve(&PoolMemberEditApply{svc}, "POST /api/pools/{name}/members/edit/apply",
		adminReq(http.MethodPost, "/api/pools/web/members/edit/apply", editForm()))

	if !strings.Contains(rec.Body.String(), "RESULT ok=true") {
		t.Fatalf("body = %q", rec.Body.String())
	}
	if rec.Header().Get("HX-Trigger") != memberChangedEvent {
		t.Error("success should trigger a members refresh")
	}
	if len(cs.savedDrafts) != 1 || !strings.Contains(cs.savedDrafts[0], "weight 75") {
		t.Errorf("draft = %v", cs.savedDrafts)
	}
	if len(audit.entries) != 1 || audit.entries[0].Action != "pool.member.edit" || audit.entries[0].Target != "web/node01" {
		t.Errorf("audit = %+v", audit.entries)
	}
}

func TestPoolMemberEditApply_RenamesMember(t *testing.T) {
	cs := &fakeConfigStore{
		active: poolCfg, validateRes: cfgfile.ValidateResult{OK: true},
		draftPath: "/staging/d.cfg", applyRes: cfgfile.ApplyResult{OK: true},
	}
	svc := newPoolService(t, cs, &fakeAudit{})
	form := editForm()
	form.Set("name", "node01b")
	rec := serve(&PoolMemberEditApply{svc}, "POST /api/pools/{name}/members/edit/apply",
		adminReq(http.MethodPost, "/api/pools/web/members/edit/apply", form))
	if !strings.Contains(rec.Body.String(), "RESULT ok=true") {
		t.Fatalf("body = %q", rec.Body.String())
	}
	if len(cs.savedDrafts) != 1 || !strings.Contains(cs.savedDrafts[0], "server node01b") {
		t.Errorf("draft = %v", cs.savedDrafts)
	}
}

func newPoolForm() url.Values {
	return url.Values{"pool_name": {"http_new"}, "name": {"n1"}, "host": {"10.0.0.9"}, "port": {"80"}}
}

func TestPoolNewFormHandler_Renders(t *testing.T) {
	svc := newPoolService(t, &fakeConfigStore{active: poolCfg}, &fakeAudit{})
	rec := serve(&PoolNewFormHandler{svc}, "GET /pools/new", adminReq(http.MethodGet, "/pools/new", nil))
	if rec.Code != http.StatusOK || rec.Body.String() != "NEWPOOLFORM" {
		t.Errorf("code=%d body=%q", rec.Code, rec.Body.String())
	}
}

func TestPoolNewPreview_ShowsBlockAndValidates(t *testing.T) {
	cs := &fakeConfigStore{active: poolCfg, validateRes: cfgfile.ValidateResult{OK: true}}
	svc := newPoolService(t, cs, &fakeAudit{})
	rec := serve(&PoolNewPreview{svc}, "POST /api/pools/new/preview",
		adminReq(http.MethodPost, "/api/pools/new/preview", newPoolForm()))
	if !strings.Contains(rec.Body.String(), "backend http_new") || !strings.Contains(rec.Body.String(), "OK=true") {
		t.Errorf("body = %q", rec.Body.String())
	}
	if cs.appliedPath != "" {
		t.Error("preview must not apply anything")
	}
}

func TestPoolNewPreview_DuplicateNameShowsReason(t *testing.T) {
	svc := newPoolService(t, &fakeConfigStore{active: poolCfg}, &fakeAudit{})
	form := newPoolForm()
	form.Set("pool_name", "web") // already exists in poolCfg
	rec := serve(&PoolNewPreview{svc}, "POST /api/pools/new/preview",
		adminReq(http.MethodPost, "/api/pools/new/preview", form))
	if !strings.Contains(rec.Body.String(), "RESULT ok=false") {
		t.Errorf("body = %q", rec.Body.String())
	}
}

func TestPoolNewApply_CreatesAndAudits(t *testing.T) {
	cs := &fakeConfigStore{
		active: poolCfg, validateRes: cfgfile.ValidateResult{OK: true},
		draftPath: "/staging/d.cfg", applyRes: cfgfile.ApplyResult{OK: true},
	}
	audit := &fakeAudit{}
	svc := newPoolService(t, cs, audit)
	rec := serve(&PoolNewApply{svc}, "POST /api/pools/new/apply",
		adminReq(http.MethodPost, "/api/pools/new/apply", newPoolForm()))

	if !strings.Contains(rec.Body.String(), "RESULT ok=true") {
		t.Fatalf("body = %q", rec.Body.String())
	}
	if len(cs.savedDrafts) != 1 || !strings.Contains(cs.savedDrafts[0], "backend http_new") {
		t.Errorf("draft = %v", cs.savedDrafts)
	}
	if len(audit.entries) != 1 || audit.entries[0].Action != "pool.create" || audit.entries[0].Target != "http_new" {
		t.Errorf("audit = %+v", audit.entries)
	}
}

func TestPoolNewApply_InvalidConfigNotApplied(t *testing.T) {
	cs := &fakeConfigStore{active: poolCfg, validateRes: cfgfile.ValidateResult{OK: false, Output: "bad"}}
	audit := &fakeAudit{}
	svc := newPoolService(t, cs, audit)
	rec := serve(&PoolNewApply{svc}, "POST /api/pools/new/apply",
		adminReq(http.MethodPost, "/api/pools/new/apply", newPoolForm()))
	if !strings.Contains(rec.Body.String(), "RESULT ok=false") || cs.appliedPath != "" {
		t.Errorf("body=%q applied=%q", rec.Body.String(), cs.appliedPath)
	}
}

func rateLimitForm() url.Values {
	return url.Values{"rps": {"20"}, "action": {"deny"}}
}

func TestRateLimitPreview_ShowsBlockAndValidates(t *testing.T) {
	cs := &fakeConfigStore{active: poolCfg, validateRes: cfgfile.ValidateResult{OK: true}}
	svc := newPoolService(t, cs, &fakeAudit{})
	rec := serve(&RateLimitPreview{svc}, "POST /api/pools/{name}/rate-limit/preview",
		adminReq(http.MethodPost, "/api/pools/web/rate-limit/preview", rateLimitForm()))
	body := rec.Body.String()
	if !strings.Contains(body, "haproxy-gui:rate-limit rps=20 action=deny") || !strings.Contains(body, "OK=true") {
		t.Errorf("body = %q", body)
	}
	if cs.appliedPath != "" {
		t.Error("preview must not apply anything")
	}
}

func TestRateLimitPreview_UnknownPoolShowsReason(t *testing.T) {
	svc := newPoolService(t, &fakeConfigStore{active: poolCfg}, &fakeAudit{})
	rec := serve(&RateLimitPreview{svc}, "POST /api/pools/{name}/rate-limit/preview",
		adminReq(http.MethodPost, "/api/pools/nope/rate-limit/preview", rateLimitForm()))
	if !strings.Contains(rec.Body.String(), "RESULT ok=false") {
		t.Errorf("body = %q", rec.Body.String())
	}
}

func TestRateLimitApply_AppliesAndAudits(t *testing.T) {
	cs := &fakeConfigStore{
		active: poolCfg, validateRes: cfgfile.ValidateResult{OK: true},
		draftPath: "/staging/d.cfg", applyRes: cfgfile.ApplyResult{OK: true},
	}
	audit := &fakeAudit{}
	svc := newPoolService(t, cs, audit)
	rec := serve(&RateLimitApply{svc}, "POST /api/pools/{name}/rate-limit/apply",
		adminReq(http.MethodPost, "/api/pools/web/rate-limit/apply", rateLimitForm()))

	if !strings.Contains(rec.Body.String(), "RESULT ok=true") {
		t.Fatalf("body = %q", rec.Body.String())
	}
	if len(cs.savedDrafts) != 1 || !strings.Contains(cs.savedDrafts[0], "haproxy-gui:rate-limit rps=20 action=deny") {
		t.Errorf("draft = %v", cs.savedDrafts)
	}
	if len(audit.entries) != 1 || audit.entries[0].Action != "pool.rate_limit.set" || audit.entries[0].Target != "web" {
		t.Errorf("audit = %+v", audit.entries)
	}
}

func TestRateLimitRemove_RemovesAndAudits(t *testing.T) {
	withLimit, _, err := haproxycfg.SetRateLimit(poolCfg, "web", haproxycfg.RateLimitSpec{RPS: 20, Action: "deny"})
	if err != nil {
		t.Fatal(err)
	}
	cs := &fakeConfigStore{
		active: withLimit, validateRes: cfgfile.ValidateResult{OK: true},
		draftPath: "/staging/d.cfg", applyRes: cfgfile.ApplyResult{OK: true},
	}
	audit := &fakeAudit{}
	svc := newPoolService(t, cs, audit)
	rec := serve(&RateLimitRemove{svc}, "POST /api/pools/{name}/rate-limit/remove",
		adminReq(http.MethodPost, "/api/pools/web/rate-limit/remove", nil))

	if !strings.Contains(rec.Body.String(), "RESULT ok=true") {
		t.Fatalf("body = %q", rec.Body.String())
	}
	if len(cs.savedDrafts) != 1 || strings.Contains(cs.savedDrafts[0], "haproxy-gui:rate-limit") {
		t.Errorf("draft still contains the rate-limit block: %v", cs.savedDrafts)
	}
	if len(audit.entries) != 1 || audit.entries[0].Action != "pool.rate_limit.remove" {
		t.Errorf("audit = %+v", audit.entries)
	}
}

func TestRateLimitRemove_ErrorsWhenNoneConfigured(t *testing.T) {
	cs := &fakeConfigStore{active: poolCfg}
	svc := newPoolService(t, cs, &fakeAudit{})
	rec := serve(&RateLimitRemove{svc}, "POST /api/pools/{name}/rate-limit/remove",
		adminReq(http.MethodPost, "/api/pools/web/rate-limit/remove", nil))
	if !strings.Contains(rec.Body.String(), "RESULT ok=false") || cs.appliedPath != "" {
		t.Errorf("body=%q applied=%q", rec.Body.String(), cs.appliedPath)
	}
}
