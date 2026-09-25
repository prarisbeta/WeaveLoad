package web

import (
	"errors"
	"html/template"
	"net/http"
	"os"
	"time"

	"haproxy-gui/internal/haproxylog"
)

// LogHandler serves the traffic log viewer: the raw HAProxy access log,
// optionally filtered to one day and/or a keyword. Reachable behind
// auth.RequireRole(store.RoleOperator) — same sensitivity level as the
// audit log, since request logs can contain client IPs and URLs.
type LogHandler struct {
	Path      string
	Templates *template.Template
}

func (h *LogHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	dateParam := q.Get("date")
	keyword := q.Get("q")

	var date time.Time
	if dateParam != "" {
		d, err := time.ParseInLocation("2006-01-02", dateParam, time.Local)
		if err != nil {
			http.Error(w, "Format tanggal tidak dikenali, gunakan YYYY-MM-DD.", http.StatusBadRequest)
			return
		}
		date = d
	}

	lines, err := haproxylog.Read(h.Path, haproxylog.Filter{Date: date, Keyword: keyword})
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			http.Error(w, "Berkas log belum ditemukan di server. Hubungi administrator untuk memastikan lokasinya sudah benar.", http.StatusInternalServerError)
			return
		}
		http.Error(w, "Log gagal dibaca: "+err.Error(), http.StatusInternalServerError)
		return
	}

	renderTemplate(w, h.Templates, "logs.html", struct {
		Chrome
		Lines   []haproxylog.Line
		Date    string
		Keyword string
		Today   string
	}{
		Chrome:  NewChrome(r, "logs"),
		Lines:   lines,
		Date:    dateParam,
		Keyword: keyword,
		Today:   time.Now().Format("2006-01-02"),
	})
}
