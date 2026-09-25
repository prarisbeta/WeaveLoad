package web

import (
	"bufio"
	"fmt"
	"html/template"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"haproxy-gui/internal/auth"
	"haproxy-gui/internal/store"
)

// MapRuntime is the subset of *runtime.Client the ACL/map handlers need.
type MapRuntime interface {
	AddMapEntry(mapFile, key, value string) error
	SetMapEntry(mapFile, key, value string) error
	DelMapEntry(mapFile, key string) error
}

// MapFile describes one managed map/ACL list file this app knows how to
// edit (host routing maps, the stats admin_allow.lst, etc).
type MapFile struct {
	// Label shown in the UI, e.g. "HTTP host routing".
	Label string
	// Path on disk, must be absolute; only files explicitly listed in
	// AclHandler.Files are ever writable through this UI.
	Path string
	// HasValue is true for "key value" maps (host routing) and false for
	// plain allow/deny lists (admin_allow.lst, https_redirect.lst).
	HasValue bool
}

// AclHandler lists and edits the map/ACL files this instance manages. Every
// write appends to the runtime socket first (so it takes effect
// immediately) and only then persists to the file, matching the pattern
// already used operationally on haproxy-cni: a runtime-only change survives
// until the next reload, but is lost unless also written to disk.
type AclHandler struct {
	Files     []MapFile
	Runtime   MapRuntime
	Audit     AuditRecorder
	Templates *template.Template
}

func (h *AclHandler) findFile(path string) (MapFile, bool) {
	for _, f := range h.Files {
		if f.Path == path {
			return f, true
		}
	}
	return MapFile{}, false
}

type mapEntry struct {
	Key   string
	Value string
}

func readMapFile(path string, hasValue bool) ([]mapEntry, error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer f.Close()

	var out []mapEntry
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if hasValue {
			fields := strings.Fields(line)
			if len(fields) < 2 {
				continue
			}
			out = append(out, mapEntry{Key: fields[0], Value: strings.Join(fields[1:], " ")})
		} else {
			out = append(out, mapEntry{Key: line})
		}
	}
	return out, sc.Err()
}

func (h *AclHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	type fileView struct {
		MapFile
		Entries []mapEntry
	}
	var views []fileView
	for _, f := range h.Files {
		entries, err := readMapFile(f.Path, f.HasValue)
		if err != nil {
			http.Error(w, fmt.Sprintf("failed to read %s: %v", f.Path, err), http.StatusInternalServerError)
			return
		}
		views = append(views, fileView{MapFile: f, Entries: entries})
	}
	data := struct {
		Chrome
		Files []fileView
	}{Chrome: NewChrome(r, "acl"), Files: views}

	if isHTMXRequest(r) {
		renderTemplate(w, h.Templates, "acl_list.html", data)
		return
	}
	renderTemplate(w, h.Templates, "acl.html", data)
}

// AclAddHandler adds one entry to a managed map/list file, both at runtime
// (immediate effect) and on disk (survives reload).
type AclAddHandler struct {
	AclHandler *AclHandler
}

func (h *AclAddHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form body", http.StatusBadRequest)
		return
	}
	path := r.FormValue("path")
	key := strings.TrimSpace(r.FormValue("key"))
	value := strings.TrimSpace(r.FormValue("value"))

	mf, ok := h.AclHandler.findFile(path)
	if !ok {
		http.Error(w, "unknown map file", http.StatusBadRequest)
		return
	}
	if key == "" || strings.ContainsAny(key, " \t\n") {
		http.Error(w, "key must be non-empty and contain no whitespace", http.StatusBadRequest)
		return
	}
	if mf.HasValue && (value == "" || strings.ContainsAny(value, " \t\n")) {
		http.Error(w, "value must be non-empty and contain no whitespace", http.StatusBadRequest)
		return
	}

	u, _ := auth.UserFromContext(r.Context())
	target := path + ":" + key

	runtimeValue := value
	if !mf.HasValue {
		runtimeValue = "1" // ACL-style lists have no value; HAProxy's runtime API still wants one.
	}
	if err := h.AclHandler.Runtime.AddMapEntry(path, key, runtimeValue); err != nil {
		_ = h.AclHandler.Audit.Record(store.AuditEntry{
			UserEmail: u.Email, RemoteIP: clientIP(r),
			Action: "acl.add", Target: target, Detail: "runtime add failed: " + err.Error(),
		})
		http.Error(w, "failed to add at runtime: "+err.Error(), http.StatusBadGateway)
		return
	}

	line := key
	if mf.HasValue {
		line = key + " " + value
	}
	if err := appendLine(path, line); err != nil {
		_ = h.AclHandler.Audit.Record(store.AuditEntry{
			UserEmail: u.Email, RemoteIP: clientIP(r),
			Action: "acl.add", Target: target,
			Detail: "added at runtime but FAILED to persist to file (will be lost on reload): " + err.Error(),
		})
		http.Error(w, "added at runtime but failed to persist to file — this entry will be lost on the next reload: "+err.Error(), http.StatusInternalServerError)
		return
	}

	if err := h.AclHandler.Audit.Record(store.AuditEntry{
		UserEmail: u.Email, RemoteIP: clientIP(r),
		Action: "acl.add", Target: target, Detail: "ok",
	}); err != nil {
		http.Error(w, "added but failed to audit-log: "+err.Error(), http.StatusInternalServerError)
		return
	}

	h.AclHandler.ServeHTTP(w, r)
}

func appendLine(path, line string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o640)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.WriteString(line + "\n")
	return err
}

// AclEditHandler changes the value of an existing "key value" entry (host
// routing maps and similar), both at runtime (immediate effect) and on
// disk. It only makes sense for MapFile.HasValue files — a plain allow/deny
// list has nothing to edit but the key itself, which is a delete-then-add.
type AclEditHandler struct {
	AclHandler *AclHandler
}

func (h *AclEditHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form body", http.StatusBadRequest)
		return
	}
	path := r.FormValue("path")
	key := strings.TrimSpace(r.FormValue("key"))
	value := strings.TrimSpace(r.FormValue("value"))

	mf, ok := h.AclHandler.findFile(path)
	if !ok {
		http.Error(w, "unknown map file", http.StatusBadRequest)
		return
	}
	if !mf.HasValue {
		http.Error(w, "this list has no value to edit — delete and re-add instead", http.StatusBadRequest)
		return
	}
	if key == "" {
		http.Error(w, "key must be non-empty", http.StatusBadRequest)
		return
	}
	if value == "" || strings.ContainsAny(value, " \t\n") {
		http.Error(w, "value must be non-empty and contain no whitespace", http.StatusBadRequest)
		return
	}

	u, _ := auth.UserFromContext(r.Context())
	target := path + ":" + key

	if err := h.AclHandler.Runtime.SetMapEntry(path, key, value); err != nil {
		_ = h.AclHandler.Audit.Record(store.AuditEntry{
			UserEmail: u.Email, RemoteIP: clientIP(r),
			Action: "acl.edit", Target: target, Detail: "runtime update failed: " + err.Error(),
		})
		http.Error(w, "failed to update at runtime: "+err.Error(), http.StatusBadGateway)
		return
	}

	if err := updateLine(path, key, value); err != nil {
		_ = h.AclHandler.Audit.Record(store.AuditEntry{
			UserEmail: u.Email, RemoteIP: clientIP(r),
			Action: "acl.edit", Target: target,
			Detail: "updated at runtime but FAILED to persist to file (old value will return on the next reload): " + err.Error(),
		})
		http.Error(w, "updated at runtime but failed to update the file — the old value will come back on the next reload: "+err.Error(), http.StatusInternalServerError)
		return
	}

	if err := h.AclHandler.Audit.Record(store.AuditEntry{
		UserEmail: u.Email, RemoteIP: clientIP(r),
		Action: "acl.edit", Target: target, Detail: "value=" + value,
	}); err != nil {
		http.Error(w, "updated but failed to audit-log: "+err.Error(), http.StatusInternalServerError)
		return
	}

	h.AclHandler.ServeHTTP(w, r)
}

// updateLine rewrites the "<key> <value>" line matching key (by its first
// whitespace-separated field) to use newValue instead, leaving every other
// line untouched. It is a no-op if the key isn't found.
func updateLine(path, key, newValue string) error {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	var kept []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		trimmed := strings.TrimSpace(line)
		fields := strings.Fields(trimmed)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") || len(fields) == 0 || fields[0] != key {
			kept = append(kept, line)
			continue
		}
		kept = append(kept, key+" "+newValue)
	}
	if err := sc.Err(); err != nil {
		f.Close()
		return err
	}
	f.Close()

	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(strings.Join(kept, "\n")+"\n"), 0o640); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// AclDeleteHandler removes one entry from a managed map/list file, both at
// runtime (immediate effect) and on disk.
type AclDeleteHandler struct {
	AclHandler *AclHandler
}

func (h *AclDeleteHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form body", http.StatusBadRequest)
		return
	}
	path := r.FormValue("path")
	key := strings.TrimSpace(r.FormValue("key"))

	mf, ok := h.AclHandler.findFile(path)
	if !ok {
		http.Error(w, "unknown map file", http.StatusBadRequest)
		return
	}
	if key == "" {
		http.Error(w, "key must be non-empty", http.StatusBadRequest)
		return
	}

	u, _ := auth.UserFromContext(r.Context())
	target := path + ":" + key

	if err := h.AclHandler.Runtime.DelMapEntry(path, key); err != nil {
		_ = h.AclHandler.Audit.Record(store.AuditEntry{
			UserEmail: u.Email, RemoteIP: clientIP(r),
			Action: "acl.delete", Target: target, Detail: "runtime delete failed: " + err.Error(),
		})
		http.Error(w, "failed to remove at runtime: "+err.Error(), http.StatusBadGateway)
		return
	}

	if err := removeLine(path, key, mf.HasValue); err != nil {
		_ = h.AclHandler.Audit.Record(store.AuditEntry{
			UserEmail: u.Email, RemoteIP: clientIP(r),
			Action: "acl.delete", Target: target,
			Detail: "removed at runtime but FAILED to persist to file (entry will return on the next reload): " + err.Error(),
		})
		http.Error(w, "removed at runtime but failed to update the file — this entry will come back on the next reload: "+err.Error(), http.StatusInternalServerError)
		return
	}

	if err := h.AclHandler.Audit.Record(store.AuditEntry{
		UserEmail: u.Email, RemoteIP: clientIP(r),
		Action: "acl.delete", Target: target, Detail: "ok",
	}); err != nil {
		http.Error(w, "removed but failed to audit-log: "+err.Error(), http.StatusInternalServerError)
		return
	}

	h.AclHandler.ServeHTTP(w, r)
}

// removeLine rewrites path without the line whose key matches (the first
// whitespace-separated field for hasValue files, or the whole trimmed line
// otherwise). Comments and blank lines are preserved as-is.
func removeLine(path, key string, hasValue bool) error {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	var kept []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			kept = append(kept, line)
			continue
		}
		lineKey := trimmed
		if hasValue {
			if fields := strings.Fields(trimmed); len(fields) > 0 {
				lineKey = fields[0]
			}
		}
		if lineKey == key {
			continue
		}
		kept = append(kept, line)
	}
	if err := sc.Err(); err != nil {
		f.Close()
		return err
	}
	f.Close()

	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(strings.Join(kept, "\n")+"\n"), 0o640); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
