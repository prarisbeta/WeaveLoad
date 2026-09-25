package web

import (
	"html/template"
	"testing"
)

// mustParse builds a *template.Template from inline definitions, so each
// handler test only needs to define the few named templates it renders
// rather than pulling in the real (much larger) templates/*.html tree.
func mustParse(t *testing.T, defs string) *template.Template {
	t.Helper()
	tpl, err := template.New("root").Parse(defs)
	if err != nil {
		t.Fatalf("parse test templates: %v", err)
	}
	return tpl
}
