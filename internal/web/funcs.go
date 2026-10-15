package web

import (
	"html/template"
	"strings"

	"haproxy-gui/internal/i18n"
	"haproxy-gui/internal/sysinfo"
)

// TemplateFuncs is the one FuncMap every page template is parsed with, shared
// by the server and the real-template tests so the two cannot drift apart.
func TemplateFuncs() template.FuncMap {
	return template.FuncMap{
		"upper": strings.ToUpper,
		"bytes": formatSize,
		"t":     i18n.T,
		"list":  func(v ...string) []string { return v },
	}
}

// formatSize renders a byte count from any integer type. Sizes come from
// different sources (os.FileInfo.Size is int64, memory and disk counters are
// uint64); a template function that takes only one of them fails the whole
// page the first time the other shows up.
func formatSize(v any) string {
	switch n := v.(type) {
	case uint64:
		return sysinfo.FormatBytes(n)
	case uint:
		return sysinfo.FormatBytes(uint64(n))
	case uint32:
		return sysinfo.FormatBytes(uint64(n))
	case int64:
		return sysinfo.FormatBytes(clampNonNegative(n))
	case int:
		return sysinfo.FormatBytes(clampNonNegative(int64(n)))
	case int32:
		return sysinfo.FormatBytes(clampNonNegative(int64(n)))
	}
	return "-"
}

func clampNonNegative(n int64) uint64 {
	if n < 0 {
		return 0
	}
	return uint64(n)
}
