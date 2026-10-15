package web

import "testing"

func TestFormatSize_AcceptsEveryIntegerKind(t *testing.T) {
	cases := []struct {
		in   any
		want string
	}{
		{uint64(0), "0 B"},
		{int64(0), "0 B"},
		{int64(26897), "26.3 KiB"},
		{uint64(26897), "26.3 KiB"},
		{int(1536), "1.5 KiB"},
		{int32(2048), "2.0 KiB"},
		{uint(5 << 20), "5.0 MiB"},
		{uint32(3 << 30), "3.0 GiB"},
		{int64(-5), "0 B"},
		{"12", "-"},
		{nil, "-"},
		{1.5, "-"},
	}
	for _, c := range cases {
		if got := formatSize(c.in); got != c.want {
			t.Errorf("formatSize(%#v) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestTemplateFuncs_HasTheNamesTemplatesUse(t *testing.T) {
	f := TemplateFuncs()
	for _, name := range []string{"upper", "bytes", "t"} {
		if f[name] == nil {
			t.Errorf("missing template func %q", name)
		}
	}
}
