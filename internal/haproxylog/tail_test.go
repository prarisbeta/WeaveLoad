package haproxylog

import (
	"os"
	"testing"
)

func TestTailer_ReadsOnlyLinesAppendedAfterConstruction(t *testing.T) {
	path := writeFixture(t, "line one\nline two\n")
	tailer, err := NewTailerAtEnd(path)
	if err != nil {
		t.Fatalf("NewTailerAtEnd: %v", err)
	}

	if lines, err := tailer.ReadNew(); err != nil || len(lines) != 0 {
		t.Fatalf("ReadNew before any append: lines=%v err=%v, want none", lines, err)
	}

	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString("line three\nline four\n"); err != nil {
		t.Fatal(err)
	}
	f.Close()

	lines, err := tailer.ReadNew()
	if err != nil {
		t.Fatalf("ReadNew: %v", err)
	}
	if len(lines) != 2 || lines[0].Raw != "line three" || lines[1].Raw != "line four" {
		t.Fatalf("lines = %+v, want [line three, line four]", lines)
	}

	if lines, err := tailer.ReadNew(); err != nil || len(lines) != 0 {
		t.Fatalf("second ReadNew with nothing new: lines=%v err=%v", lines, err)
	}
}

func TestTailer_LeavesPartialTrailingLineForNextCall(t *testing.T) {
	path := writeFixture(t, "")
	tailer, err := NewTailerAtEnd(path)
	if err != nil {
		t.Fatal(err)
	}

	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString("complete line\npartial line without newline"); err != nil {
		t.Fatal(err)
	}
	f.Close()

	lines, err := tailer.ReadNew()
	if err != nil {
		t.Fatalf("ReadNew: %v", err)
	}
	if len(lines) != 1 || lines[0].Raw != "complete line" {
		t.Fatalf("lines = %+v, want only the complete line", lines)
	}

	f, err = os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(" now finished\n"); err != nil {
		t.Fatal(err)
	}
	f.Close()

	lines, err = tailer.ReadNew()
	if err != nil {
		t.Fatalf("ReadNew after completing the line: %v", err)
	}
	if len(lines) != 1 || lines[0].Raw != "partial line without newline now finished" {
		t.Fatalf("lines = %+v, want the now-completed line", lines)
	}
}

func TestTailer_DetectsRotationWhenFileShrinks(t *testing.T) {
	path := writeFixture(t, "old line one\nold line two\nold line three\n")
	tailer, err := NewTailerAtEnd(path)
	if err != nil {
		t.Fatal(err)
	}

	// Simulate log rotation: the file is truncated/replaced with new content
	// shorter than the previous offset.
	if err := os.WriteFile(path, []byte("new line\n"), 0o640); err != nil {
		t.Fatal(err)
	}

	lines, err := tailer.ReadNew()
	if err != nil {
		t.Fatalf("ReadNew: %v", err)
	}
	if len(lines) != 1 || lines[0].Raw != "new line" {
		t.Fatalf("lines = %+v, want the tailer to restart from 0 after rotation", lines)
	}
}
