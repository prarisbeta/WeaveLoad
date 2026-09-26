package haproxylog

import (
	"bytes"
	"io"
	"os"
)

// Tailer incrementally reads newly appended lines from a log file that is
// rotated by an external tool (logrotate, rsyslog). It tracks a byte offset
// rather than following file descriptors across rotation, so a rotation
// (the file shrinking below the last-seen offset) is detected and the
// tailer simply resumes from the start of the new file.
type Tailer struct {
	Path   string
	offset int64
}

// NewTailerAtEnd returns a Tailer positioned at the current end of path, so
// the first ReadNew call only returns lines appended after this point —
// avoiding a replay of the whole file on process start.
func NewTailerAtEnd(path string) (*Tailer, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	return &Tailer{Path: path, offset: fi.Size()}, nil
}

// ReadNew returns every complete line appended to the file since the last
// call (or since construction, for a fresh Tailer), parsed the same way
// Read parses lines. A trailing partial line (no final newline yet) is left
// unconsumed and picked up by a later call, once it's complete — the offset
// only ever advances past a line that ended in '\n'.
func (t *Tailer) ReadNew() ([]Line, error) {
	f, err := os.Open(t.Path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if fi.Size() < t.offset {
		// File shrank: rotated out from under us. Start over from 0.
		t.offset = 0
	}
	if _, err := f.Seek(t.offset, io.SeekStart); err != nil {
		return nil, err
	}

	buf, err := io.ReadAll(f)
	if err != nil {
		return nil, err
	}
	lastNL := bytes.LastIndexByte(buf, '\n')
	if lastNL < 0 {
		return nil, nil // no complete line yet
	}

	var lines []Line
	for _, raw := range bytes.Split(buf[:lastNL], []byte("\n")) {
		lines = append(lines, parseLine(string(raw)))
	}
	t.offset += int64(lastNL) + 1
	return lines, nil
}
