package policy

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"haproxy-gui/internal/runtime"
)

// MapRuntime is the part of *runtime.Client that edits HAProxy maps.
type MapRuntime interface {
	AddMapEntry(mapFile, key, value string) error
	DelMapEntry(mapFile, key string) error
}

// ServerRuntime is the part of *runtime.Client that changes server state.
type ServerRuntime interface {
	SetServerState(backend, server string, state runtime.ServerState) error
}

// HAProxyExecutor performs actions through the runtime socket, and for IP
// blocks also keeps the blocklist file in step so a block survives a reload.
type HAProxyExecutor struct {
	Maps          MapRuntime
	Servers       ServerRuntime
	BlocklistPath string
}

func (x *HAProxyExecutor) BlockIP(ip string) error {
	if err := x.Maps.AddMapEntry(x.BlocklistPath, ip, "1"); err != nil {
		return fmt.Errorf("runtime add: %w", err)
	}
	lines, err := readLines(x.BlocklistPath)
	if err != nil {
		return fmt.Errorf("blocked at runtime but cannot read %s: %w", x.BlocklistPath, err)
	}
	for _, l := range lines {
		if strings.TrimSpace(l) == ip {
			return nil
		}
	}
	return writeLines(x.BlocklistPath, append(lines, ip))
}

func (x *HAProxyExecutor) UnblockIP(ip string) error {
	if err := x.Maps.DelMapEntry(x.BlocklistPath, ip); err != nil && !entryMissing(err) {
		return fmt.Errorf("runtime delete: %w", err)
	}
	lines, err := readLines(x.BlocklistPath)
	if err != nil {
		return err
	}
	kept := make([]string, 0, len(lines))
	for _, l := range lines {
		if strings.TrimSpace(l) != ip {
			kept = append(kept, l)
		}
	}
	if len(kept) == len(lines) {
		return nil
	}
	return writeLines(x.BlocklistPath, kept)
}

func (x *HAProxyExecutor) Drain(backend, server string) error {
	return x.Servers.SetServerState(backend, server, runtime.StateDrain)
}

func (x *HAProxyExecutor) Undrain(backend, server string) error {
	return x.Servers.SetServerState(backend, server, runtime.StateReady)
}

func entryMissing(err error) bool {
	s := strings.ToLower(err.Error())
	return strings.Contains(s, "not found") || strings.Contains(s, "no such")
}

func readLines(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer f.Close()
	var out []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		out = append(out, sc.Text())
	}
	return out, sc.Err()
}

// writeLines replaces path atomically so a crash never leaves a half-written
// blocklist that HAProxy would load on the next reload.
func writeLines(path string, lines []string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".blocklist-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	w := bufio.NewWriter(tmp)
	for _, l := range lines {
		fmt.Fprintln(w, l)
	}
	if err := w.Flush(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(0o640); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}
