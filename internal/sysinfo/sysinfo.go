// Package sysinfo reads host resource usage (CPU, memory, disk, network
// interfaces) straight from /proc and syscall.Statfs, the way top/df/ip do —
// no external monitoring agent or dependency needed for a single-host
// gateway. It only ever reads; nothing here writes to the system.
package sysinfo

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"syscall"
)

// CPU is the share of CPU time spent not-idle since the previous read.
type CPU struct {
	UsedPercent float64
}

// Memory is host RAM usage.
type Memory struct {
	TotalBytes  uint64
	UsedBytes   uint64
	UsedPercent float64
}

// Disk is usage for one mounted path.
type Disk struct {
	Path        string
	TotalBytes  uint64
	UsedBytes   uint64
	UsedPercent float64
}

// NetIface is one non-loopback network interface's current state and
// cumulative traffic counters (since boot, as the kernel reports them).
type NetIface struct {
	Name    string
	Up      bool
	Addrs   []string
	RxBytes uint64
	TxBytes uint64
}

// Snapshot is everything the dashboard's resource panel needs from one poll.
type Snapshot struct {
	CPU   CPU
	Mem   Memory
	Disks []Disk
	Nets  []NetIface
}

// Sampler holds the previous /proc/stat reading needed to compute CPU%,
// which is only meaningful as a delta between two points in time. Keep one
// long-lived Sampler (one per process) and call Read repeatedly — e.g. once
// per dashboard poll — rather than constructing a new one each time.
type Sampler struct {
	mu   sync.Mutex
	last cpuSample
	have bool

	// overridable in tests; default to the real /proc paths.
	statPath    string
	meminfoPath string
	netDevPath  string
}

func NewSampler() *Sampler {
	return &Sampler{statPath: "/proc/stat", meminfoPath: "/proc/meminfo", netDevPath: "/proc/net/dev"}
}

type cpuSample struct{ idle, total uint64 }

func (s *Sampler) readCPUSample() (cpuSample, error) {
	f, err := os.Open(s.statPath)
	if err != nil {
		return cpuSample{}, err
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	if !sc.Scan() {
		return cpuSample{}, fmt.Errorf("empty %s", s.statPath)
	}
	fields := strings.Fields(sc.Text())
	if len(fields) < 5 || fields[0] != "cpu" {
		return cpuSample{}, fmt.Errorf("unexpected %s format: %q", s.statPath, sc.Text())
	}
	var vals []uint64
	var total uint64
	for _, f := range fields[1:] {
		n, err := strconv.ParseUint(f, 10, 64)
		if err != nil {
			break
		}
		vals = append(vals, n)
		total += n
	}
	if len(vals) < 4 {
		return cpuSample{}, fmt.Errorf("not enough fields in %s", s.statPath)
	}
	idle := vals[3] // idle
	if len(vals) > 4 {
		idle += vals[4] // + iowait
	}
	return cpuSample{idle: idle, total: total}, nil
}

// CPUPercent returns utilization since the previous call. The first call
// on a fresh Sampler has no baseline yet and returns 0.
func (s *Sampler) CPUPercent() (float64, error) {
	cur, err := s.readCPUSample()
	if err != nil {
		return 0, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	prev, had := s.last, s.have
	s.last, s.have = cur, true

	if !had {
		return 0, nil
	}
	totalDelta := float64(cur.total - prev.total)
	idleDelta := float64(cur.idle - prev.idle)
	if totalDelta <= 0 {
		return 0, nil
	}
	pct := (1 - idleDelta/totalDelta) * 100
	if pct < 0 {
		pct = 0
	}
	if pct > 100 {
		pct = 100
	}
	return pct, nil
}

func (s *Sampler) MemoryUsage() (Memory, error) {
	f, err := os.Open(s.meminfoPath)
	if err != nil {
		return Memory{}, err
	}
	defer f.Close()

	vals := map[string]uint64{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		parts := strings.SplitN(sc.Text(), ":", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		fields := strings.Fields(parts[1])
		if len(fields) == 0 {
			continue
		}
		n, err := strconv.ParseUint(fields[0], 10, 64)
		if err != nil {
			continue
		}
		vals[key] = n * 1024 // /proc/meminfo reports kB
	}

	total := vals["MemTotal"]
	avail, ok := vals["MemAvailable"]
	if !ok {
		avail = vals["MemFree"] + vals["Buffers"] + vals["Cached"]
	}
	used := total - avail
	pct := 0.0
	if total > 0 {
		pct = float64(used) / float64(total) * 100
	}
	return Memory{TotalBytes: total, UsedBytes: used, UsedPercent: pct}, nil
}

// DiskUsage reports usage for the filesystem containing path (a mount
// point, or any directory on it).
func DiskUsage(path string) (Disk, error) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		return Disk{}, fmt.Errorf("statfs %s: %w", path, err)
	}
	total := st.Blocks * uint64(st.Bsize)
	free := st.Bfree * uint64(st.Bsize)
	used := total - free
	pct := 0.0
	if total > 0 {
		pct = float64(used) / float64(total) * 100
	}
	return Disk{Path: path, TotalBytes: total, UsedBytes: used, UsedPercent: pct}, nil
}

type netCounter struct{ rx, tx uint64 }

func (s *Sampler) readNetDev() map[string]netCounter {
	out := map[string]netCounter{}
	f, err := os.Open(s.netDevPath)
	if err != nil {
		return out
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	line := 0
	for sc.Scan() {
		line++
		if line <= 2 { // two header lines
			continue
		}
		parts := strings.SplitN(sc.Text(), ":", 2)
		if len(parts) != 2 {
			continue
		}
		name := strings.TrimSpace(parts[0])
		fields := strings.Fields(parts[1])
		if len(fields) < 9 {
			continue
		}
		rx, _ := strconv.ParseUint(fields[0], 10, 64)
		tx, _ := strconv.ParseUint(fields[8], 10, 64)
		out[name] = netCounter{rx: rx, tx: tx}
	}
	return out
}

// NetInterfaces lists non-loopback interfaces with their current state,
// addresses, and cumulative traffic counters.
func (s *Sampler) NetInterfaces() ([]NetIface, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	counters := s.readNetDev()

	var out []NetIface
	for _, ifc := range ifaces {
		if ifc.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, _ := ifc.Addrs()
		addrStrs := make([]string, 0, len(addrs))
		for _, a := range addrs {
			addrStrs = append(addrStrs, a.String())
		}
		c := counters[ifc.Name]
		out = append(out, NetIface{
			Name: ifc.Name, Up: ifc.Flags&net.FlagUp != 0,
			Addrs: addrStrs, RxBytes: c.rx, TxBytes: c.tx,
		})
	}
	return out, nil
}

// Read gathers a full Snapshot in one call. Errors from any one source
// (e.g. a disk path that doesn't exist) are dropped silently for that
// source rather than failing the whole snapshot — a dashboard widget
// missing one number is better than the whole panel erroring out.
func (s *Sampler) Read(diskPaths []string) Snapshot {
	var snap Snapshot
	if cpu, err := s.CPUPercent(); err == nil {
		snap.CPU = CPU{UsedPercent: cpu}
	}
	if mem, err := s.MemoryUsage(); err == nil {
		snap.Mem = mem
	}
	for _, p := range diskPaths {
		if d, err := DiskUsage(p); err == nil {
			snap.Disks = append(snap.Disks, d)
		}
	}
	if nets, err := s.NetInterfaces(); err == nil {
		snap.Nets = nets
	}
	return snap
}

// FormatBytes renders a byte count as a human-readable size (GiB/MiB/KiB),
// for use from templates via the "bytes" FuncMap entry.
func FormatBytes(n uint64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := uint64(unit), 0
	for n/div >= unit && exp < 3 {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGT"[exp])
}
