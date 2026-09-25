package sysinfo

import (
	"os"
	"path/filepath"
	"testing"
)

func writeFile(t *testing.T, name, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(content), 0o640); err != nil {
		t.Fatal(err)
	}
	return path
}

func testSampler(t *testing.T, statContent, meminfoContent, netDevContent string) *Sampler {
	t.Helper()
	s := NewSampler()
	if statContent != "" {
		s.statPath = writeFile(t, "stat", statContent)
	}
	if meminfoContent != "" {
		s.meminfoPath = writeFile(t, "meminfo", meminfoContent)
	}
	if netDevContent != "" {
		s.netDevPath = writeFile(t, "net_dev", netDevContent)
	}
	return s
}

const statSnapshot1 = "cpu  100 0 50 850 0 0 0 0 0 0\n"
const statSnapshot2 = "cpu  200 0 100 1600 0 0 0 0 0 0\n" // +100 user, +50 sys, +750 idle => 900 total, 750 idle

func TestCPUPercent_FirstCallHasNoBaseline(t *testing.T) {
	s := testSampler(t, statSnapshot1, "", "")
	pct, err := s.CPUPercent()
	if err != nil {
		t.Fatalf("CPUPercent: %v", err)
	}
	if pct != 0 {
		t.Errorf("pct = %v, want 0 on the first call", pct)
	}
}

func TestCPUPercent_ComputesDeltaBetweenCalls(t *testing.T) {
	s := testSampler(t, statSnapshot1, "", "")
	if _, err := s.CPUPercent(); err != nil {
		t.Fatal(err)
	}

	// Swap in the second reading at the same path.
	if err := os.WriteFile(s.statPath, []byte(statSnapshot2), 0o640); err != nil {
		t.Fatal(err)
	}
	pct, err := s.CPUPercent()
	if err != nil {
		t.Fatalf("CPUPercent: %v", err)
	}
	// totalDelta=900, idleDelta=750 => used = (1 - 750/900)*100 = 16.666...
	if pct < 16.5 || pct > 16.7 {
		t.Errorf("pct = %v, want ~16.67", pct)
	}
}

func TestCPUPercent_MalformedStatFile(t *testing.T) {
	s := testSampler(t, "not cpu data\n", "", "")
	if _, err := s.CPUPercent(); err == nil {
		t.Error("expected an error for a malformed /proc/stat")
	}
}

const meminfoFixture = `MemTotal:       16000000 kB
MemFree:         2000000 kB
MemAvailable:    4000000 kB
Buffers:          500000 kB
Cached:          1000000 kB
`

func TestMemoryUsage_ParsesMeminfo(t *testing.T) {
	s := testSampler(t, "", meminfoFixture, "")
	mem, err := s.MemoryUsage()
	if err != nil {
		t.Fatalf("MemoryUsage: %v", err)
	}
	wantTotal := uint64(16000000 * 1024)
	wantUsed := uint64(16000000*1024) - uint64(4000000*1024)
	if mem.TotalBytes != wantTotal {
		t.Errorf("TotalBytes = %d, want %d", mem.TotalBytes, wantTotal)
	}
	if mem.UsedBytes != wantUsed {
		t.Errorf("UsedBytes = %d, want %d", mem.UsedBytes, wantUsed)
	}
	if mem.UsedPercent < 74 || mem.UsedPercent > 76 {
		t.Errorf("UsedPercent = %v, want ~75", mem.UsedPercent)
	}
}

func TestMemoryUsage_FallsBackWithoutMemAvailable(t *testing.T) {
	fixture := `MemTotal:       10000 kB
MemFree:         2000 kB
Buffers:          500 kB
Cached:          1500 kB
`
	s := testSampler(t, "", fixture, "")
	mem, err := s.MemoryUsage()
	if err != nil {
		t.Fatalf("MemoryUsage: %v", err)
	}
	// avail = 2000+500+1500 = 4000; used = 10000-4000 = 6000
	if mem.UsedBytes != 6000*1024 {
		t.Errorf("UsedBytes = %d, want %d", mem.UsedBytes, 6000*1024)
	}
}

func TestDiskUsage_RootAlwaysReadable(t *testing.T) {
	d, err := DiskUsage("/")
	if err != nil {
		t.Fatalf("DiskUsage(/): %v", err)
	}
	if d.TotalBytes == 0 {
		t.Error("expected a non-zero total for the root filesystem")
	}
	if d.UsedPercent < 0 || d.UsedPercent > 100 {
		t.Errorf("UsedPercent = %v, want 0-100", d.UsedPercent)
	}
}

func TestDiskUsage_MissingPath_Errors(t *testing.T) {
	if _, err := DiskUsage(filepath.Join(t.TempDir(), "does-not-exist")); err == nil {
		t.Error("expected an error for a nonexistent path")
	}
}

const netDevFixture = `Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
    lo:  1000       10    0    0    0     0          0         0     1000      10    0    0    0     0       0          0
  eth0: 50000      100    0    0    0     0          0         0    30000       80    0    0    0     0       0          0
`

func TestNetInterfaces_SkipsLoopback(t *testing.T) {
	s := testSampler(t, "", "", netDevFixture)
	ifaces, err := s.NetInterfaces()
	if err != nil {
		t.Fatalf("NetInterfaces: %v", err)
	}
	for _, ifc := range ifaces {
		if ifc.Name == "lo" {
			t.Error("loopback interface should be excluded")
		}
	}
}

func TestFormatBytes(t *testing.T) {
	cases := map[uint64]string{
		500:                    "500 B",
		2048:                   "2.0 KiB",
		5 * 1024 * 1024:        "5.0 MiB",
		3 * 1024 * 1024 * 1024: "3.0 GiB",
	}
	for in, want := range cases {
		if got := FormatBytes(in); got != want {
			t.Errorf("FormatBytes(%d) = %q, want %q", in, got, want)
		}
	}
}
