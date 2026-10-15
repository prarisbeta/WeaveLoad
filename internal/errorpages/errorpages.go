package errorpages

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// DefaultDir is the standard HAProxy errorfiles directory on Linux targets.
const DefaultDir = "/etc/haproxy/errors"

// Page represents a custom error page configuration.
type Page struct {
	Code        int    `json:"code"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Path        string `json:"path"`
	Content     string `json:"content"`
	HTMLBody    string `json:"html_body"`
}

// Manager manages reading, previewing, and saving HAProxy .http errorfiles.
type Manager struct {
	Dir string
}

// NewManager creates an error page manager with dir (defaults to /etc/haproxy/errors if empty).
func NewManager(dir string) *Manager {
	if dir == "" {
		dir = DefaultDir
	}
	return &Manager{Dir: dir}
}

// SupportedCodes lists standard HTTP status codes supported as HAProxy errorfiles.
var SupportedCodes = []struct {
	Code        int
	Name        string
	Description string
}{
	{Code: 429, Name: "429 Too Many Requests (Waiting Room)", Description: "Halaman ruang tunggu antrean pengunjung saat trafik penuh atau terkena rate limit."},
	{Code: 503, Name: "503 Service Unavailable (Maintenance)", Description: "Halaman pemeliharaan sistem atau ketika semua server backend sedang offline."},
	{Code: 502, Name: "502 Bad Gateway", Description: "Halaman peringatan ketika server backend gagal dihubungi atau tidak merespons."},
	{Code: 504, Name: "504 Gateway Timeout", Description: "Halaman peringatan ketika server backend membutuhkan waktu terlalu lama untuk merespons."},
	{Code: 403, Name: "403 Forbidden (Security Block)", Description: "Halaman penolakan akses untuk IP yang terdaftar dalam daftar blokir atau melanggar aturan ACL."},
	{Code: 400, Name: "400 Bad Request", Description: "Halaman kesalahan format permintaan dari browser klien."},
}

// Get returns the Page for a specific HTTP status code, loading from disk if present or returning default preset.
func (m *Manager) Get(code int) (Page, error) {
	var meta struct {
		Code        int
		Name        string
		Description string
	}
	found := false
	for _, c := range SupportedCodes {
		if c.Code == code {
			meta = c
			found = true
			break
		}
	}
	if !found {
		return Page{}, fmt.Errorf("kode status %d tidak didukung sebagai errorfile", code)
	}

	targetPath := filepath.Join(m.Dir, fmt.Sprintf("%d.http", code))
	content := ""
	if data, err := os.ReadFile(targetPath); err == nil {
		content = string(data)
	} else {
		content = GetPreset(code)
	}

	htmlBody := ExtractHTMLBody(content)

	return Page{
		Code:        code,
		Name:        meta.Name,
		Description: meta.Description,
		Path:        targetPath,
		Content:     content,
		HTMLBody:    htmlBody,
	}, nil
}

// List returns all supported error pages with their current status and content.
func (m *Manager) List() []Page {
	pages := make([]Page, 0, len(SupportedCodes))
	for _, sc := range SupportedCodes {
		p, err := m.Get(sc.Code)
		if err == nil {
			pages = append(pages, p)
		}
	}
	return pages
}

// Save writes the raw HTTP errorfile to disk.
func (m *Manager) Save(code int, content string) error {
	if code < 400 || code > 599 {
		return fmt.Errorf("kode status tidak valid: %d", code)
	}
	content = strings.TrimSpace(content)
	if content == "" {
		return fmt.Errorf("konten halaman error tidak boleh kosong")
	}

	// Ensure proper HTTP header prefix
	if !strings.HasPrefix(content, "HTTP/1.") {
		reason := statusReason(code)
		content = fmt.Sprintf("HTTP/1.1 %d %s\r\nContent-Type: text/html; charset=UTF-8\r\nCache-Control: no-cache, no-store, must-revalidate\r\nConnection: close\r\n\r\n%s", code, reason, content)
	}

	if err := os.MkdirAll(m.Dir, 0755); err != nil {
		return fmt.Errorf("gagal membuat direktori error: %w", err)
	}

	targetPath := filepath.Join(m.Dir, fmt.Sprintf("%d.http", code))
	if err := os.WriteFile(targetPath, []byte(content), 0644); err != nil {
		return fmt.Errorf("gagal menyimpan berkas %s: %w", targetPath, err)
	}
	return nil
}

// ExtractHTMLBody extracts HTML content from a raw HTTP response string.
func ExtractHTMLBody(raw string) string {
	if idx := strings.Index(raw, "\r\n\r\n"); idx != -1 {
		return strings.TrimSpace(raw[idx+4:])
	}
	if idx := strings.Index(raw, "\n\n"); idx != -1 {
		return strings.TrimSpace(raw[idx+2:])
	}
	return strings.TrimSpace(raw)
}

func statusReason(code int) string {
	switch code {
	case 400:
		return "Bad Request"
	case 403:
		return "Forbidden"
	case 429:
		return "Too Many Requests"
	case 500:
		return "Internal Server Error"
	case 502:
		return "Bad Gateway"
	case 503:
		return "Service Unavailable"
	case 504:
		return "Gateway Timeout"
	default:
		return "Error"
	}
}

// GetPreset returns the enterprise Cloudflare-inspired preset template for a given code.
func GetPreset(code int) string {
	switch code {
	case 429:
		return `HTTP/1.1 429 Too Many Requests
Content-Type: text/html; charset=UTF-8
Retry-After: 5
Cache-Control: no-cache, no-store, must-revalidate
Connection: close

<!DOCTYPE html>
<html lang="id">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Ruang Tunggu Antrean Kunjungan</title>
  <style>
    :root {
      --bg: #090d16;
      --card-bg: rgba(18, 26, 43, 0.85);
      --border: rgba(255, 255, 255, 0.1);
      --accent: #38bdf8;
      --accent-glow: rgba(56, 189, 248, 0.35);
      --text: #f1f5f9;
      --text-muted: #94a3b8;
      --warning: #fbbf24;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif; }
    body { background: radial-gradient(circle at top center, #1e293b 0%, var(--bg) 80%); color: var(--text); min-height: 100vh; display: flex; align-items: center; justify-content: center; padding: 20px; }
    .waiting-container { background: var(--card-bg); backdrop-filter: blur(16px); -webkit-backdrop-filter: blur(16px); border: 1px solid var(--border); border-radius: 20px; max-width: 520px; width: 100%; padding: 40px 32px; text-align: center; box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.6), 0 0 40px var(--accent-glow); position: relative; overflow: hidden; }
    .waiting-container::before { content: ""; position: absolute; top: 0; left: 0; right: 0; height: 4px; background: linear-gradient(90deg, #38bdf8, #818cf8, #c084fc, #38bdf8); background-size: 300% 100%; animation: gradient-flow 3s linear infinite; }
    @keyframes gradient-flow { 0% { background-position: 0% 50%; } 100% { background-position: 100% 50%; } }
    .queue-icon-wrapper { position: relative; width: 84px; height: 84px; margin: 0 auto 24px; display: flex; align-items: center; justify-content: center; }
    .pulse-ring { position: absolute; width: 100%; height: 100%; border-radius: 50%; border: 2px solid var(--accent); animation: pulse 2s cubic-bezier(0.24, 0, 0.38, 1) infinite; }
    @keyframes pulse { 0% { transform: scale(0.85); opacity: 0.9; } 50% { transform: scale(1.25); opacity: 0.3; } 100% { transform: scale(1.5); opacity: 0; } }
    .icon-badge { width: 64px; height: 64px; background: linear-gradient(135deg, rgba(56, 189, 248, 0.2), rgba(129, 140, 248, 0.2)); border: 1px solid rgba(56, 189, 248, 0.4); border-radius: 50%; display: flex; align-items: center; justify-content: center; font-size: 28px; box-shadow: 0 0 20px var(--accent-glow); }
    h1 { font-size: 22px; font-weight: 700; margin-bottom: 8px; color: #ffffff; letter-spacing: -0.02em; }
    .status-pill { display: inline-flex; align-items: center; gap: 6px; background: rgba(251, 191, 36, 0.15); border: 1px solid rgba(251, 191, 36, 0.3); color: var(--warning); font-size: 12px; font-weight: 600; padding: 4px 12px; border-radius: 20px; margin-bottom: 20px; text-transform: uppercase; letter-spacing: 0.05em; }
    .status-dot { width: 8px; height: 8px; background-color: var(--warning); border-radius: 50%; animation: blink 1.2s ease-in-out infinite alternate; }
    @keyframes blink { 0% { opacity: 0.4; } 100% { opacity: 1; } }
    p.desc { font-size: 14px; line-height: 1.6; color: var(--text-muted); margin-bottom: 24px; }
    .countdown-card { background: rgba(15, 23, 42, 0.6); border: 1px solid rgba(255, 255, 255, 0.06); border-radius: 12px; padding: 16px; margin-bottom: 24px; }
    .countdown-label { font-size: 12px; color: var(--text-muted); margin-bottom: 6px; }
    .countdown-number { font-size: 32px; font-weight: 800; color: var(--accent); font-feature-settings: "tnum"; font-variant-numeric: tabular-nums; }
    .progress-bar-bg { width: 100%; height: 6px; background: rgba(255, 255, 255, 0.08); border-radius: 4px; margin-top: 12px; overflow: hidden; }
    .progress-bar-fill { height: 100%; background: linear-gradient(90deg, var(--accent), #818cf8); border-radius: 4px; width: 100%; animation: countdown-progress 5s linear infinite; }
    @keyframes countdown-progress { 0% { width: 100%; } 100% { width: 0%; } }
    .btn-retry { display: inline-flex; align-items: center; justify-content: center; gap: 8px; background: linear-gradient(135deg, #0284c7, #2563eb); color: #ffffff; border: none; padding: 12px 24px; border-radius: 10px; font-size: 14px; font-weight: 600; cursor: pointer; text-decoration: none; transition: all 0.2s ease; box-shadow: 0 4px 12px rgba(37, 99, 235, 0.3); width: 100%; }
    .btn-retry:hover { background: linear-gradient(135deg, #0369a1, #1d4ed8); transform: translateY(-1px); box-shadow: 0 6px 16px rgba(37, 99, 235, 0.4); }
    .footer-note { font-size: 11px; color: #64748b; margin-top: 20px; line-height: 1.4; }
  </style>
</head>
<body>
  <div class="waiting-container">
    <div class="queue-icon-wrapper">
      <div class="pulse-ring"></div>
      <div class="icon-badge">⏳</div>
    </div>
    <div class="status-pill"><span class="status-dot"></span> Antrean Kunjungan Aktif</div>
    <h1>Mohon Menunggu Sejenak</h1>
    <p class="desc">Layanan sedang melayani volume pengunjung yang sangat tinggi. Demi keamanan dan kestabilan transaksi Anda, antrean otomatis sedang berlangsung.</p>
    <div class="countdown-card">
      <div class="countdown-label">Memuat ulang otomatis dalam:</div>
      <div class="countdown-number" id="countdown-val">5</div>
      <div class="progress-bar-bg"><div class="progress-bar-fill"></div></div>
    </div>
    <button type="button" class="btn-retry" id="btn-manual-reload">🔄 Coba Muat Ulang Sekarang</button>
    <div class="footer-note">Halaman akan otomatis menghubungkan Anda kembali segera setelah kapasitas server tersedia.</div>
  </div>
  <script>
    (function() {
      // Retry with a growing, randomised delay (about 5s, 8s, 13s ... up to 30s)
      // so waiting visitors do not all hit the server at the same moment.
      var KEY = 'kgw_wait';
      var attempt = 0;
      try {
        var saved = JSON.parse(sessionStorage.getItem(KEY) || '{}');
        if (saved.t && Date.now() - saved.t < 120000) { attempt = saved.n || 0; }
        sessionStorage.setItem(KEY, JSON.stringify({ n: attempt + 1, t: Date.now() }));
      } catch (e) {}
      var base = Math.min(30, 5 * Math.pow(1.6, attempt));
      var seconds = Math.max(3, Math.round(base * (0.7 + Math.random() * 0.6)));
      var el = document.getElementById('countdown-val');
      var fill = document.querySelector('.progress-bar-fill');
      if (el) { el.textContent = seconds; }
      if (fill) { fill.style.animation = 'countdown-progress ' + seconds + 's linear forwards'; }
      function retry() { window.location.replace(window.location.href); }
      var timer = setInterval(function() {
        seconds--;
        if (el) { el.textContent = seconds > 0 ? seconds : 0; }
        if (seconds <= 0) { clearInterval(timer); retry(); }
      }, 1000);
      var btn = document.getElementById('btn-manual-reload');
      if (btn) { btn.addEventListener('click', retry); }
    })();
  </script>
</body>
</html>`

	case 503:
		return `HTTP/1.1 503 Service Unavailable
Content-Type: text/html; charset=UTF-8
Retry-After: 30
Cache-Control: no-cache, no-store, must-revalidate
Connection: close

<!DOCTYPE html>
<html lang="id">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>503: Pemeliharaan Sistem</title>
  <style>
    :root { --bg: #0b1120; --card: rgba(30, 41, 59, 0.9); --text: #f8fafc; --muted: #94a3b8; --accent: #f59e0b; }
    * { box-sizing: border-box; margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; }
    body { background: radial-gradient(circle at top, #1e293b, var(--bg)); color: var(--text); min-height: 100vh; display: flex; align-items: center; justify-content: center; padding: 24px; }
    .card { background: var(--card); border: 1px solid rgba(255, 255, 255, 0.1); border-radius: 16px; max-width: 520px; width: 100%; padding: 40px 32px; text-align: center; box-shadow: 0 20px 45px rgba(0, 0, 0, 0.6); }
    .icon-svg { width: 48px; height: 48px; margin: 0 auto 16px; color: var(--accent); display: block; }
    h1 { font-size: 24px; font-weight: 700; margin-bottom: 12px; color: #fff; }
    p { font-size: 14px; line-height: 1.6; color: var(--muted); margin-bottom: 24px; }
    .badge { display: inline-block; background: rgba(245, 158, 11, 0.15); border: 1px solid rgba(245, 158, 11, 0.4); color: var(--accent); padding: 4px 12px; border-radius: 9999px; font-size: 12px; font-weight: 600; margin-bottom: 16px; }
    .btn { background: #3b82f6; color: #fff; border: none; padding: 10px 24px; border-radius: 8px; font-size: 14px; font-weight: 600; cursor: pointer; text-decoration: none; display: inline-block; }
    .btn:hover { background: #2563eb; }
  </style>
</head>
<body>
  <div class="card">
    <svg class="icon-svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
      <path d="M14.7 6.3a1 1 0 0 0 0 1.4l1.6 1.6a1 1 0 0 0 1.4 0l3.77-3.77a6 6 0 0 1-7.94 7.94l-6.91 6.91a2.12 2.12 0 0 1-3-3l6.91-6.91a6 6 0 0 1 7.94-7.94l-3.76 3.76z"/>
    </svg>
    <div class="badge">Status: 503 Maintenance</div>
    <h1>Sistem Sedang Dalam Pemeliharaan</h1>
    <p>Kami sedang melakukan peningkatan performa dan pemeliharaan terjadwal. Layanan akan segera kembali normal dalam beberapa saat.</p>
    <button class="btn" onclick="window.location.reload()">Coba Muat Ulang</button>
  </div>
</body>
</html>`

	case 502:
		return `HTTP/1.1 502 Bad Gateway
Content-Type: text/html; charset=UTF-8
Cache-Control: no-cache, no-store, must-revalidate
Connection: close

<!DOCTYPE html>
<html lang="id">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>502: Server Upstream Tidak Merespons</title>
  <style>
    :root { --bg: #0f172a; --card: rgba(30, 41, 59, 0.9); --text: #f8fafc; --muted: #94a3b8; --bad: #ef4444; --ok: #22c55e; }
    * { box-sizing: border-box; margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; }
    body { background: var(--bg); color: var(--text); min-height: 100vh; display: flex; align-items: center; justify-content: center; padding: 24px; }
    .card { background: var(--card); border: 1px solid rgba(255, 255, 255, 0.1); border-radius: 16px; max-width: 600px; width: 100%; padding: 40px 32px; text-align: center; }
    h1 { font-size: 24px; margin-bottom: 8px; font-weight: 700; }
    p.lead { color: var(--muted); font-size: 14px; margin-bottom: 24px; line-height: 1.6; }
    .flow { display: flex; justify-content: space-around; align-items: center; margin: 24px 0; padding: 20px; background: rgba(0,0,0,0.25); border-radius: 12px; }
    .node { font-size: 12px; display: flex; flex-direction: column; align-items: center; gap: 8px; }
    .node-icon { width: 44px; height: 44px; border-radius: 50%; display: flex; align-items: center; justify-content: center; font-size: 16px; font-weight: 700; }
    .node.ok .node-icon { background: rgba(34, 197, 94, 0.15); border: 2px solid var(--ok); color: var(--ok); }
    .node.bad .node-icon { background: rgba(239, 68, 68, 0.15); border: 2px solid var(--bad); color: var(--bad); }
    .arrow { color: var(--muted); font-size: 16px; }
  </style>
</head>
<body>
  <div class="card">
    <h1>502 Bad Gateway</h1>
    <p class="lead">Gateway load balancer berhasil terhubung, namun server aplikasi backend gagal memberikan respons yang valid.</p>
    <div class="flow">
      <div class="node ok"><div class="node-icon">OK</div><span>Klien Browser</span></div>
      <div class="arrow">→</div>
      <div class="node ok"><div class="node-icon">OK</div><span>Gateway</span></div>
      <div class="arrow">→</div>
      <div class="node bad"><div class="node-icon">ERR</div><span>Server Backend</span></div>
    </div>
    <p style="font-size:12px; color:var(--muted)">Tim operasional telah menerima catatan teknis otomatis terkait kendala ini.</p>
  </div>
</body>
</html>`

	case 504:
		return `HTTP/1.1 504 Gateway Timeout
Content-Type: text/html; charset=UTF-8
Cache-Control: no-cache, no-store, must-revalidate
Connection: close

<!DOCTYPE html>
<html lang="id">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>504: Waktu Respons Habis</title>
  <style>
    body { background: #0f172a; color: #f8fafc; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; display: flex; align-items: center; justify-content: center; min-height: 100vh; margin: 0; padding: 24px; box-sizing: border-box; }
    .card { background: rgba(30, 41, 59, 0.9); border: 1px solid #334155; border-radius: 16px; padding: 40px 32px; max-width: 500px; text-align: center; }
    .icon-svg { width: 48px; height: 48px; margin: 0 auto 16px; color: #f59e0b; display: block; }
    h1 { font-size: 24px; font-weight: 700; margin-bottom: 12px; }
    p { color: #94a3b8; font-size: 14px; line-height: 1.6; margin-bottom: 24px; }
    .btn { background: #3b82f6; color: #fff; border: none; padding: 10px 24px; border-radius: 8px; font-size: 14px; font-weight: 600; cursor: pointer; }
    .btn:hover { background: #2563eb; }
  </style>
</head>
<body>
  <div class="card">
    <svg class="icon-svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
      <circle cx="12" cy="12" r="10"/>
      <polyline points="12 6 12 12 16 14"/>
    </svg>
    <h1>504 Gateway Timeout</h1>
    <p>Server upstream membutuhkan waktu terlalu lama untuk merespons permintaan Anda. Silakan coba kembali beberapa saat lagi.</p>
    <button class="btn" onclick="window.location.reload()">Muat Ulang</button>
  </div>
</body>
</html>`

	case 403:
		return `HTTP/1.1 403 Forbidden
Content-Type: text/html; charset=UTF-8
Cache-Control: no-cache, no-store, must-revalidate
Connection: close

<!DOCTYPE html>
<html lang="id">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>403: Akses Ditolak (Security Block)</title>
  <style>
    :root {
      --bg: #090d16;
      --card-bg: rgba(18, 26, 43, 0.9);
      --border: rgba(255, 255, 255, 0.1);
      --border-danger: rgba(239, 68, 68, 0.3);
      --danger: #ef4444;
      --danger-soft: rgba(239, 68, 68, 0.15);
      --text: #f1f5f9;
      --text-muted: #94a3b8;
      --accent: #38bdf8;
    }
    * {
      box-sizing: border-box;
      margin: 0;
      padding: 0;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
    }
    body {
      background: radial-gradient(circle at top center, #1e1b4b 0%, var(--bg) 80%);
      color: var(--text);
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 24px;
    }
    .security-container {
      background: var(--card-bg);
      border: 1px solid var(--border-danger);
      border-radius: 16px;
      max-width: 580px;
      width: 100%;
      padding: 40px 32px;
      box-shadow: 0 20px 45px rgba(0, 0, 0, 0.6);
      position: relative;
      overflow: hidden;
      text-align: center;
    }
    .security-container::before {
      content: "";
      position: absolute;
      top: 0;
      left: 0;
      right: 0;
      height: 3px;
      background: linear-gradient(90deg, #ef4444, #f97316, #ef4444);
    }
    .shield-icon {
      width: 52px;
      height: 52px;
      margin: 0 auto 16px;
      color: var(--danger);
      display: block;
    }
    .header-badge {
      display: inline-flex;
      align-items: center;
      gap: 8px;
      background: var(--danger-soft);
      border: 1px solid var(--border-danger);
      color: #fca5a5;
      font-size: 12px;
      font-weight: 700;
      letter-spacing: 0.05em;
      padding: 4px 12px;
      border-radius: 20px;
      text-transform: uppercase;
      margin-bottom: 16px;
    }
    h1 {
      font-size: 24px;
      font-weight: 700;
      color: #ffffff;
      margin-bottom: 10px;
      letter-spacing: -0.02em;
    }
    p.lead {
      font-size: 14px;
      line-height: 1.6;
      color: var(--text-muted);
      margin-bottom: 24px;
    }
    .diagnostic-box {
      background: rgba(10, 15, 29, 0.8);
      border: 1px solid var(--border);
      border-radius: 10px;
      padding: 16px 20px;
      margin-bottom: 24px;
      text-align: left;
    }
    .diagnostic-title {
      font-size: 11px;
      text-transform: uppercase;
      letter-spacing: 0.08em;
      color: #64748b;
      font-weight: 700;
      margin-bottom: 12px;
    }
    .diagnostic-grid {
      display: grid;
      grid-template-columns: 140px 1fr;
      row-gap: 8px;
      font-size: 13px;
    }
    .diag-label {
      color: var(--text-muted);
    }
    .diag-val {
      color: #f8fafc;
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
      font-size: 12px;
      word-break: break-all;
    }
    .info-section {
      text-align: left;
      background: rgba(255, 255, 255, 0.02);
      border: 1px solid rgba(255, 255, 255, 0.05);
      border-radius: 8px;
      padding: 14px 16px;
      margin-bottom: 24px;
      font-size: 13px;
      line-height: 1.5;
      color: var(--text-muted);
    }
    .info-section strong {
      color: var(--text);
      display: block;
      margin-bottom: 4px;
    }
    .actions {
      display: flex;
      gap: 12px;
    }
    .btn {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      padding: 10px 20px;
      border-radius: 8px;
      font-size: 13px;
      font-weight: 600;
      text-decoration: none;
      cursor: pointer;
      border: 1px solid var(--border);
      transition: all 0.15s ease;
      flex: 1;
    }
    .btn-secondary {
      background: rgba(255, 255, 255, 0.05);
      color: var(--text);
    }
    .btn-secondary:hover {
      background: rgba(255, 255, 255, 0.1);
    }
    .btn-primary {
      background: #2563eb;
      color: #ffffff;
      border-color: #3b82f6;
    }
    .btn-primary:hover {
      background: #1d4ed8;
    }
  </style>
</head>
<body>
  <div class="security-container">
    <svg class="shield-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
      <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
      <line x1="12" y1="8" x2="12" y2="12"/>
      <line x1="12" y1="16" x2="12.01" y2="16"/>
    </svg>
    <div class="header-badge">Aturan Keamanan Aktif</div>
    <h1>403: Akses Ditolak</h1>
    <p class="lead">Permintaan Anda diblokir oleh kebijakan keamanan jaringan gateway. Alamat IP atau pola trafik tidak diizinkan mengakses sumber daya ini.</p>
    
    <div class="diagnostic-box">
      <div class="diagnostic-title">Informasi Diagnostik</div>
      <div class="diagnostic-grid">
        <span class="diag-label">Status Respons:</span>
        <span class="diag-val">HTTP 403 Forbidden</span>
        <span class="diag-label">Aturan Pemicu:</span>
        <span class="diag-val">Access Control List (ACL) / IP Restriction</span>
        <span class="diag-label">Tindakan:</span>
        <span class="diag-val">DROP / FORBIDDEN</span>
      </div>
    </div>

    <div class="info-section">
      <strong>Apa yang dapat Anda lakukan?</strong>
      Jika Anda adalah pengguna sah dan merasa ini merupakan kekeliruan, hubungi pengelola sistem dengan menyertakan waktu akses serta alamat URL yang dituju.
    </div>

    <div class="actions">
      <button type="button" class="btn btn-secondary" onclick="window.history.back()">Kembali ke Halaman Sebelumnya</button>
      <button type="button" class="btn btn-primary" onclick="window.location.reload()">Coba Lagi</button>
    </div>
  </div>
</body>
</html>`

	default:
		return fmt.Sprintf(`HTTP/1.1 %d %s
Content-Type: text/html; charset=UTF-8
Cache-Control: no-cache, no-store, must-revalidate
Connection: close

<!DOCTYPE html>
<html>
<head><title>%d %s</title></head>
<body style="font-family:sans-serif;background:#0f172a;color:#f8fafc;text-align:center;padding:50px">
  <h1>%d %s</h1>
  <p style="color:#94a3b8">Permintaan tidak dapat diproses.</p>
</body>
</html>`, code, statusReason(code), code, statusReason(code), code, statusReason(code))
	}
}

// ParseCode parses status code string safely.
func ParseCode(s string) (int, error) {
	c, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil || c < 400 || c > 599 {
		return 0, fmt.Errorf("kode status tidak valid: %s", s)
	}
	return c, nil
}
