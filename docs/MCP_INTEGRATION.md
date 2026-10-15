# Integrasi MCP Konsol Gateway dengan Aplikasi Pihak Ketiga

Konsol Gateway menyediakan MCP (Model Context Protocol) lewat **dua jalur** yang menjalankan tool yang sama:

| Jalur | Dipakai oleh | Cara kerja |
|---|---|---|
| **HTTP** `POST /mcp` | Klien yang menerima URL + header: Claude Code, Cursor, VS Code, n8n, Dify, MCP Inspector, skrip | Langsung ke gateway, tanpa memasang apa pun di sisi klien |
| **stdio** `konsolgw-mcp` | Klien yang menjalankan perintah lokal: Claude Desktop, Antigravity | Biner kecil yang memanggil REST `/api/v1` gateway |

Keduanya memakai **token API** (bagian 2). Sebelum perbaikan ini tidak ada cara membuat token, sehingga MCP tidak bisa dikonfigurasi dari aplikasi lain.

---

## 1. Prinsip keamanan

1. **Read-only.** Token hanya bisa membaca status, backend, server, node, dan insiden. Token tidak bisa mengubah konfigurasi, server, pengguna, atau pengaturan. Token bertindak sebagai peran *Auditor*; setiap panggilan tool melewati pemeriksaan autentikasi dan kapabilitas yang sama dengan `/api/v1`.
2. **AI bukan trust root.** `propose_action` hanya **mencatat usulan** sebagai alert aktif di halaman **Alerts** untuk ditinjau operator. Tidak ada yang dieksekusi.
3. **Token disimpan sebagai hash** (SHA-256). Nilai asli tampil **sekali** saat dibuat. Pencabutan berlaku seketika.
4. **Hanya token.** `/mcp` menolak cookie sesi browser, sehingga tidak bisa dipicu dari halaman web lain (CSRF).
5. Pembuatan dan pencabutan token, serta setiap usulan, **tercatat di audit log** (`api_token.create`, `api_token.revoke`, `proposal.create`).

---

## 2. Membuat token

1. Masuk sebagai admin, buka **Pengaturan → Token API**.
2. Isi nama (mis. aplikasi yang memakainya), klik **Buat token**.
3. Salin token (`kgw_...`) **sekarang**; tidak akan ditampilkan lagi.
4. Satu token per aplikasi, supaya bisa dicabut sendiri-sendiri. Kolom *Terakhir dipakai* membantu menemukan token yang tidak terpakai.

Panel **Konfigurasi → Setup MCP / AI** menghasilkan potongan konfigurasi siap salin untuk tiap klien (isi token di kolom yang tersedia) dan tombol **Uji** yang memeriksa REST dan MCP **hanya dengan token** (tanpa sesi login Anda).

---

## 3. Jalur HTTP: `POST /mcp`

* URL: `https://<alamat-gateway>:9443/mcp` (sama dengan alamat GUI).
* Header: `Authorization: Bearer kgw_...`
* Transport: *Streamable HTTP* bentuk sederhana. Tiap `POST` dijawab dengan satu body JSON; notifikasi dijawab `202`; `GET`/`DELETE` dijawab `405` (tidak ada stream server-ke-klien).
* Versi protokol yang didukung: `2025-06-18`, `2025-03-26`, `2024-11-05` (dinegosiasikan saat `initialize`).
* CORS: `OPTIONS /mcp` dijawab tanpa kredensial dan mengizinkan header `Authorization`, sehingga klien berbasis browser bisa memakainya.

### Claude Code
```bash
claude mcp add --transport http konsol-gateway https://103.31.159.8:9443/mcp --header "Authorization: Bearer kgw_..."
```

### Cursor / VS Code / n8n / klien MCP HTTP lain (`mcp.json`)
```json
{
  "mcpServers": {
    "konsol-gateway": {
      "url": "https://103.31.159.8:9443/mcp",
      "headers": { "Authorization": "Bearer kgw_..." }
    }
  }
}
```

### Claude Desktop (lewat `mcp-remote`, butuh Node.js)
```json
{
  "mcpServers": {
    "konsol-gateway": {
      "command": "npx",
      "args": ["-y", "mcp-remote", "https://103.31.159.8:9443/mcp", "--header", "Authorization: Bearer kgw_..."],
      "env": { "NODE_EXTRA_CA_CERTS": "C:\\path\\haproxy-gui-ca.pem" }
    }
  }
}
```

### Uji cepat dengan curl
```bash
curl -sk https://103.31.159.8:9443/mcp \
  -H "Authorization: Bearer kgw_..." -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}'
```

### Catatan jaringan dan TLS
* **Jangkauan.** Alamat `:9443` hanya menerima IP di `/etc/haproxy/maps/admin_allow.lst` (VPN). Aplikasi cloud (mis. claude.ai web) tidak bisa menjangkaunya kecuali IP-nya diizinkan atau gateway dipublikasikan lewat jalur lain; itu keputusan jaringan, bukan perubahan aplikasi.
* **Sertifikat self-signed.** GUI diakses lewat IP dengan sertifikat `haproxy-gui.pem`. Klien harus memercayainya: pasang sertifikatnya sebagai CA tepercaya (Node: `NODE_EXTRA_CA_CERTS`). `NODE_TLS_REJECT_UNAUTHORIZED=0` hanya untuk uji.

---

## 4. Jalur stdio: `konsolgw-mcp`

Variabel lingkungan:

| Variabel | Arti | Bawaan |
|---|---|---|
| `KONSOLGW_API_URL` | Basis REST gateway | `http://127.0.0.1:9900/api/v1` (di server). Dari luar: `https://<alamat>:9443/api/v1` |
| `KONSOLGW_API_TOKEN` | Token API | wajib |
| `KONSOLGW_INSECURE` | `1` = terima sertifikat self-signed | kosong |

Bawaan sebelumnya (`http://localhost:8080`) salah karena gateway tidak mendengarkan di port itu.

### Claude Desktop (`claude_desktop_config.json`) / Antigravity (`mcp_config.json`)
```json
{
  "mcpServers": {
    "konsol-gateway": {
      "command": "konsolgw-mcp",
      "env": {
        "KONSOLGW_API_URL": "https://103.31.159.8:9443/api/v1",
        "KONSOLGW_API_TOKEN": "kgw_...",
        "KONSOLGW_INSECURE": "1"
      }
    }
  }
}
```

Uji tangan lewat stdio:
```bash
echo '{"jsonrpc":"2.0","id":1,"method":"tools/list"}' | KONSOLGW_API_TOKEN=kgw_... konsolgw-mcp
```

---

## 5. Tool

| Tool | Jenis | Deskripsi | Argumen |
|---|---|---|---|
| `get_status` | baca | Status HAProxy, sesi, CPU/Memori/Disk | — |
| `list_nodes` | baca | Node (host) dan pool yang memakainya | — |
| `list_backends` | baca | Backend, status, server UP/DOWN, sesi | — |
| `list_servers` | baca | Semua server di semua backend | — |
| `list_incidents` | baca | Daftar insiden | `status`, `severity`, `q` (opsional) |
| `get_incident` | baca | Detail insiden + catatan + event terkait | `id` (wajib) |
| `propose_action` | usulan | Mencatat usulan untuk operator (tidak mengeksekusi) | `reason`, `evidence` (wajib, maks 2000 karakter) |

Tool baca ditandai `readOnlyHint`, sehingga klien dapat melewati konfirmasi untuknya. Jika API menjawab error (mis. token salah, HTTP 401/403), tool mengembalikan `isError: true` dengan statusnya, bukan seolah-olah sukses.

## 6. REST `/api/v1` (untuk skrip dan n8n tanpa MCP)

Header yang sama: `Authorization: Bearer kgw_...`

* `GET /api/v1/status`, `/backends`, `/servers`, `/nodes`, `/incidents`, `/incidents/{id}`
* `POST /api/v1/proposals` dengan body `{"reason":"...","evidence":"..."}` → `201 {"success":true,"data":{"id":N}}`

## 7. Pengujian otomatis

* `internal/mcp`: protokol (negosiasi versi, notifikasi, batch, error), tool, dan transport HTTP.
* `internal/web/mcp_test.go`: `/mcp` end-to-end melalui middleware autentikasi sungguhan; membuktikan token tidak bisa menjangkau lebih dari yang diizinkan `/api/v1` (tool dijawab HTTP 403), dan `propose_action` bekerja dengan token tanpa CSRF.
* `internal/auth/apitoken_test.go`: token, pencabutan, penolakan sesi pada `/mcp`, CSRF hanya dilewati untuk token.
* `internal/store/apitokens_test.go`: hash, verifikasi, pencabutan, `last_used`.
* `cmd/konsolgw-mcp/main_test.go`: transport stdio terhadap API tiruan.
