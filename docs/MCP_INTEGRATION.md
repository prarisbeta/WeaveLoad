# Panduan Integrasi dan Konfigurasi Konsol Gateway MCP Server

Dokumen ini menjelaskan cara mengintegrasikan, mengonfigurasi, dan menguji biner `konsolgw-mcp` (Model Context Protocol) untuk HAProxy CNI / Konsol Gateway.

---

## 1. Ikhtisar MCP Server

`konsolgw-mcp` adalah server stdio berbasis JSON-RPC 2.0 yang memungkinkan asisten AI (seperti Claude Desktop, Claude Code, Cursor, Antigravity, dll.) melakukan observasi status HAProxy, investigasi insiden keamanan, dan pengusulan tindakan mitigasi (*Observe → Context → Decide → Propose*).

### Prinsip Keamanan MCP:
1. **AI Bukan Trust Root**: MCP server hanya mengeksekusi operasi pembacaan (READ) dan investigasi (INVESTIGATE).
2. **Human-in-the-Loop**: Aksi perubahan trafik (`propose_action`) hanya berstatus *proposal/usulan* dan memerlukan otorisasi/persetujuan operator manusia sebelum dieksekusi di HAProxy.
3. **Autentikasi Bertoken**: Akses ke API backend dilindungi dengan Bearer Token (`KONSOLGW_API_TOKEN`).

---

## 2. Daftar Tools yang Didukung

| Nama Tool | Kategori | Deskripsi | Parameter |
|---|---|---|---|
| `get_status` | READ | Mengambil status keseluruhan HAProxy (kesehatan live, sesi, metrik CPU/Memory/Disk). | — |
| `list_nodes` | READ | Menampilkan daftar node HAProxy (host) dan pool yang menggunakannya. | — |
| `list_backends` | READ | Menampilkan seluruh backend, status, jumlah server UP/DOWN, dan sesi. | — |
| `list_servers` | READ | Menampilkan detail seluruh server individual di semua backend (status, bobot, drain/maint). | — |
| `list_incidents` | INVESTIGATE | Mengambil daftar insiden keamanan dengan filter. | `status` (opsional), `severity` (opsional), `q` (opsional) |
| `get_incident` | INVESTIGATE | Mengambil detail lengkap insiden tertentu beserta linimasa catatan dan log kejadian keamanan terkait. | `id` (wajib, integer) |
| `propose_action` | PROPOSE | Mengajukan proposal tindakan perbaikan/mitigasi untuk ditinjau oleh operator. | `reason` (wajib, string), `evidence` (wajib, string) |

---

## 3. Konfigurasi Klien AI

### 3.1 Claude Desktop (`claude_desktop_config.json`)

Tambahkan entri berikut ke konfigurasi Claude Desktop Anda (misal di `%APPDATA%\Claude\claude_desktop_config.json` di Windows atau `~/.config/Claude/claude_desktop_config.json` di Linux/macOS):

```json
{
  "mcpServers": {
    "konsol-gateway": {
      "command": "/usr/local/bin/konsolgw-mcp",
      "env": {
        "KONSOLGW_API_URL": "http://127.0.0.1:8080/api/v1",
        "KONSOLGW_API_TOKEN": "<API_TOKEN_ANDA>"
      }
    }
  }
}
```

### 3.2 Claude Code / Antigravity MCP Config (`mcp_config.json`)

```json
{
  "mcpServers": {
    "konsol-gateway": {
      "command": "konsolgw-mcp",
      "args": [],
      "env": {
        "KONSOLGW_API_URL": "http://127.0.0.1:8080/api/v1",
        "KONSOLGW_API_TOKEN": "your-token-here"
      }
    }
  }
}
```

---

## 4. Pengujian Langsung (Manual Stdio)

Anda dapat menguji interaksi JSON-RPC stdio secara langsung dari terminal:

### Inisialisasi:
**Input:**
```json
{"jsonrpc":"2.0","id":1,"method":"initialize"}
```
**Output yang diharapkan:**
```json
{"jsonrpc":"2.0","id":1,"result":{"capabilities":{"tools":{}},"protocolVersion":"2024-11-05","serverInfo":{"name":"konsolgw-mcp","version":"1.0.0"}}}
```

### Melihat Daftar Tools:
**Input:**
```json
{"jsonrpc":"2.0","id":2,"method":"tools/list"}
```

### Memanggil Tool `get_status`:
**Input:**
```json
{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"get_status"}}
```

### Memanggil Tool `list_incidents`:
**Input:**
```json
{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"list_incidents","arguments":{"status":"open"}}}
```

### Memanggil Tool `propose_action`:
**Input:**
```json
{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"propose_action","arguments":{"reason":"Tingkat error 502 tinggi pada bk_api","evidence":"Terdeteksi 150 request 502 dalam 1 menit terakhir pada node 10.0.0.2"}}}
```

---

## 5. Pengujian Unit Otomatis

Pengujian unit otomatis untuk MCP server tersedia di [`cmd/konsolgw-mcp/main_test.go`](../cmd/konsolgw-mcp/main_test.go):
- Memverifikasi protokol JSON-RPC 2.0 (inisialisasi, daftar tool, format error code).
- Memverifikasi integrasi HTTP client terhadap mock API server dengan Bearer token.
- Menguji seluruh pemanggilan tools (`get_status`, `list_nodes`, `list_backends`, `list_servers`, `list_incidents`, `get_incident`, `propose_action`).
