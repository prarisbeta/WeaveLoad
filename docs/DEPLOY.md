# Panduan Deploy Rilis Terbaru ke Server (HAProxy GUI / Konsol Gateway)

Paket rilis biner statis Linux amd64 telah siap dikompilasi beserta template *error files*, MCP server binary, root helpers, dan file konfigurasi.

---

### 📦 Berkas Rilis Siap Upload

| Nama Berkas | Lokasi Lokal | SHA256 Checksum |
| :--- | :--- | :--- |
| **Tarball Rilis** | `dist/haproxy-gui-62fe96b.tar.gz` | `fca95f26d4c1645afb6a322afe35fefcdc4bd75c24bdd7755f31e4062f9b84b0` |
| **Checksum SHA256** | `dist/haproxy-gui-62fe96b.tar.gz.sha256` | — |
| **Biner Utama Linux** | `dist/haproxy-gui-62fe96b/bin/haproxy-gui` | `8ae2735e8c4b6be2191cc7d9546a0eefd80884ad8f9b665dfa2dc24b957e4aae` |
| **Biner MCP Server** | `dist/haproxy-gui-62fe96b/bin/konsolgw-mcp` | `c74bbca3e268c9fd273345bfa5ea08f67ad741cc54159e0dcaeb91793a1b23df` |

---

### 🚀 Langkah 1: Upload Berkas Rilis ke Server

Jalankan perintah ini dari terminal lokal Anda (PowerShell / Git Bash / Command Prompt):

```bash
scp -P 2212 dist/haproxy-gui-62fe96b.tar.gz dist/haproxy-gui-62fe96b.tar.gz.sha256 programmer@103.31.159.8:/tmp/
```

---

### ⚙️ Langkah 2: Eksekusi Pemasangan di Server

Login ke server melalui SSH:
```bash
ssh -p 2212 programmer@103.31.159.8
```

Lalu jalankan rangkaian perintah berikut:

```bash
cd /tmp

# 1. Verifikasi integritas paket rilis
sha256sum -c haproxy-gui-62fe96b.tar.gz.sha256

# 2. Ekstrak paket rilis
rm -rf haproxy-gui-62fe96b
tar xzf haproxy-gui-62fe96b.tar.gz

# 3. Verifikasi checksum biner
sha256sum haproxy-gui-62fe96b/bin/haproxy-gui
# Output harus sama dengan: 8ae2735e8c4b6be2191cc7d9546a0eefd80884ad8f9b665dfa2dc24b957e4aae

sha256sum haproxy-gui-62fe96b/bin/konsolgw-mcp
# Output harus sama dengan: c74bbca3e268c9fd273345bfa5ea08f67ad741cc54159e0dcaeb91793a1b23df

# 4. Pasang biner baru
sudo install -o root -g root -m 755 haproxy-gui-62fe96b/bin/haproxy-gui /usr/local/bin/haproxy-gui
sudo install -o root -g root -m 755 haproxy-gui-62fe96b/bin/konsolgw-mcp /usr/local/bin/konsolgw-mcp

# 5. Pasang template Error Pages (Waiting Room & Custom Error Pages)
sudo mkdir -p /etc/haproxy/errors
sudo cp -r haproxy-gui-62fe96b/deploy/errors/*.http /etc/haproxy/errors/ 2>/dev/null || true
sudo chown -R root:haproxy /etc/haproxy/errors
sudo chmod 644 /etc/haproxy/errors/*.http

# 6. Pastikan direktori cadangan terisolasi & terenkripsi
sudo mkdir -p /etc/haproxy/backups
sudo chown -R root:haproxy /etc/haproxy/backups
sudo chmod 775 /etc/haproxy/backups

# 7. Restart service HAProxy GUI & cek status
sudo systemctl restart haproxy-gui
sudo journalctl -u haproxy-gui -n 20 --no-pager
```

---

### ✅ Fitur yang Terintegrasi di Rilis `62fe96b`:
1. **🔒 Sistem Cadangan Terenkripsi (AES-256-GCM)**: Seluruh berkas cadangan disimpan di folder terisolasi `/etc/haproxy/backups/`, terenkripsi di disk, dengan tombol Unduh (dekripsi on-the-fly), Rollback instan, dan Hapus.
2. **🤖 Setup & Integrasi Model Context Protocol (MCP)**: Biner `konsolgw-mcp`, panel setup interaktif pada `/config` dengan generator config untuk Antigravity/Claude/Cursor dan test live endpoint.
3. **🚨 Incident Management & Evidence Bundle**: Halaman `/incidents`, linimasa catatan, korelasi kejadian keamanan otomatis, serta ekspor JSON dan CSV.
4. **🪑 Waiting Room & Error Pages Management (`/config/error-pages`)**: Live interactive previewer HTTP 429, 503, 502, 504, 403, 400.
5. **🌐 Framework Multi-Bahasa i18n**: Dukungan antarmuka Bahasa Indonesia dan English.
6. **➕ F5-Style Pool & Node Management**: Wizard pool baru multi-node, inline member edit, batch host maintenance, dan dynamic routing.
