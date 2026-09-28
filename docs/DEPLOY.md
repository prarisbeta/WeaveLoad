# Panduan Deploy Rilis Terbaru ke Server (HAProxy GUI / Konsol Gateway)

Paket rilis biner statis Linux amd64 telah siap dikompilasi beserta template *error files*, MCP server binary, root helpers, dan file konfigurasi.

---

### 📦 Berkas Rilis Siap Upload

| Nama Berkas | Lokasi Lokal | SHA256 Checksum |
| :--- | :--- | :--- |
| **Tarball Rilis** | `dist/haproxy-gui-e2b4fa3.tar.gz` | `281f3b2530fc538cd133c0443d2c1ca5a615ed4121e6d27f7e6fec968b6b3c8b` |
| **Checksum SHA256** | `dist/haproxy-gui-e2b4fa3.tar.gz.sha256` | — |
| **Biner Utama Linux** | `dist/haproxy-gui-e2b4fa3/bin/haproxy-gui` | `3cff2f0c8f3c9277b3b0661cfe41692158485e6f95b993c2e58fc96971c5da77` |
| **Biner MCP Server** | `dist/haproxy-gui-e2b4fa3/bin/konsolgw-mcp` | `c74bbca3e268c9fd273345bfa5ea08f67ad741cc54159e0dcaeb91793a1b23df` |

---

### 🚀 Langkah 1: Upload Berkas Rilis ke Server

Jalankan perintah ini dari terminal lokal Anda (PowerShell / Git Bash / Command Prompt):

```bash
scp -P 2212 dist/haproxy-gui-e2b4fa3.tar.gz dist/haproxy-gui-e2b4fa3.tar.gz.sha256 programmer@103.31.159.8:/tmp/
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
sha256sum -c haproxy-gui-e2b4fa3.tar.gz.sha256

# 2. Ekstrak paket rilis
rm -rf haproxy-gui-e2b4fa3
tar xzf haproxy-gui-e2b4fa3.tar.gz

# 3. Verifikasi checksum biner
sha256sum haproxy-gui-e2b4fa3/bin/haproxy-gui
# Output harus sama dengan: 3cff2f0c8f3c9277b3b0661cfe41692158485e6f95b993c2e58fc96971c5da77

sha256sum haproxy-gui-e2b4fa3/bin/konsolgw-mcp
# Output harus sama dengan: c74bbca3e268c9fd273345bfa5ea08f67ad741cc54159e0dcaeb91793a1b23df

# 4. Pasang biner baru
sudo install -o root -g root -m 755 haproxy-gui-e2b4fa3/bin/haproxy-gui /usr/local/bin/haproxy-gui
sudo install -o root -g root -m 755 haproxy-gui-e2b4fa3/bin/konsolgw-mcp /usr/local/bin/konsolgw-mcp

# 5. Pasang template Error Pages (Waiting Room & Custom Error Pages)
sudo mkdir -p /etc/haproxy/errors
sudo cp -r haproxy-gui-e2b4fa3/deploy/errors/*.http /etc/haproxy/errors/ 2>/dev/null || true
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

### ✅ Pembaruan yang Terintegrasi di Rilis `e2b4fa3`:
1. **🎨 Tampilan Input & Date Picker yang Seragam**: Seluruh form input (`input[type=date]`, `input[type=text]`, `select`, `button`) kini memiliki tinggi (35px), font, padding, border radius, background surface, dan indikator kalender yang selaras sempurna di tema terang dan gelap.
2. **🌐 Dukungan Multibahasa Penuh (ID, EN, ZH, JA)**: Seluruh teks di Dashboard (grafik pie koneksi, deskripsi backend, tombol aksi server, bobot), Nodes, Pools, ACL/Maps, Audit Trail, dan Log Trafik kini 100% dinamis mengikuti pilihan bahasa pengguna (Bahasa Indonesia, English, 中文, 日本語) dengan persistensi cookie dan database.
3. **🔒 Enkripsi Cadangan Terenkripsi (AES-256-GCM)**: Manajemen backup aman di `/etc/haproxy/backups/` dengan pelestarian timestamp modtime riwayat backup.
4. **🤖 Setup & Integrasi Model Context Protocol (MCP)**: Biner `konsolgw-mcp` dengan 7 tools SRE investigasi dan kontrol trafik.
