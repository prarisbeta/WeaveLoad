# Panduan Deploy Rilis Terbaru ke Server (HAProxy GUI)

Paket rilis biner statis Linux amd64 telah siap dikompilasi beserta template *error files*, root helpers, dan file konfigurasi.

---

### 📦 Berkas Rilis Siap Upload

| Nama Berkas | Lokasi Lokal | SHA256 Checksum |
| :--- | :--- | :--- |
| **Tarball Rilis** | `dist/haproxy-gui-1ad6f47.tar.gz` | `d813c17989b3ba9cd940af6fef7e8278c8ed7153f6ae52a77c978f4ea9d53528` |
| **Checksum SHA256** | `dist/haproxy-gui-1ad6f47.tar.gz.sha256` | — |
| **Biner Statis Linux** | `dist/haproxy-gui-1ad6f47/bin/haproxy-gui` | `933a375742e21072e0dcc43071083728af6c9235d697fd6369ad0fb285dbc5e9` |

---

### 🚀 Langkah 1: Upload Berkas Rilis ke Server

Jalankan perintah ini dari terminal lokal Anda:

```bash
scp -P 2212 dist/haproxy-gui-1ad6f47.tar.gz dist/haproxy-gui-1ad6f47.tar.gz.sha256 programmer@103.31.159.8:/tmp/
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
sha256sum -c haproxy-gui-1ad6f47.tar.gz.sha256

# 2. Ekstrak paket rilis
rm -rf haproxy-gui-1ad6f47
tar xzf haproxy-gui-1ad6f47.tar.gz

# 3. Verifikasi checksum biner utama
sha256sum haproxy-gui-1ad6f47/bin/haproxy-gui
# Output harus sama dengan: 933a375742e21072e0dcc43071083728af6c9235d697fd6369ad0fb285dbc5e9

# 4. Pasang biner baru
sudo install -o root -g root -m 755 haproxy-gui-1ad6f47/bin/haproxy-gui /usr/local/bin/haproxy-gui

# 5. Pasang template Error Pages (Waiting Room & Custom Error Pages)
sudo mkdir -p /etc/haproxy/errors
sudo cp -r haproxy-gui-1ad6f47/deploy/errors/*.http /etc/haproxy/errors/ 2>/dev/null || true
sudo chown -R root:haproxy /etc/haproxy/errors
sudo chmod 644 /etc/haproxy/errors/*.http

# 6. Restart service HAProxy GUI & cek status
sudo systemctl restart haproxy-gui
sudo journalctl -u haproxy-gui -n 20 --no-pager
```

---

### ✅ Fitur yang Terintegrasi di Rilis Ini:
1. **🪑 Integrasi Batas Laju (Rate Limit) & Ruang Tunggu (Waiting Room)**: Pengunjung yang melebihi batas request otomatis disajikan halaman ruang tunggu interaktif beranimasi (HTTP 429) dengan hitung mundur auto-reload 5 detik.
2. **🎨 Pengelola Halaman Error Kustom (`/config/error-pages`)**: Live interactive preview (Desktop & Mobile) ala Cloudflare untuk HTTP 429, 503, 502, 504, 403, dan 400.
3. **⏸️ Nonaktifkan / Aktifkan Pool (`/pools`)**: Menonaktifkan (disable) atau mengaktifkan kembali (enable) seluruh backend secara instan tanpa menghapus definisinya.
4. **🗑️ Hapus Kelompok Pool (`/pools`)**: Menghapus seluruh pool dan membersihkan map routing domain terkait secara aman dengan auto-rollback.
5. **⚡ Operasi Antrean Enterprise (`/queue`)**: Release IP instan dari stick-table HAProxy, Whitelist VIP IP, Forward to Incident, dan Kosongkan Antrean Redis.
