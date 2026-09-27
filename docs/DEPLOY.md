# Panduan Deploy Rilis Terbaru ke Server (HAProxy GUI)

Paket rilis biner statis Linux amd64 telah siap dikompilasi beserta template *error files*, root helpers, dan file konfigurasi.

---

### 📦 Berkas Rilis Siap Upload

| Nama Berkas | Lokasi Lokal | SHA256 Checksum |
| :--- | :--- | :--- |
| **Tarball Rilis** | `dist/haproxy-gui-1ad6f47.tar.gz` | `d133aafe3427a693079310ba25c2ed961e443416253b872d0a2162b5a4172836` |
| **Checksum SHA256** | `dist/haproxy-gui-1ad6f47.tar.gz.sha256` | — |
| **Biner Statis Linux** | `dist/haproxy-gui-1ad6f47/bin/haproxy-gui` | `fcca273b10f0956149da55d41f56a73326fa799a527b3e41c7dacd2795ba6cd0` |

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
# Output harus sama dengan: fcca273b10f0956149da55d41f56a73326fa799a527b3e41c7dacd2795ba6cd0

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
1. **➕ Tambah Multiple Node/Anggota Saat Buat Pool (`/pools/new`)**: Tombol dinamis **"+ Tambah Node / Anggota Lain"** untuk memasukkan banyak server backend sekaligus dalam wizard pembuatan pool baru.
2. **🪑 Integrasi Batas Laju (Rate Limit) & Ruang Tunggu (Waiting Room)**: Pengunjung yang melebihi batas request otomatis disajikan halaman ruang tunggu interaktif beranimasi (HTTP 429) dengan hitung mundur auto-reload 5 detik.
3. **🎨 Pengelola Halaman Error Kustom (`/config/error-pages`)**: Live interactive preview (Desktop & Mobile) ala Cloudflare untuk HTTP 429, 503, 502, 504, 403, dan 400.
4. **⏸️ Nonaktifkan / Aktifkan Pool (`/pools`)**: Menonaktifkan (disable) atau mengaktifkan kembali (enable) seluruh backend secara instan tanpa menghapus definisinya.
5. **🗑️ Hapus Kelompok Pool (`/pools`)**: Menghapus seluruh pool dan membersihkan map routing domain terkait secara aman dengan auto-rollback.
6. **⚡ Operasi Antrean Enterprise (`/queue`)**: Release IP instan dari stick-table HAProxy, Whitelist VIP IP, Forward to Incident, dan Kosongkan Antrean Redis.
