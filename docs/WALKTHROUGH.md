# Walkthrough — RBAC, Autentikasi, Antrean, Trafik, Alert, dan Keamanan

Panduan pakai untuk fitur-fitur utama yang telah dibangun di `haproxy-gui` (Konsol Gateway):
RBAC 8-role, Autentikasi Username/Password & 2FA TOTP, Pengelolaan Pengguna, Antrean Rate-Limit, Analisis Trafik, Peringatan Sistem, Security Engine, dan Analisis AI. Untuk konteks perencanaan dan status tiap task, lihat [`IMPLEMENTATION_PLAN.md`](IMPLEMENTATION_PLAN.md).

---

## 1. RBAC 8-role & Autentikasi Pengguna

### Peran yang tersedia

| Peran | Kapabilitas utama |
|---|---|
| **Super Admin** / **Admin Platform** | Semua kapabilitas. |
| **Operator NOC** | Kontrol runtime (drain/ready/weight), lihat log, lihat antrean. |
| **Analis SOC** | Lihat antrean, lihat audit, lihat keamanan, kelola insiden. |
| **SRE** | Kontrol runtime, kelola config, lihat log, lihat antrean. |
| **Admin Keamanan** | Kontrol runtime, kelola config, lihat log/audit/keamanan, kelola insiden, kelola pengaturan. |
| **Auditor** | Lihat log, antrean, audit, keamanan (read-only). |
| **Pengamat (Viewer)** | Tidak ada kapabilitas tambahan — hanya melihat dashboard dasar. |

Peran menentukan menu apa yang muncul di sidebar dan endpoint apa yang bisa diakses — bukan hierarki peringkat, tapi daftar kapabilitas eksplisit per peran (`internal/store/users.go`, `rolePermissions`).

### Mengelola pengguna & Akun Default

1. Buka **Pengguna** (butuh kapabilitas `manage_users` — Admin Platform/Super Admin secara default).
2. Akun admin awal dibuat otomatis hanya jika belum ada (tidak pernah ditimpa saat restart):
   - **Username**: `konsolgw`
   - **Password**: dari `KONSOLGW_BOOTSTRAP_PASSWORD` di `/etc/haproxy-gui/env`; jika kosong, dibuat acak dan dicatat sekali di log (`journalctl -u haproxy-gui | grep "created local admin"`). Ganti setelah login pertama.
   - **Role**: `super_admin`
3. **Tambah Pengguna**: Pendaftaran akun baru dengan kredensial username/password atau integrasi SSO.
4. **Hapus Pengguna**: Admin dapat menghapus pengguna dari daftar pengguna. Sistem mencegah penghapusan akun Anda sendiri untuk keamanan.
5. **Reset Password Admin**: Admin dapat mengatur ulang password pengguna lain langsung dari panel manajemen pengguna.
6. **Ubah Password Mandiri**: Pengguna dapat mengubah password akun mereka sendiri melalui `/api/profile/password`.

### Autentikasi 2FA TOTP

1. Pengguna dapat mengaktifkan **2-Factor Authentication (TOTP)** standar RFC 6238 via `/api/profile/totp`.
2. Saat diaktifkan, QR Code / Secret Key disajikan bersama 8 kode pemulihan (*recovery codes* 8 karakter).
3. Pada halaman Login (`/auth/login-password`), setelah username dan password valid, langkah verifikasi kode TOTP 6-digit atau kode pemulihan akan diminta.
4. **Integrasi Security Engine**: Setiap percobaan login yang gagal menghasilkan respons HTTP 401/403 yang dibaca langsung oleh HAProxy Security Engine untuk deteksi otomatis serangan *brute force*.

---

## 2. Analisis Trafik (`/traffic`)

### Fitur Utama

Halaman **Analisis Trafik** (`/traffic`, butuh kapabilitas `view_logs`) menyajikan visualisasi real-time performa gateway:
1. **Grafik SVG Murni (Pure Go)**: Menampilkan tren *Requests per Second* (req/s) dan persentase *5xx Error Rate* tanpa dependensi JavaScript eksternal.
2. **Top Source IPs**: 10 IP pengirim trafik terbanyak.
3. **Top Request Paths**: Path URL yang paling sering diakses.
4. **Top Hostnames**: Domain / Virtual Host terpopuler.
5. **Backend Paling Lambat**: Daftar backend dengan waktu respons (latency) tertinggi.

---

## 3. Peringatan Sistem (`/alerts`)

### Cara Kerja & Pengelolaan

Halaman **Peringatan Sistem** (`/alerts`) mencatat dan mengawasi kesehatan infrastruktur:
1. **Kategori Alert**: Server DOWN, backend degraded, rasio 5xx melonjak, sertifikat SSL mendekati kedaluwarsa, serta penggunaan disk/memori.
2. **Status Filter**: Pengguna dapat memfilter berdasarkan status `semua`, `belum ditinjau` (unacknowledged), dan `ditinjau` (acknowledged).
3. **Konfirmasi (Acknowledge)**: Tombol konfirmasi mengirimkan `POST /api/alerts/{id}/ack` untuk menandai peringatan telah ditangani.

---

## 4. Analisis AI untuk Insiden & Keamanan

### Fitur AI Assistant

Sistem menyediakan integrasi AI (Anthropic LLM / Mock Provider) untuk membantu investigasi:
1. **Analisis Insiden** (`POST /api/incidents/{id}/ai-analyze`): AI menganalisis linimasa kejadian, dampak service, dan merekomendasikan langkah mitigasi.
2. **Analisis Keamanan** (`POST /api/security/events/{id}/ai-analyze`): Menganalisis pola serangan per IP/Rule dan memberikan wawasan ancaman.
3. **Redaksi Data Sensitif**: Sebelum data dikirim ke LLM, filter sanitasi otomatis menyamarkan token API, kata sandi, dan kunci rahasia untuk menjaga privasi.

---

## 5. Antrean (Queue) rate-limit

### Apa isinya

Setiap kali HAProxy menolak permintaan karena kena rate limit (status 429) pada pool yang punya aturan rate limit, `haproxy-gui` menulis kejadian itu ke sebuah list Redis (`haproxy:ratelimit:events`). Halaman **Antrean** (`/queue`, butuh kapabilitas `view_queue`) mengintip isi list ini.

### API konsumsi eksternal

Sistem eksternal dapat mengambil event dari antrean ini secara destruktif via:

```
POST /api/queue/ratelimit-events/consume?limit=50
Authorization: Bearer <token>
```

---

## 6. Keamanan (Security Engine)

### 7 Detektor Real-Time

Setiap 15 detik, Security Engine mengevaluasi baris log baru lewat 8 detektor: `brute_force`, `rate_anomaly`, `path_scan`, `sensitive_probe`, `http_abuse`, `backend_abuse`, `rate_limited`, dan `threat_intel` (signature serangan CTI di URL: SQLi, XSS, traversal, RFI, command injection, Shellshock, Log4Shell, reverse shell; dipetakan ke MITRE ATT&CK).

Setiap kejadian menambah skor risiko IP (0–100) yang dipetakan ke status: `normal` → `watch` (≥15) → `suspicious` (≥35) → `high_risk` (≥60).

