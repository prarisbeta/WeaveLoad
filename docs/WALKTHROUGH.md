# Walkthrough — RBAC, Antrean, dan Keamanan

Panduan pakai untuk tiga fitur yang ditambahkan ke `haproxy-gui` pada 26 September 2026:
RBAC 8-role, Antrean rate-limit + API konsumsi, dan Security Engine. Untuk konteks perencanaan
dan status tiap task, lihat [`IMPLEMENTATION_PLAN.md`](IMPLEMENTATION_PLAN.md).

---

## 1. RBAC 8-role

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

Peran menentukan menu apa yang muncul di sidebar dan endpoint apa yang bisa diakses — bukan
hierarki peringkat, tapi daftar kapabilitas eksplisit per peran (`internal/store/users.go`,
`rolePermissions`). Ini sengaja dipilih karena kebutuhan seperti "Analis SOC boleh lihat data
keamanan/insiden, tapi tidak boleh menyentuh config HAProxy" tidak bisa dinyatakan sebagai
perbandingan peringkat linier.

### Mengelola pengguna

1. Buka **Pengguna** (butuh kapabilitas `manage_users` — Admin Platform/Super Admin secara
   default).
2. Tombol **Tambah Pengguna** untuk mendaftarkan akun baru (login tetap lewat SSO OMS; entri di
   sini hanya menentukan peran awal).
3. Di baris tiap pengguna, dropdown peran bisa diganti langsung. Sistem menolak jika Anda mencoba
   menurunkan peran akun Anda sendiri ke peran tanpa `manage_users` — supaya Anda tidak
   mengunci diri sendiri.

### Upgrade dari skema lama

Jika Anda meng-upgrade dari versi sebelum RBAC 8-role (peran `admin`/`operator`/`viewer`), migrasi
berjalan otomatis saat aplikasi start pertama kali: `admin → platform_admin`,
`operator → noc_operator`, `viewer` tetap `viewer`. Tidak ada akses yang berubah untuk akun yang
sudah ada. **Sebelum meng-upgrade ke rilis ini di server produksi, backup dulu**
`/var/lib/haproxy-gui/app.db` — migrasi ini menulis ulang tabel `users` sekali saja
(idempoten, aman dijalankan ulang, tapi backup tetap prasyarat sebelum aksi tak-rutin di database
produksi).

---

## 2. Antrean (Queue) rate-limit

### Apa isinya

Setiap kali HAProxy menolak permintaan karena kena rate limit (status 429) pada pool yang punya
aturan rate limit, `haproxy-gui` menulis kejadian itu ke sebuah list Redis
(`haproxy:ratelimit:events`). Halaman **Antrean** (`/queue`, butuh kapabilitas `view_queue`) hanya
mengintip isi list ini — tidak menghapusnya.

### Prasyarat

Simpan koneksi Redis di **Pengaturan** (`manage_settings`) terlebih dahulu. Tanpa itu, halaman
Antrean menampilkan status "belum dikonfigurasi".

### API konsumsi eksternal

Sistem lain (mis. modul Incident Management yang akan datang, atau SIEM eksternal) mengambil
event dari antrean ini secara destruktif — sekali diambil, event itu hilang dari list — lewat:

```
POST /api/queue/ratelimit-events/consume?limit=50
Authorization: Bearer <token>
```

Token dibuat dari halaman **Pengaturan** → panel "Token API Konsumsi Antrean" → tombol
**Buat Token** (atau **Buat Ulang Token** untuk mengganti yang lama). Token hanya ditampilkan
sekali saat dibuat — salin dan simpan di tempat aman saat itu juga, aplikasi tidak
menyimpannya dalam bentuk yang bisa ditampilkan ulang.

`limit` opsional (default 50, maksimum 500). Respons:

```json
{"count": 2, "events": [{"time": "...", "pool": "https_oms", "status": "429", "raw": "..."}]}
```

---

## 3. Keamanan (Security Engine)

### Cara kerja singkat

Setiap 15 detik, `haproxy-gui` membaca baris baru dari log akses HAProxy (mulai dari akhir log
saat proses start — tidak memutar ulang riwayat lama), lalu mengevaluasinya lewat 7 detektor.
**Ini murni observasi — tidak ada trafik yang diblokir otomatis.**

| Rule | Yang dideteksi |
|---|---|
| `brute_force` | Login gagal (401/403 pada path login) beruntun dari satu IP dalam 5 menit. |
| `rate_anomaly` | Laju permintaan satu IP jauh di atas kebiasaannya (atau di atas ambang mutlak untuk IP baru). |
| `path_scan` | Banyak path unik + rasio 404 tinggi dari satu IP — ciri pemindaian direktori. |
| `sensitive_probe` | Permintaan ke path yang menandakan probing (`/.env`, `/.git`, `wp-admin`, `/vendor/`, dll.). |
| `http_abuse` | Banjir POST, rasio 4xx/5xx tinggi, atau burst permintaan dalam 10 detik. |
| `backend_abuse` | Satu backend mengalami rasio 5xx tinggi, timeout, atau waktu antrean jauh di atas kebiasaannya. |
| `rate_limited` | IP terkena rate limit (429) berulang kali dalam 5 menit — sinyal tambahan untuk skor risiko. |

Setiap kejadian juga menambah **skor risiko** (0–100) untuk subjeknya (biasanya sebuah IP), yang
meluruh seiring waktu (paruh 2 jam) dan naik jika IP itu memicu beberapa rule berbeda sekaligus.
Skor ini dipetakan ke status: `normal` → `watch` (≥15) → `suspicious` (≥35) → `high_risk` (≥60).
Status `blocked` **tidak pernah** diberikan otomatis oleh sistem — itu keputusan manual atau,
nanti, keputusan Policy Engine (belum dikerjakan).

### Halaman Keamanan

1. Buka **Keamanan** di sidebar (`view_security` — Analis SOC, Admin Keamanan, Auditor, Admin
   Platform, Super Admin).
2. Filter di atas: **Rule**, **Tingkat** (low/medium/high/critical), **Status**
   (terbuka/ditinjau/diabaikan/dieskalasi), **IP**, dan **Periode** (1 jam/24 jam/7 hari).
   Mengubah filter memuat ulang tabel lewat htmx tanpa reload halaman penuh.
3. Panel kanan **"IP Berisiko Tinggi"** menampilkan 10 IP dengan skor tertinggi saat ini,
   dengan tautan ke profil masing-masing.
4. Klik **Status** pada baris kejadian untuk membuka detailnya: bukti (jumlah, ambang yang
   terlampaui, sampel), profil risiko subjek (jika IP), dan tombol aksi.
5. Klik alamat IP di mana pun (tabel, panel risiko, detail kejadian) untuk membuka
   `/security/ip/{ip}` — skor, status, dan seluruh riwayat kejadian untuk IP itu.

### Menindaklanjuti kejadian

Di halaman detail kejadian, tiga tombol aksi (butuh kapabilitas `manage_incidents` — Analis SOC,
Admin Keamanan, Admin Platform, Super Admin):

- **Tandai Ditinjau** — menandai `acknowledged`, tercatat siapa yang meninjau.
- **Abaikan** — menandai `dismissed` (kejadian lama yang sudah diabaikan akan dibersihkan
  otomatis dari database setelah beberapa waktu; kejadian yang masih terbuka/ditinjau tidak
  pernah dihapus otomatis).
- **Eskalasi** — menandai `escalated`, untuk kejadian yang perlu tindak lanjut lebih serius
  (mis. calon insiden, begitu modul Incident Management ada).

Setiap perubahan status tercatat di **Riwayat Aktivitas** (audit log) dengan email peninjau,
IP asal, dan aksi persisnya.

### Yang belum ada (lihat rencana implementasi)

- Ambang deteksi (mis. berapa kali gagal login sebelum dianggap brute force) masih tetap di kode,
  belum bisa diubah dari halaman Pengaturan.
- Belum ada korelasi otomatis kejadian → insiden (modul Incident Management terpisah, belum
  dikerjakan — lihat P7 di `IMPLEMENTATION_PLAN.md`).
- Snapshot risiko per IP dipublikasikan ke Redis (`security:{ip}`) untuk dikonsumsi sistem lain,
  memakai koneksi Redis yang sama dengan fitur Antrean — pastikan itu sudah dikonfigurasi di
  Pengaturan jika Anda ingin sistem eksternal membaca profil risiko ini.
