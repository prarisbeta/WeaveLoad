# Konsol Gateway — Implementation Plan per Edisi

Versi 0.2 · 26 September 2026 · Acuan: *HAIProxy Enterprise AI SRE Platform — Product Knowledge v0.1*

Konsol Gateway (nama kerja) adalah control plane untuk HAProxy dengan loop **Observe → Context →
Decide → Act → Verify → Audit**. Produk ini dijual dalam 3 edisi dari satu codebase tertutup:
**Community** (gratis), **Professional**, dan **Enterprise**. Rencana ini berisi 101 task, dengan
estimasi ±186 hari kerja untuk satu engineer. Pembagiannya: Community 66 hari, Professional
64 hari, Enterprise 56 hari. Aplikasi `haproxy-gui` yang sekarang berjalan di haproxy-cni
menjadi titik awal, dan tetap dipakai internal (dogfooding) selama pengembangan.

---

## 1. Keputusan produk

| # | Keputusan | Status |
|---|---|---|
| PD-1 | Nama kerja produk: **Konsol Gateway**. Biner `konsolgw`, service `konsol-gateway`. | Diputuskan 26 Sep 2026 |
| PD-2 | Tiga edisi: Community, Professional, Enterprise. | Diputuskan |
| PD-3 | Community **tertutup tapi gratis**: hanya biner yang didistribusikan, di bawah EULA. Source code tetap di repo privat. | Diputuskan |
| PD-4 | **RBAC dasar dan audit dasar masuk Community**. Aplikasi yang bisa drain server dan mengubah config produksi tidak boleh tanpa login dan jejak audit. | Diputuskan |
| PD-5 | Satu biner untuk semua edisi. Fitur dibuka oleh file lisensi bertanda tangan dan divalidasi offline. Tanpa lisensi, biner berjalan sebagai Community. | Diusulkan |
| PD-6 | haproxy-cni menjadi pelanggan pertama dengan lisensi internal Enterprise (butuh SSO OMS). | Diusulkan |

---

## 2. Matriks fitur per edisi

| Kapabilitas | Community | Professional | Enterprise |
|---|---|---|---|
| Jumlah node HAProxy | 1 (all-in-one) | Banyak, 1 site | Multi-site |
| Tenant | 1 | 1 | Multi-tenant |
| Dashboard live + tren (req/s, 5xx, latensi, bytes) | ✓ | ✓ + agregat lintas node | ✓ + per site/tenant |
| Top source/path/host dari log | ✓ | ✓ | ✓ |
| Kontrol server (ready/drain/maint/weight) | ✓ | ✓ | ✓ |
| Kelola pool & node ala F5 (tambah/hapus anggota, inventori node, wizard pool baru) | ✓ | ✓ + lintas node | ✓ |
| ACL/map, editor config + validasi + rollback, SSL | ✓ | ✓ + push ke grup node (canary) | ✓ |
| Rate limit | Statis per IP/host, blocklist manual | + per path, header/API key, burst, TTL, global lintas node | + per tenant |
| Monitoring dasar (alert down/5xx/cert/disk, email + webhook) | ✓ | ✓ | ✓ |
| Login lokal + 2FA TOTP | ✓ | ✓ | ✓ |
| RBAC | 3 role tetap | 5 role (+ auditor, security) | Role kustom + scope site/tenant/backend |
| Audit | Dasar, retensi 30 hari | Before/after, reason, retensi dapat diatur | Hash-chain (immutable), retensi panjang, laporan compliance |
| Action expiry + verifikasi pasca-aksi | — | ✓ | ✓ |
| Approval workflow | — | — | ✓ (berlapis untuk CRITICAL) |
| Security analytics + profil source | — | ✓ | ✓ |
| Incident management + evidence bundle | — | ✓ | ✓ |
| MCP | — | Read + propose | + eksekusi otomatis sesuai policy |
| AI analysis | — | Cloud, BYO API key | + private/on-prem LLM |
| SSO | — | — | OIDC + SAML 2.0 |
| SIEM (syslog/CEF, webhook bertanda tangan) | — | — | ✓ |
| HA control plane | — | — | ✓ |
| Database | SQLite | SQLite atau PostgreSQL | PostgreSQL (+ Redis untuk HA) |
| Bahasa UI | ID + EN | ID + EN | ID + EN |
| Support | Forum/dokumentasi | Email, jam kerja | 24x7 + SLA |

---

## 3. Arsitektur target

### 3.1 Komponen

```
                     ┌──────────────── konsolgw server ────────────────┐
  Browser / MCP ───► │ UI · API /api/v1 · Policy · Approval · Workers   │
                     │ (sampler agregat, detektor, verifier, reaper)    │
                     │ Store: SQLite | PostgreSQL   (+ Redis saat HA)   │
                     └───────────▲──────────────────────▲───────────────┘
                                 │ gRPC + mTLS          │ (agent yang memulai koneksi keluar)
                   ┌─────────────┴────────┐   ┌─────────┴────────────┐
                   │ konsolgw agent       │   │ konsolgw agent       │
                   │ socket · tail log ·  │   │ ...                  │
                   │ apply map/config     │   │                      │
                   │ HAProxy node A       │   │ HAProxy node B       │
                   └──────────────────────┘   └──────────────────────┘
```

- **Mode `all-in-one`** (Community): server dan agent dalam satu proses di node HAProxy. Pemanggilan agent dilakukan in-process, tanpa gRPC.
- **Mode `server` + `agent`** (Professional/Enterprise): biner yang sama, dijalankan dengan subcommand berbeda.
- Agent **selalu yang memulai koneksi** ke server, sehingga node HAProxy tidak perlu membuka port masuk baru.
- Semua mutasi HAProxy tetap dieksekusi di node oleh agent, lewat helper sudo yang sempit (pola `haproxy-gui-apply.sh` yang sudah ada).

### 3.2 Prinsip yang dibawa dari dokumen acuan

| # | Prinsip | Penerapan |
|---|---|---|
| AP-1 | AI bukan trust root | AI (lewat MCP atau UI) hanya bisa `propose`. Eksekusi selalu lewat `ActionService` → Policy → (Approval) → Agent → Verify → Audit. |
| AP-2 | Kegagalan control plane tidak mengubah trafik | Enforcement berupa entry map/ACL/stick-table di HAProxy. Jika server atau agent mati, HAProxy tetap jalan dengan state valid terakhir. Command ke agent kedaluwarsa dalam 60 detik agar aksi basi tidak dieksekusi belakangan. |
| AP-3 | Aksi darurat tidak jadi drift | TTL wajib untuk block/rate limit (Pro+). Reaper mengembalikan state, termasuk setelah restart. |
| AP-4 | Lisensi tidak pernah mematikan trafik | Lisensi kedaluwarsa → masa tenggang 14 hari → turun ke fitur Community. Data tetap bisa dibaca dan diekspor. Agent tidak pernah menghapus konfigurasi HAProxy karena status lisensi. |

### 3.3 Lisensi dan gating edisi

- File lisensi JSON ditandatangani **Ed25519**: `{license_id, customer, edition, max_nodes, max_sites, max_tenants, features[], issued_at, expires_at}`. Public key tertanam di biner. Validasi sepenuhnya offline, sehingga bisa dipakai di jaringan tertutup.
- Paket `internal/edition`: `Has(feature)`, middleware `RequireFeature`, helper template untuk menyembunyikan atau menonaktifkan menu (dengan keterangan "Tersedia di Professional").
- Private key disimpan offline oleh tim. Penerbitan lewat tool internal `konsolgw-license` di repo terpisah.
- Biner Go bisa di-patch untuk melewati cek lisensi. Ini risiko yang diterima: nilai edisi berbayar ada di update, support, dan fitur server-side. Tidak ada investasi besar untuk anti-tamper. Obfuscation (`garble`) opsional.

### 3.4 Storage

| Edisi | Store | Catatan |
|---|---|---|
| Community | SQLite (WAL) | Satu node, target DB < 300 MB. |
| Professional | SQLite atau PostgreSQL | PostgreSQL disarankan di atas 5 node. |
| Enterprise | PostgreSQL wajib, Redis untuk HA | Redis dipakai untuk pub/sub antar replika, distributed lock, dan leader election worker singleton (reaper, detektor, verifier). |

Rate limit selalu ditegakkan oleh stick-table HAProxy di tiap node. "Global lintas node" (Pro+)
berarti server menjumlahkan rate per node dari agent (tiap 10 detik) lalu mendorong entry block
atau limit ke semua node. Rate limit global ini terlambat ±10 detik, dan hal itu dicantumkan di dokumentasi.

---

## 4. Ringkasan roadmap

| Milestone | Isi | Estimasi | Kumulatif |
|---|---|---|---|
| **Community 1.0** | Generalisasi, fondasi, lisensi, SEE, rate limit dasar, monitoring dasar, pool & node, packaging | 66 hari | 66 |
| **Professional 1.0** | Agent/server, PostgreSQL, rate limit lanjutan, governance dasar, verifikasi, security analytics, insiden, MCP, AI | 64 hari | 130 |
| **Enterprise 1.0** | Multi-site, multi-tenant, HA, SSO/SAML, approval, compliance, SIEM, AI automation, private LLM | 56 hari | 186 |

Dengan 2 engineer, Professional dan Enterprise bisa dikerjakan tumpang tindih setelah P1
(agent/server) selesai. Total waktu kalender menjadi sekitar 5–6 bulan.

Format ID task: `C`/`P`/`E` + nomor epic + nomor task. Estimasi dalam hari kerja (h). Semua
task mengikuti TDD dengan coverage ≥ 80% per paket.

---

## 5. Community 1.0 (66 h)

### C0 — Rebranding dan generalisasi (10,5 h)

| ID | Task | Detail | Kriteria selesai | Est. |
|---|---|---|---|---|
| C0-1 | Rename produk | Module Go `haproxy-gui` → `konsolgw`. Path `/etc/konsol-gateway`, `/var/lib/konsol-gateway`, unit `konsol-gateway.service`. Perintah `konsolgw migrate-from-haproxy-gui` menyalin DB dan env lama. | Instalasi haproxy-cni pindah tanpa kehilangan user/audit. | 1,5 |
| C0-2 | File konfigurasi | `config.yaml` + override env. Pindahkan semua nilai yang ditulis langsung di kode ke config: daftar map/ACL (sekarang di `routes.go`), path log, socket, disk. Validasi saat start dengan pesan error yang jelas. | Tidak ada path spesifik haproxy-cni di kode. | 1,5 |
| C0-3 | Login lokal + 2FA | Password argon2id, setup wizard saat pertama jalan (token sekali pakai tampil di journal), TOTP opsional, lockout setelah 5 kali gagal, perintah `konsolgw user reset-password`. | Instalasi baru bisa dipakai tanpa SSO. Test brute-force lockout. | 3 |
| C0-4 | SSO OMS → modul provider | Pindahkan OIDC dan pencarian direktori OMS ke interface `auth.Provider` / `directory.Provider` di bawah fitur `sso` (Enterprise). | haproxy-cni tetap login lewat OMS dengan lisensi internal. | 1 |
| C0-5 | i18n ID/EN | Katalog pesan, fungsi template `t`, preferensi bahasa per user, default dari `Accept-Language`. | Semua teks UI ada di katalog. Test mencegah string yang lupa diterjemahkan. | 2,5 |
| C0-6 | TLS bawaan | Sertifikat self-signed otomatis saat instalasi pertama, atau sertifikat dari user. Proxy lewat HAProxy menjadi opsional. | Bisa diakses langsung di `https://<host>:9443`. | 1 |

### C1 — Fondasi (7,5 h)

| ID | Task | Detail | Kriteria selesai | Est. |
|---|---|---|---|---|
| C1-1 | Migrasi DB berversi | Daftar migrasi berurutan per dialect (SQLite sekarang, PostgreSQL disiapkan untuk P2), `PRAGMA user_version`, WAL, `busy_timeout`. Backup otomatis `app.db` sebelum migrasi. | Salinan DB produksi haproxy-cni naik versi di CI. | 1,5 |
| C1-2 | Lab HAProxy 2.8 | `lab/docker-compose.yml`: `haproxy:2.8` + 2 backend dummy + socket bersama + log ke file. | `make lab-up`. Test integrasi memakai lab. | 2 |
| C1-3 | Kerangka worker | `internal/worker`: supervisor, restart + backoff, shutdown bersih. | Worker yang panik tidak mematikan proses. | 1 |
| C1-4 | HTTP API `/api/v1` | JSON `{success, data, error, meta}`. Auth via session atau Bearer token. | `status`, `backends`, `servers` + test. | 2 |
| C1-5 | Token API per user | Hash SHA-256, label, masa berlaku, pencabutan, tampil sekali. | Token dicabut → 401. Tercatat di audit. | 1 |

### C2 — Lisensi dan edisi (5 h)

| ID | Task | Detail | Kriteria selesai | Est. |
|---|---|---|---|---|
| C2-1 | Paket `internal/edition` | Enum fitur, `Has()`, middleware `RequireFeature`, helper template, default Community. | Test tiap route berfitur terhadap 3 edisi. | 1,5 |
| C2-2 | Validasi lisensi | Parse + verifikasi Ed25519, cek masa berlaku, tenggang 14 hari, turun ke Community. Halaman "Lisensi" untuk upload dan melihat status. | Lisensi palsu/rusak ditolak. Lisensi kedaluwarsa tidak mengubah trafik (AP-4). | 2 |
| C2-3 | Tool penerbit lisensi | `konsolgw-license` di repo privat terpisah + prosedur penyimpanan private key (offline, 2 pemegang). | Lisensi internal haproxy-cni terbit. | 1 |
| C2-4 | Batas Community | Hanya mode all-in-one, 1 node, 1 tenant. | Mode `server` menolak agent kedua tanpa lisensi Pro. | 0,5 |

### C3 — SEE: metrik trafik (12 h)

| ID | Task | Detail | Kriteria selesai | Est. |
|---|---|---|---|---|
| C3-1 | Perluas parser `show stat` | Kolom `stot, bin, bout, req_rate, rate, hrsp_*, econ, eresp, qcur, rtime, ttime, chkfail, downtime`. Kolom yang hilang bernilai 0, tidak error. | Fixture CSV asli ter-parse. | 1 |
| C3-2 | Sampler metrik | Tiap 30 detik, simpan delta counter ke `metrics_raw`. Reset counter (reload HAProxy) terdeteksi dan sampelnya dibuang. | Tidak ada lonjakan palsu setelah reload. | 2 |
| C3-3 | Retensi + rollup | Raw 48 jam, rollup 5 menit 30 hari, hapus bertahap. | DB stabil < 300 MB untuk ±40 server. | 1 |
| C3-4 | Tailer log inkremental | Offset tersimpan, aman terhadap logrotate, parser `httplog` penuh (IP, frontend, backend/server, timer, status, bytes, Host, method, path). | Tidak ada baris ganda/hilang saat rotate. | 3 |
| C3-5 | Agregasi log per menit | `log_agg_1m` + `log_top_1m` (IP, path tanpa query, host, status). Retensi 7 hari. | Top 10 IP dalam 1 jam < 200 ms. | 2 |
| C3-6 | Grafik tren | req/s, rasio 5xx, p95 latensi, bytes. Rentang 1 jam/24 jam/7 hari. SVG dirender server, tanpa JS eksternal. | Benar di light/dark. CSP tidak berubah. | 2 |
| C3-7 | Halaman Traffic | Top source/path/host/status, backend paling lambat, filter waktu/backend. | Penyebab lonjakan terlihat tanpa membuka log mentah. | 1 |

### C4 — Rate limit dan blocklist dasar (4 h)

| ID | Task | Detail | Kriteria selesai | Est. |
|---|---|---|---|---|
| C4-1 | Wizard "Aktifkan proteksi" | Membuat potongan config (stick-table per IP `http_req_rate(10s)`, `track-sc0 src`, deny 403 untuk `blocklist_ip.lst`, deny 429 untuk host di `ratelimit_host.map`) untuk frontend yang dipilih. Ditampilkan sebagai diff, lalu diterapkan lewat alur validasi + rollback yang sudah ada. | Di lab: map kosong = tanpa efek. IP diblok → 403. Host melewati ambang → 429. | 2 |
| C4-2 | UI aturan statis | Limit per IP dan per host, blocklist manual, allowlist yang tidak bisa diblok (IP internal/VPN). Runtime + file. | Entry allowlist ditolak saat akan diblok (test). | 2 |

### C5 — Monitoring dasar (4,5 h)

| ID | Task | Detail | Kriteria selesai | Est. |
|---|---|---|---|---|
| C5-1 | Aturan alert | Server DOWN > N menit, backend tanpa server UP, rasio 5xx > X%, sertifikat kedaluwarsa < 30/14 hari, disk > 85%. Ada ambang default. | Alarm tidak muncul saat reload HAProxy. | 2 |
| C5-2 | Kanal notifikasi | Email SMTP + webhook JSON generik. Dedup 15 menit. Ada notifikasi "pulih". | Test pengiriman dengan server SMTP/webhook palsu. | 1,5 |
| C5-3 | Riwayat alert | Halaman daftar alert + acknowledge. | Acknowledge tercatat di audit. | 1 |

### C6 — RBAC dan audit dasar (1,5 h)

| ID | Task | Detail | Kriteria selesai | Est. |
|---|---|---|---|---|
| C6-1 | Kelola user lokal | Buat, nonaktifkan, ubah role (admin/operator/viewer). Admin tidak bisa menurunkan role dirinya sendiri. | Test RBAC per route. | 1 |
| C6-2 | Retensi audit Community | 30 hari (tetap). Ekspor CSV (sudah ada). | Job retensi berjalan harian. | 0,5 |

### C8 — Pool dan node ala F5 (11 h)

Tujuan: menambah dan melepas server di sebuah pool semudah di F5 BIG-IP (Local Traffic → Pools →
Members → Add), tanpa menyentuh editor config mentah. Pemetaan konsep: Node = host di baris
`server`, Pool = `backend`, Member = baris `server`, Ratio = `weight`, Priority group = `backup`,
Force Offline = `maint`, Virtual Server = `frontend` + map host. File config tetap menjadi sumber
kebenaran. Setiap perubahan melewati validasi `haproxy -c`, helper apply (backup, reload,
rollback otomatis), dan audit.

| ID | Task | Detail | Kriteria selesai | Est. |
|---|---|---|---|---|
| C8-1 | Parser struktur config | Paket `internal/haproxycfg`: pool (backend/listen), anggota, balance, health check, cookie. Tambah/hapus satu baris `server` tanpa mengubah baris lain (komentar, CRLF, indentasi tetap). Anggota baru menyalin pengaturan SSL/SNI/check dari anggota contoh. | **Selesai** (26 Sep 2026). Coverage 94%. | 2 |
| C8-2 | Halaman Kelompok Server + Node | `/pools`, `/pools/{name}` (anggota + status live + tombol aktifkan/kosongkan/nonaktifkan), form tambah anggota dengan pratinjau baris + `haproxy -c`, hapus anggota hanya jika MAINT atau DRAIN tanpa koneksi. `/nodes`: host → pool yang memakainya + pintasan "tambahkan ke kelompok". Tambah/hapus = admin, state/bobot = operator. | **Selesai** (26 Sep 2026), menunggu deploy. | 2 |
| C8-3 | Status runtime bertahan saat reload | Helper apply menyimpan `show servers state` sebelum reload. Config memakai `server-state-file` + `load-server-state-from-file global`. | **Kode selesai**. Perlu 2 baris config di haproxy-cni. Server yang di-MAINT tetap MAINT setelah anggota lain ditambah (uji di lab C1-2). | 0,5 |
| C8-4 | Edit anggota | Ubah bobot, maxconn, backup, dan alamat/port anggota secara permanen di config (bukan hanya runtime). Tombol "Simpan bobot runtime ke config". | Diff hanya menyentuh baris anggota itu. | 1,5 |
| C8-5 | Inventori node | Tabel `nodes` (host, nama, catatan, tag). Aksi tingkat node: nonaktifkan/kosongkan di **semua** pool sekaligus (seperti menonaktifkan Node di F5) untuk maintenance mesin. | Satu klik men-drain CESIUM02 di ±25 pool, tercatat sebagai satu aksi di audit. | 2 |
| C8-6 | Wizard pool + virtual server | Buat pool baru (nama, metode balance, health check host/path/status, HTTP/HTTPS + SNI, cookie sticky) dan rutekan host ke pool itu lewat map `hosts_http.map`/`hosts_https.map`. | Situs baru bisa dipublikasikan tanpa membuka editor config. | 3 |

### C7 — Packaging dan rilis (10 h)

| ID | Task | Detail | Kriteria selesai | Est. |
|---|---|---|---|---|
| C7-1 | Pipeline build | linux amd64 + arm64, versi disematkan lewat `-ldflags`, paket RPM (EL7/8/9) dan DEB (Ubuntu 22.04/24.04, Debian 12) via nfpm, tarball, image Docker. | Satu perintah menghasilkan semua artefak. | 2 |
| C7-2 | Tanda tangan rilis | `SHA256SUMS` + tanda tangan minisign/cosign. | Installer memverifikasi tanda tangan sebelum pasang. | 0,5 |
| C7-3 | Installer + `konsolgw doctor` | Deteksi OS, user service, izin socket/log, versi HAProxy ≥ 2.4, sudoers helper. `doctor` memeriksa semuanya dan memberi saran perbaikan. | Instalasi bersih di VM EL9 dan Ubuntu 24.04 < 10 menit. | 1,5 |
| C7-4 | Jalur upgrade | Backup DB otomatis, migrasi, rollback terdokumentasi. | Upgrade dari versi sebelumnya lolos di CI. | 1 |
| C7-5 | Dokumentasi | Instalasi, quickstart, referensi config, hardening keamanan (ID + EN). | Orang baru bisa memasang tanpa bantuan (uji dengan 1 orang). | 3 |
| C7-6 | Distribusi | Halaman unduh + persetujuan EULA Community, catatan rilis. | EULA disetujui tim legal (lihat §9). | 1 |
| C7-7 | Migrasi dogfood | haproxy-cni pindah dari `haproxy-gui` ke Konsol Gateway (all-in-one + lisensi internal). | Tidak ada downtime GUI > 5 menit. Audit lama tetap ada. | 1 |

---

## 6. Professional 1.0 (64 h)

### P1 — Agent dan control plane (16 h)

| ID | Task | Detail | Kriteria selesai | Est. |
|---|---|---|---|---|
| P1-1 | Pemisahan kode | Paket `agent` (socket, tailer, apply file, helper) dan `server`. Interface `NodeClient` dengan implementasi in-process (all-in-one) dan remote (gRPC). | All-in-one tetap lolos semua test lama. | 3 |
| P1-2 | Protokol gRPC | mTLS, agent yang memulai koneksi, stream dua arah: telemetri naik, command turun, ack berisi hasil. Heartbeat 10 detik. Command kedaluwarsa 60 detik. | Agent reconnect otomatis. Command basi tidak dieksekusi. | 3 |
| P1-3 | Enrollment node | Token join sekali pakai (TTL 1 jam) → agent membuat key + CSR → CA internal menandatangani. Rotasi sertifikat 90 hari. Node bisa dicabut. | Node yang dicabut langsung ditolak. | 2 |
| P1-4 | Buffer offline | Agent menyimpan agregat metrik/log di disk (maks. 256 MB / 24 jam) saat server tidak terjangkau, lalu mengirim ulang. | Tidak ada celah data setelah server down 1 jam. | 1,5 |
| P1-5 | Inventaris node | Daftar node, status, versi agent/HAProxy, last seen, grup node. | Node offline > 1 menit ditandai. | 2 |
| P1-6 | Push config ke grup | Render → validasi `haproxy -c` di tiap node → canary 1 node → sisanya. Berhenti dan rollback jika gagal. | Di lab 3 node: config rusak berhenti di canary. | 3 |
| P1-7 | Dashboard agregat | Gabungan semua node + filter per node. | Angka agregat = jumlah per node (test). | 1,5 |

### P2 — PostgreSQL (5 h)

| ID | Task | Detail | Kriteria selesai | Est. |
|---|---|---|---|---|
| P2-1 | Implementasi store PostgreSQL | Interface store, migrasi dua dialect, CI matrix SQLite + PostgreSQL 15/16. | Semua test store lolos di kedua dialect. | 3,5 |
| P2-2 | Tool migrasi SQLite → PostgreSQL | `konsolgw migrate-db --to postgres://...` dengan verifikasi jumlah baris. | Migrasi DB haproxy-cni berhasil di staging. | 1,5 |

### P3 — Rate limit lanjutan (6 h)

| ID | Task | Detail | Kriteria selesai | Est. |
|---|---|---|---|---|
| P3-1 | Dimensi tambahan | Per path prefix, per header/API key (`req.hdr(X-API-Key)`), burst dua jendela (10 detik + 1 menit). | Setiap dimensi diuji di lab dengan `hey`. | 3 |
| P3-2 | TTL aturan | Aturan sementara dengan kedaluwarsa otomatis (pakai reaper P4-6). | Aturan hilang dari runtime + file saat kedaluwarsa. | 1 |
| P3-3 | Limit global lintas node | Server menjumlahkan rate per node dari `show table` tiap 10 detik, lalu mendorong block/limit ke semua node. | Di lab 2 node: limit gabungan tercapai dengan jeda ≤ 15 detik. | 2 |

### P4 — Governance dasar (10 h)

| ID | Task | Detail | Kriteria selesai | Est. |
|---|---|---|---|---|
| P4-1 | Model aksi terpadu | `internal/action`: semua mutasi (server, map/ACL, config, cert, user, rate limit) lewat `ActionService`. Handler hanya parse + panggil service. | Test arsitektur: tidak ada mutasi runtime di luar `internal/action`. | 3 |
| P4-2 | Katalog risk class | Risk class tetap per jenis aksi (§8.1). | Aksi tanpa risk class gagal di test. | 1 |
| P4-3 | Policy engine | `Evaluate(action, user) → Allow / Deny / RequireApproval` + alasan. Di Pro, `RequireApproval` diperlakukan sebagai Allow + wajib reason ≥ 30 karakter. Approval sesungguhnya ada di E5. | 100% cabang ter-test. | 1,5 |
| P4-4 | Reason wajib | Untuk MEDIUM ke atas, divalidasi di server. | Form tanpa alasan ditolak. | 0,5 |
| P4-5 | Audit v2 | `reason, risk, decision, before_state, after_state, result, verify_status, action_id, source`. Retensi dapat diatur. | Setiap aksi punya before/after. | 2 |
| P4-6 | Aksi sementara + reaper | TTL untuk drain/maint/weight/block/limit. Reaper tiap 30 detik, tahan restart. | Drain 15 menit kembali `ready` walau app di-restart di tengah. | 1,5 |
| P4-7 | Role tambahan | `auditor` (baca semua termasuk audit) dan `security` (block/limit, tanpa config). | Test RBAC per role. | 0,5 |

### P5 — Verifikasi pasca-aksi (5 h)

| ID | Task | Detail | Kriteria selesai | Est. |
|---|---|---|---|---|
| P5-1 | Ekspektasi per aksi | Cek per jenis aksi (§8.1 kolom verifikasi). | Setiap aksi punya minimal satu cek. | 1,5 |
| P5-2 | Worker verifier | Cek pada +2 dan +10 menit. Hasil: `improved` / `no_change` / `degraded` / `inconclusive`. | Test dengan data sintetis untuk tiap hasil. | 2 |
| P5-3 | Tampilan + tombol kembalikan | Badge di audit/dashboard. `degraded` → banner + tombol revert lewat jalur policy yang sama. | Revert merujuk `action_id` asal. | 1,5 |

### P6 — Security analytics (8,5 h)

| ID | Task | Detail | Kriteria selesai | Est. |
|---|---|---|---|---|
| P6-1 | Kerangka detektor | Rule tiap 1 menit → `events` (dedup 15 menit). Ambang di DB, bisa diubah admin (ter-audit). Ada mode "observe only". | Rule baru = satu file + test. | 2 |
| P6-2 | Rule keamanan | Burst per IP, auth abuse (401/403), path scanning (404 unik), probe sensitif (`/.env`, `/.git/`, `/wp-admin`, dll.). | Test positif/negatif dari fixture log. | 3 |
| P6-3 | Rule reliabilitas | 5xx > 3× baseline jam yang sama, p95 > 2× baseline, server flapping, antrean `qcur` > 0 selama ≥ 2 menit. | Tidak ada alarm palsu saat reload. | 2 |
| P6-4 | Profil source | Ringkasan IP: req, host/path, status, event, riwayat mitigasi, status allowlist. | Terbuka < 500 ms untuk data 7 hari. | 1,5 |

### P7 — Incident management (3,5 h)

| ID | Task | Detail | Kriteria selesai | Est. |
|---|---|---|---|---|
| P7-1 | Insiden + timeline | Status open/investigating/mitigated/resolved, owner, event yang dikorelasikan otomatis (subjek/backend sama), aksi, verifikasi, catatan. | Timeline lengkap dari event pertama sampai resolved. | 2,5 |
| P7-2 | Evidence bundle | Ekspor JSON + CSV: event, log mentah (maks. 1.000 baris), metrik jendela waktu, aksi. | Bisa dibaca tanpa akses ke server. | 1 |

### P8 — MCP (5 h)

| ID | Task | Detail | Kriteria selesai | Est. |
|---|---|---|---|---|
| P8-1 | API baca + investigasi | `/api/v1`: traffic, events, incidents, sources, audit, `policy/check` (dry-run). | RBAC sama dengan UI. | 2 |
| P8-2 | Biner `konsolgw-mcp` | MCP server stdio, konfigurasi base URL + token dari env. Tools di §8.3. | Dipakai dari Claude Code/Desktop di laptop operator. | 2 |
| P8-3 | Tool `propose_action` | Membuat aksi `proposed` dengan `source=ai` + reason + evidence. Tidak pernah dieksekusi tanpa klik manusia. | Test: tidak ada jalur MCP yang mengeksekusi aksi. | 1 |

### P9 — AI analysis BYO key (4 h)

| ID | Task | Detail | Kriteria selesai | Est. |
|---|---|---|---|---|
| P9-1 | Provider abstraction | Interface `ai.Provider`. Implementasi pertama Anthropic (`claude-sonnet-5`). API key pelanggan disimpan terenkripsi. | Ganti provider tanpa mengubah pemanggil. | 1,5 |
| P9-2 | Investigasi terstruktur | Output schema `{observed, analysis, recommendation, risk, evidence[]}`. Penyamaran data (IP internal, cookie, query string) sebelum dikirim. Rekomendasi → `propose_action`. | Output selalu valid schema. Kegagalan API tidak memblokir UI. | 2 |
| P9-3 | Batas pemakaian | Pencatatan token/biaya per investigasi, kuota bulanan per instalasi. | Kuota habis → pesan jelas, tidak error. | 0,5 |

### P10 — Lisensi Professional (1 h)

| ID | Task | Detail | Kriteria selesai | Est. |
|---|---|---|---|---|
| P10-1 | Penegakan batas | `max_nodes`, gating fitur Pro, banner lisensi hampir kedaluwarsa (30 hari). | Agent melebihi batas ditolak dengan pesan jelas. Node yang sudah ada tidak terputus. | 1 |

---

## 7. Enterprise 1.0 (56 h)

| ID | Task | Detail | Kriteria selesai | Est. |
|---|---|---|---|---|
| **E1** | **Multi-site** | | | **5** |
| E1-1 | Entitas site | Node milik site, tampilan dan filter per site, ringkasan kesehatan semua site. | Site offline tidak mengganggu site lain. | 3 |
| E1-2 | Policy per site | Aturan rate limit, alert, dan jendela maintenance per site. Toleransi latensi WAN untuk agent. | Agent dengan latensi 300 ms stabil di lab. | 2 |
| **E2** | **Multi-tenant** | | | **10** |
| E2-1 | Model tenant | `tenant_id` di semua data tenant. Penegakan di lapisan store (bukan hanya handler). | Test kebocoran: query tanpa tenant gagal. | 4 |
| E2-2 | Pemetaan host → tenant | Trafik, event, dan insiden dikelompokkan per tenant dari Host/backend. | Tenant A tidak melihat data tenant B (test E2E). | 3 |
| E2-3 | Admin tenant + limit per tenant | Role admin tenant, rate limit per tenant, laporan per tenant. | Admin tenant tidak bisa mengubah config global. | 3 |
| **E3** | **HA control plane** | | | **8** |
| E3-1 | Server stateless | Sesi di PostgreSQL, 2+ replika di belakang load balancer. Agent bisa terhubung ke replika mana saja. | Matikan satu replika → UI dan agent tetap jalan. | 3 |
| E3-2 | Redis: koordinasi | Pub/sub antar replika, distributed lock, leader election untuk reaper/detektor/verifier. | Worker singleton tidak pernah jalan ganda (test chaos). | 3 |
| E3-3 | Panduan HA database | Rekomendasi PostgreSQL HA (Patroni atau layanan terkelola) + uji failover. | Failover DB < 60 detik tanpa kehilangan audit. | 2 |
| **E4** | **SSO** | | | **6** |
| E4-1 | OIDC generik | Port dari implementasi OMS, konfigurasi issuer/claim bebas. | Diuji dengan Keycloak, Entra ID, OMS. | 2 |
| E4-2 | SAML 2.0 | SP-initiated + IdP-initiated, metadata upload. | Diuji dengan Keycloak dan ADFS/Entra. | 2,5 |
| E4-3 | Mapping grup → role + JIT | Provisioning otomatis, opsi "hanya SSO" (login lokal dinonaktifkan kecuali break-glass). | User keluar dari grup → akses dicabut saat login berikutnya. | 1,5 |
| **E5** | **RBAC lanjutan + approval** | | | **6** |
| E5-1 | Role kustom + scope | Kumpulan permission, scope per site/tenant/grup backend. | Matriks permission ter-test. | 2,5 |
| E5-2 | Approval workflow | HIGH → 1 approver, CRITICAL → 2 approver. Approver ≠ requester. Kedaluwarsa 30 menit. Notifikasi email/webhook. | Self-approve ditolak. Approval kedaluwarsa tidak bisa dieksekusi. | 2,5 |
| E5-3 | Break-glass + change record | Self-approve darurat dengan reason ≥ 50 karakter, disorot di audit + notifikasi. Kolom nomor tiket perubahan untuk CRITICAL. | Setiap break-glass memicu notifikasi. | 1 |
| **E6** | **Audit dan compliance** | | | **6** |
| E6-1 | Audit immutable | Hash-chain (tiap baris menyimpan hash baris sebelumnya) + perintah verifikasi integritas. | Perubahan satu baris terdeteksi. | 2 |
| E6-2 | Retensi + arsip | Retensi 1–7 tahun, arsip ke file/object storage. | Arsip bisa diverifikasi ulang. | 1,5 |
| E6-3 | Laporan compliance | Laporan bulanan perubahan, review akses, aksi privileged (PDF + CSV). | Laporan cocok dengan audit mentah. | 2,5 |
| **E7** | **Integrasi SIEM** | Syslog RFC 5424 + CEF (TCP/TLS), webhook dengan tanda tangan HMAC, schema event JSON terdokumentasi. Diuji dengan Wazuh dan Elastic. | Semua event + audit terkirim. Tidak ada kehilangan saat SIEM down ≤ 1 jam (buffer). | **3** |
| **E8** | **AI automation** | | | **6** |
| E8-1 | Aturan auto-execute | Policy yang mengizinkan eksekusi otomatis LOW/MEDIUM dengan kondisi (mis. probe sensitif → block IP 1 jam). | Hanya aksi yang cocok aturan yang tereksekusi. | 2,5 |
| E8-2 | Guardrail otomasi | Kill switch global, batas N aksi otomatis per jam, mode shadow (hanya mencatat apa yang akan dilakukan), revert otomatis saat verifikasi `degraded`. | Kill switch menghentikan otomasi < 5 detik. | 2,5 |
| E8-3 | Laporan otomasi | Ringkasan harian aksi otomatis, hasil verifikasi, false positive yang ditandai operator. | Operator bisa menandai aksi otomatis yang keliru. | 1 |
| **E9** | **Private AI / on-prem LLM** | | | **4** |
| E9-1 | Provider OpenAI-compatible | Untuk vLLM, Ollama, dan sejenisnya. Model dikonfigurasi per tenant. Tidak ada data yang keluar jaringan. | Investigasi berjalan dengan model lokal di lab. | 2 |
| E9-2 | Evaluasi kualitas | Set 20 skenario insiden berlabel untuk membandingkan model. Panduan kebutuhan hardware. | Skor tiap model terdokumentasi. | 2 |
| **E10** | **Tooling support 24x7** | Support bundle (diagnostik tersamarkan), `/healthz`, ekspor metrik aplikasi Prometheus, cek versi terbaru. | Bundle tidak memuat secret (test). | **2** |

---

## 8. Referensi teknis

### 8.1 Katalog aksi, risk class, dan kontrol per edisi

| Aksi | Risk | Community | Professional | Enterprise | Cek verifikasi |
|---|---|---|---|---|---|
| Baca status/metrik/log, investigasi | LOW | Role | Role | Role | — |
| `incident.*`, catatan | LOW | — | Role | Role | — |
| `server.ready`, `server.weight` | MEDIUM | Operator | + reason | + reason | Status UP, distribusi sesi |
| `ratelimit.set`, `detect_rule.update` | MEDIUM | Admin | + reason + TTL | + reason + TTL, bisa otomatis (E8) | Rasio 429 < 5% trafik sah |
| `server.drain` / `server.maint` | HIGH | Operator | + reason, opsional TTL | Approval jika sisa ≤ 1 server UP | Sesi turun, 5xx tidak naik |
| `source.block` (1 IP) | HIGH | Admin (manual) | + reason + TTL ≤ 24 jam | Approval, atau otomatis via aturan E8 | Hit dari IP = 0 |
| `map.host.*`, `cert.upload`, `user.role` | HIGH | Admin | + reason | Approval | Host non-5xx, cert tersaji |
| `config.apply` / `rollback`, block CIDR ≥ /24 | CRITICAL | Admin | + reason ≥ 30 karakter | 2 approver + nomor tiket | Reload sukses, 5xx global tidak naik |

Allowlist internal/VPN tidak pernah bisa diblok di edisi mana pun.

### 8.2 Tabel data baru per edisi

| Edisi | Tabel |
|---|---|
| Community | `schema_migrations`, `api_tokens`, `license`, `metrics_raw`, `metrics_5m`, `log_agg_1m`, `log_top_1m`, `tail_state`, `rate_rules`, `blocklist`, `allowlist`, `alert_rules`, `alerts` |
| Professional | `nodes`, `node_groups`, `node_certs`, `actions`, `temp_actions`, `verifications`, `detect_rules`, `events`, `incidents`, `incident_notes`, `ai_investigations` |
| Enterprise | `sites`, `tenants`, `roles`, `role_permissions`, `approvals`, `sso_providers`, `siem_sinks`, `automation_rules`, `audit_chain` |

Perkiraan volume Community: 40 server × 2.880 sampel/hari ≈ 115 ribu baris `metrics_raw`/hari
(disimpan 48 jam).

### 8.3 Tools MCP (Professional+)

| Kategori | Tool |
|---|---|
| READ | `get_status`, `list_nodes`, `list_backends`, `list_servers`, `traffic_summary`, `top_traffic`, `list_events`, `list_audit` |
| INVESTIGATE | `get_incident`, `source_profile`, `related_events`, `check_policy` (dry-run) |
| PROPOSE | `propose_action` → status `proposed`, menunggu manusia (Pro) atau aturan automation (Enterprise) |

Jawaban AI mengikuti struktur **Observed → Analysis → Recommendation → Risk → Evidence**.

---

## 9. Pekerjaan non-teknis

| Item | Kebutuhan | Dibutuhkan sebelum |
|---|---|---|
| EULA Community | Lisensi pemakaian gratis, larangan reverse engineering/redistribusi, tanpa garansi | Community 1.0 |
| Perjanjian lisensi komersial + SLA | Pro dan Enterprise, termasuk definisi 24x7 dan waktu respons | Professional 1.0 |
| Cek merek "Konsol Gateway" | Pencarian di PDKI (DJKI) dan kelas 9/42 sebelum branding final | Community 1.0 |
| Harga dan skema lisensi | Per node/site/tenant, tahunan | Professional 1.0 |
| Kebijakan data AI | Data apa yang boleh dikirim ke provider cloud, persetujuan pelanggan | Professional 1.0 (P9) |
| Tim support 24x7 | Jadwal on-call, runbook, kanal eskalasi | Enterprise 1.0 |
| Situs produk + dokumentasi publik | Halaman unduh, docs ID/EN | Community 1.0 |

---

## 10. Pertanyaan terbuka

| # | Pertanyaan | Dampak |
|---|---|---|
| Q1 | Apakah unduhan Community perlu registrasi (email) untuk mendapatkan data pengguna? | C7-6 |
| Q2 | Telemetri anonim opt-in di Community (jumlah node, versi)? | C7, keputusan privasi |
| Q3 | Provider AI default untuk Professional: hanya Anthropic, atau langsung multi-provider? | P9 |
| Q4 | Target OS minimum: tetap mendukung EL7 (EOL) demi haproxy-cni dan pelanggan lama? | C7-1, uji kompatibilitas |
| Q5 | Siapa saja yang membutuhkan edisi Enterprise lebih dulu, dan fitur mana yang paling mendesak (SSO, multi-tenant, atau SIEM)? Urutan E1–E10 bisa disesuaikan. | Urutan Enterprise |
| Q6 | Siapa pemegang private key lisensi (minimal 2 orang)? | C2-3 |

---

## 11. Risiko dan mitigasi

| Risiko | Dampak | Mitigasi |
|---|---|---|
| Lingkup terlalu besar untuk tim kecil | Community tertunda | Community 1.0 dirilis dulu dan dipakai nyata sebelum Pro dimulai. Fitur Pro/Ent bisa digeser tanpa mengubah arsitektur. |
| Bersaing dengan HAProxy Fusion (control plane komersial resmi) | Sulit masuk ke pelanggan besar | Pembeda: AI SRE + policy/approval, harga lokal, on-prem LLM, bahasa Indonesia, support lokal. |
| Sampler/tailer membebani node HAProxy | Latensi naik | Interval 30 detik, baca log inkremental, `CPUQuota=50%` di unit systemd, ukur p99 sebelum/sesudah (kenaikan < 1 ms). |
| Block/rate limit salah sasaran | Pengguna sah terblokir | Allowlist tidak bisa diblok, TTL wajib (Pro+), verifikasi, approval (Enterprise). |
| Push config multi-node gagal di tengah jalan | Node tidak seragam | Validasi di tiap node, canary, berhenti + rollback otomatis (P1-6). |
| Cek lisensi di-bypass dengan patch biner | Kehilangan pendapatan | Diterima. Nilai ada di update, support, dan fitur server. |
| Kebocoran data antar tenant | Insiden keamanan serius | Penegakan `tenant_id` di lapisan store + test kebocoran wajib di CI (E2-1). |
| AI merekomendasikan aksi keliru | Aksi berbahaya | AI hanya `propose`. Otomasi hanya lewat aturan eksplisit + guardrail + kill switch (E8). |

---

## 12. Strategi pengujian

- **Unit** (≥ 80% per paket): parser, policy engine, detektor, verifier, reaper, validasi lisensi, gating edisi.
- **Integrasi**: `httptest` + SQLite in-memory dan PostgreSQL (CI matrix). Agent dan runtime diuji terhadap HAProxy 2.8 di lab Docker (1 node untuk Community, 3 node untuk Pro/Ent).
- **Edisi**: setiap route berfitur diuji terhadap Community, Professional, dan Enterprise, serta terhadap lisensi kedaluwarsa dan dalam masa tenggang.
- **Migrasi**: salinan DB haproxy-cni dinaikkan ke skema terbaru di setiap rilis.
- **E2E (Playwright)**: setup wizard → login → drain dengan TTL → kembali otomatis. Burst di lab → insiden → usulan AI → approval → block → verifikasi `improved`.
- **Chaos (Enterprise)**: matikan replika server, Redis, dan PostgreSQL primary. Trafik HAProxy tidak boleh terganggu.
- **Beban**: p99 latensi HAProxy diukur dengan `wrk` sebelum/sesudah pemasangan agent. Kenaikan harus < 1 ms.

---

## 13. Deploy dogfood (haproxy-cni)

| Tahap | Kapan | Isi |
|---|---|---|
| D1 | Setelah C7-7 | haproxy-cni pindah ke Konsol Gateway all-in-one + lisensi internal Enterprise (untuk SSO OMS). |
| D2 | Setiap milestone | Rilis dipasang di haproxy-cni dulu minimal 1 minggu sebelum dirilis ke luar. |
| D3 | Setelah P1 | Jika ada LB kedua (mis. untuk site lain), jadikan node agent kedua sebagai uji multi-node nyata. |

Alur deploy tetap sama: build → tarball + tanda tangan → `scp -P 2212` ke `/tmp` →
installer → restart service.
