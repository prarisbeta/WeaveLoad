# Analisis: Menambahkan CTI (Cyber Threat Intelligence) ke Konsol Gateway

> **Status:** Dokumen analisis/rekomendasi, ditulis 2026-09-28. Belum ada kode yang diubah untuk fitur ini — implementasi menyusul setelah keputusan di bagian bawah dokumen ini diambil.

## Context

Ide ini **bukan tangensial** — CTI/"IP Intelligence" sudah tertulis eksplisit di roadmap Q3 produk ini, sejajar dengan Anomaly Detection dan MCP AI Investigation. Jadi pertanyaannya bukan "apakah cocok", tapi "berapa besar" dan "kapan" — karena arsitektur aplikasi saat ini sengaja dibuat sangat ringan (single static binary, SQLite saja, Redis opsional), dan **berjalan satu host dengan HAProxy produksi** (103.31.159.8) yang benar-benar menangani traffic. Setiap resource yang ditambahkan CTI mengurangi headroom HAProxy di box yang sama.

Analisis ini berbasis penelusuran kode aktual (bukan asumsi):

**Kondisi arsitektur saat ini (terverifikasi dari kode):**
- Ingest traffic: **bukan** syslog listener atau dataplane API — rsyslog menulis `log local2` HAProxy ke file (`/var/log/haproxy.log`), lalu `internal/haproxylog` *tail* file itu tiap 15 detik dan parse dengan regex ([reader.go](../internal/haproxylog/reader.go), [tail.go](../internal/haproxylog/tail.go)). Tailer mulai dari EOF — **tidak ada replay histori** saat start.
- Sudah ada rule-engine deteksi lokal: `internal/security` (brute force, rate anomaly, path scan, sensitive-file probe, http abuse, backend abuse) dengan risk-scoring 0-100 + decay, disimpan ke SQLite (`security_events`, `ip_risk`).
- **Belum ada** kode IOC/reputasi/GeoIP sama sekali — grep menyeluruh nihil (AbuseIPDB, OTX, MISP, MaxMind, dst).
- Jalur enforcement sudah ada: `blocklist_ip.lst` + HAProxy runtime map API (`internal/runtime`, dipakai `internal/web/acl.go`) — ini titik pemblokiran siap pakai untuk IP hasil match CTI.
- Redis **opsional**, client custom minim (`internal/redisping`, tanpa pooling), dipakai untuk 2 hal saja (queue rate-limit, publish `security:{ip}`). Bukan dependency wajib.
- **Tidak ada resource limit** di systemd unit (`deploy/haproxy-gui.service`) hari ini — padahal `docs/IMPLEMENTATION_PLAN.md` sudah menulis niat `CPUQuota=50%` untuk melindungi HAProxy, tapi **belum pernah diterapkan** ke file service sebenarnya.
- **Tidak ada retensi otomatis** untuk `security_events`/`ip_risk`/`incidents`/backup cadangan — satu-satunya auto-prune yang ada adalah audit log (30 hari) dan session. Data akan tumbuh tanpa batas kalau ditambah tabel CTI baru tanpa desain retensi dari awal.
- Binary rilis sudah tumbuh ~2.5x (3.4MB → 13.6MB tergabung dgn MCP) seiring fitur bertambah — bukan masalah besar, tapi tren yang perlu diawasi.

---

## Dampak (Impact)

### Positif
1. **Menaikkan kualitas keputusan block/alert** — deteksi lokal (rate anomaly, brute force) jadi *corroborated*: IP yang sudah kena rule lokal **dan** terdaftar di feed reputasi eksternal → confidence jauh lebih tinggi untuk auto-block, mengurangi false positive dibanding heuristik lokal saja.
2. **Proaktif, bukan cuma reaktif** — IP yang sudah dikenal jahat (Spamhaus DROP, Tor exit node, botnet C2 list) bisa diblokir *sebelum* sempat memicu rule lokal, bukan menunggu pola traffic mencurigakan terbentuk dulu.
3. **Evidence bundle incident makin kuat** — ekspor JSON/CSV incident yang sudah ada (`internal/web/incidents.go`) bisa memuat atribusi sumber ("IP ini terdaftar di AbuseIPDB dengan confidence 92%, kategori: SSH brute force") — bernilai untuk audit/compliance.
4. **Selaras roadmap & nilai jual** — mempercepat Q3, dan jadi pembeda fitur untuk edisi Pro/Enterprise (Konsol Gateway sedang diproduktisasi 3 edisi).
5. Titik integrasi ke rule-engine dan enforcement **sudah ada**, jadi ini extension, bukan infrastruktur baru dari nol.

### Risiko / Negatif
1. **Resource contention dengan HAProxy produksi** — ini risiko #1 karena co-located di host yang sama. Tanpa `CPUQuota`/`MemoryMax` yang benar (yang hari ini kosong), lonjakan proses feed-refresh atau matching bisa mencuri CPU dari load balancer yang sedang melayani traffic nyata.
2. **Pertumbuhan data tak terbatas** — tabel baru (cache reputasi, histori match IOC) akan mengulang pola `security_events`/`ip_risk` yang sudah tidak punya retensi. Harus didesain retensi dari hari pertama, jangan menyusul.
3. **Permukaan serangan baru** — panggilan HTTP keluar ke API pihak ketiga (perlu timeout ketat, allowlist domain feed, circuit breaker; hindari echo balik data yang bisa disalahgunakan untuk SSRF-adjacent abuse).
4. **Rate limit & biaya feed** — API gratis (mis. AbuseIPDB free tier ±1000 lookup/hari) cepat habis kalau dipanggil live per-request. Solusinya arsitektural: pakai *bulk list* (Spamhaus/Tor/ET, didownload berkala, di-match secara lokal/in-memory) untuk volume tinggi, baru panggil API live hanya untuk IP yang **sudah** dicurigai rule lokal (jumlah kecil per hari).
5. **False positive / feed basi** — IP dinamis (DHCP/CGNAT) bisa masih membawa reputasi buruk dari histori lama. Harus diperlakukan sebagai satu sinyal tambahan, bukan sumber kebenaran tunggal — kebetulan ini sudah cocok dengan pola risk-scoring yang ada sekarang.
6. **Lisensi & legal** — MaxMind GeoLite2 wajib akun + license key dan ada syarat redistribusi; feed komersial (AbuseIPDB paid, dst.) berbayar. Perlu dipetakan feed mana gratis (Community) vs berbayar (Pro/Enterprise) — cocok dengan pola gating edisi yang sudah direncanakan.
7. **Menggeser identitas produk** — aplikasi ini sengaja "single binary, tanpa dependency runtime". Menambah CTI harus tetap *opsional & graceful-degrade* (pola yang sama seperti Redis hari ini), bukan jadi hard dependency, supaya edisi Community tetap ringan.

---

## Kebutuhan Server Minimal & Resource untuk Analisa Log

Ini bercabang tergantung ambisi. Ada 2 skenario — **Skenario A dipilih** sebagai titik mulai, karena selaras dengan filosofi arsitektur yang ada sekarang.

### Skenario A — IP Intelligence ringan, co-located (DIPILIH)
Real-time enrichment atas apa yang sudah dideteksi rule-engine lokal, tanpa index log penuh. Tambahan di atas footprint `haproxy-gui` yang sudah ada di 103.31.159.8:

| Resource | Estimasi tambahan | Catatan |
| :--- | :--- | :--- |
| RAM | +100–200 MB puncak | GeoIP Country mmdb (~7MB, mmap) + IOC hash-set 50–100rb entri (~10–20MB) + overhead goroutine/HTTP client |
| CPU | <5% rata-rata, burst ~10–20% saat refresh feed (tiap 1–6 jam) | Wajib pasang `CPUQuota` di systemd (belum ada hari ini — lihat gap di bawah) |
| Disk | <200 MB steady-state | GeoIP2 Country ~7MB (atau City ~65-75MB kalau perlu ASN/ISP detail); bulk list Spamhaus+ET+Tor ~3-5MB (di-replace, bukan diakumulasi); tabel SQLite cache reputasi dengan retensi 90 hari ~15-75MB |
| Network egress | Beberapa MB / beberapa jam (bulk feed) + JSON kecil per live-lookup | **Perlu konfirmasi**: firewall/security-group host produksi ini mengizinkan outbound HTTPS 443 ke domain feed (Spamhaus, AbuseIPDB, MaxMind, OTX)? Ini host LB produksi, mungkin sudah dikunci ketat. |
| **Spek server minimal (modul CTI saja, di luar HAProxy)** | **1 vCPU, headroom RAM 512MB–1GB, headroom disk 2GB** | Modest karena ini matching/enrichment, bukan pengindeksan log penuh |

Ini cocok untuk **live triage**: memperkaya deteksi yang sudah terjadi hari ini, bukan menggali histori log lama (tailer memang tidak replay histori — lihat gap di bawah).

### Skenario B — Threat-hunting berat / mini-SIEM (opsi masa depan, tidak dipilih sekarang)
Kalau yang dimaksud "menganalisa log aktivitas" adalah korelasi retrospektif berminggu-minggu, deteksi anomali berbasis ML, multi-node HAProxy digabung satu backend analitik — ini kelas tool berbeda, **bukan** perluasan wajar dari arsitektur single-binary sekarang:

- Butuh log/time-series store sungguhan (Postgres/ClickHouse custom, atau tempel minimal stack seperti Wazuh/Elastic) — di luar cakupan `haproxy-gui` sebagai binary tunggal.
- **Rekomendasi kuat: jalankan di box terpisah**, bukan di 103.31.159.8 — supaya tidak pernah bersaing resource dengan HAProxy produksi.
- Estimasi: **4+ vCPU, 8–16GB RAM, disk SSD 100GB+** (skala naik sesuai jumlah node HAProxy & retensi log detail).
- Ini pas jadi diferensiator tier **Enterprise** (arsitektur multi-tenant Organization → Site → HAProxy Cluster sudah direncanakan) — bukan untuk dipaksakan masuk edisi Community.

### Resource non-infra yang juga dibutuhkan
1. **Sumber feed** — starter set gratis untuk Community: Spamhaus DROP/EDROP (gratis, tanpa key), Tor exit list, Emerging Threats compromised-IP list, AbuseIPDB tier gratis (perlu daftar API key). Opsional berbayar untuk Pro/Enterprise: AbuseIPDB paid tier, MaxMind GeoIP2 City/ISP komersial.
2. **Kelengkapan field log** — regex parser HAProxy sekarang (`httplogRE`) menangkap IP, frontend/backend/server, timer, status, method, path — **tidak** menangkap User-Agent/header lain. Kalau CTI butuh matching lebih kaya (mis. korelasi User-Agent dengan pola bot), perlu penyesuaian `log-format` di `haproxy.cfg` — ini perubahan level infra HAProxy, bukan cuma kode Go.
3. **Proses manusia** — role SOC Analyst (sudah ada di target RBAC 8-role) perlu meninjau flag awal, whitelist IP internal/partner bisnis, tuning threshold — akurasi CTI butuh kalibrasi manusia di awal, bukan cuma infra.
4. **Keputusan retensi eksplisit** sebelum implementasi — berapa lama simpan histori match IOC? (Rekomendasi awal: 90 hari, sejalan pola SOC umum, dan jauh dari target `<300MB` yang sudah disebut di `IMPLEMENTATION_PLAN.md` untuk fitur metrics serupa.)

---

## Gap yang Harus Ditutup Lebih Dulu (independen dari CTI, tapi jadi prasyarat)

1. **`deploy/haproxy-gui.service` belum punya `CPUQuota`/`MemoryMax`** — roadmap doc sudah mengasumsikan ini ada, kenyataannya tidak. Perlu ditambahkan **sebelum** menambah beban kerja baru (CTI) di proses yang sama, supaya ada jaminan nyata bahwa CTI tidak bisa mencuri resource dari HAProxy di box yang sama.
2. **Tidak ada mekanisme retensi otomatis** selain audit log (30 hari) — tabel CTI baru (`ip_intel`, `threat_feed_matches`, dst.) wajib punya prune job dari awal, jangan menunggu masalah disk muncul dulu seperti pola backup cadangan yang sekarang menumpuk tanpa batas.
3. **Tailer mulai dari EOF, tanpa replay histori** — kalau tujuannya termasuk hunting retrospektif, perlu keputusan eksplisit: terima keterbatasan ini (CTI hanya berlaku maju/real-time), atau bangun jalur ingest histori terpisah (baca log terotasi) yang scope-nya lebih besar.

---

## Rekomendasi Arsitektur Garis Besar (untuk didiskusikan, belum dieksekusi)

Mengikuti pola yang sudah ada di kode, bukan bikin pola baru:
- Paket baru `internal/threatintel`: bulk-feed fetcher (jadwal periodik) + in-memory match set (IP/CIDR) + client on-demand untuk API live (dipanggil hanya untuk IP yang sudah dicurigai `security.Runner`, bukan tiap request).
- Cache/state disimpan di SQLite (tabel baru `ip_intel`, mengikuti pola kolom `ip_risk`) — **bukan** bergantung Redis, karena Redis opsional dan CTI perlu tetap jalan di edisi Community tanpa Redis.
- Hook masuk di titik yang sama seperti `security.Runner.updateRisk` — enrichment IP yang sudah kena rule lokal, bukan menambah beban ke hot-path tail 15 detik.
- Enforcement pakai jalur yang sudah ada: `blocklist_ip.lst` via `runtime.Client.AddMapEntry` (`internal/web/acl.go`) — tidak perlu mekanisme block baru.
- Konfigurasi (API key feed, dst.) disimpan lewat pola `store.settings` yang sudah ada (seperti `RedisSettings`) — bukan env var baru di `appconfig`.
- UI: tambah kolom/panel di `security_ip.html`, `security_event.html`, dan sidebar "Top risk IPs" — bukan halaman baru dari nol.
- RBAC: pakai `CapViewSecurity` yang sudah ada untuk melihat; pertimbangkan capability baru `CapManageThreatIntel` kalau konfigurasi feed ingin dipisah dari `CapManageSettings` umum.

---

## Keputusan yang Perlu Diambil Sebelum Implementasi Dimulai

1. ~~**Skenario A (ringan, co-located) atau B (berat, box terpisah)?**~~ → **Diputuskan: Skenario A** (ringan, co-located di 103.31.159.8, ~1 vCPU / 512MB–1GB RAM headroom). Selaras filosofi single-binary yang ada; Skenario B disimpan sebagai opsi Enterprise di masa depan kalau skala berubah.
2. **Feed gratis dulu (Spamhaus/Tor/ET/AbuseIPDB free) atau langsung include feed berbayar?** — menentukan biaya operasional & apakah perlu digating per edisi.
3. **Real-time-only (menerima keterbatasan tailer tanpa histori) atau perlu hunting retrospektif atas log lama juga?** — ini mengubah scope secara signifikan (lihat gap #3 di atas).
4. Prioritas: apakah CTI ini masuk sebagai kelanjutan Q2 (Security Engine) yang sedang jalan, atau ditunda sampai Q3 resmi mulai sesuai roadmap?

Setelah ketiga sisanya dijawab, plan implementasi bertahap bisa disusun (skema tabel, kontrak paket `internal/threatintel`, daftar feed konkret, dan perubahan `deploy/haproxy-gui.service` untuk `CPUQuota`).
