# Panduan Deploy Rilis ke Server (HAProxy GUI / Konsol Gateway)

Rilis `284ed39-cti`: **CTI bawaan (signature serangan + MITRE, aturan `threat_intel`) dan analisis AI Gemini opsional**, token API digabung ke panel MCP, **perbaikan halaman /config (error .Size int64)**, **halaman Pengaturan digabung ke /config** (/settings dialihkan), **MCP bisa dikonfigurasi dari aplikasi pihak ketiga** (token API di Pengaturan, endpoint HTTP `POST /mcp`, lihat `docs/MCP_INTEGRATION.md`), halaman login menampilkan form dan tombol SSO lagi, hapus sertifikat dari GUI, perbaikan upload SSL (HTTP 500), pemasangan sertifikat dari GUI, 2FA/manajemen user, traffic, alerts, AI investigation, serta sistem snapshot/rollback di server.

---

### 📦 Berkas Rilis

| Nama Berkas | Lokasi Lokal | SHA256 |
| :--- | :--- | :--- |
| **Tarball** | `dist/haproxy-gui-284ed39-cti.tar.gz` | `4342fca8c78107d45ab5d55d5bab4a07d1623ae25763f82b4d1c5cda637d4195` |
| **haproxy-gui** | `dist/haproxy-gui-284ed39-cti/bin/haproxy-gui` | `2488794ee2c31d1f4abeb63df9b13a02cd46304d23d5997643ac43d459ca25b8` |
| **konsolgw-mcp** | `dist/haproxy-gui-284ed39-cti/bin/konsolgw-mcp` | `50f56e9ac6be1518de2950560a087a8b5d29f9ff4ecabe18cac71204ecf6b004` |

---

### 🚀 Langkah 1: Upload (dari terminal lokal)

```bash
scp -P 2212 dist/haproxy-gui-284ed39-cti.tar.gz dist/haproxy-gui-284ed39-cti.tar.gz.sha256 programmer@103.31.159.8:/tmp/
scp -P 2212 "C:/Users/User/Downloads/palapacloud.id.pem" programmer@103.31.159.8:/tmp/palapacloud.pem
```

### ⚙️ Langkah 2: Update + uji + snapshot otomatis (satu perintah)

```bash
ssh -t -p 2212 programmer@103.31.159.8 'cd /tmp && sha256sum -c haproxy-gui-284ed39-cti.tar.gz.sha256 && rm -rf haproxy-gui-284ed39-cti && tar xzf haproxy-gui-284ed39-cti.tar.gz && sudo bash haproxy-gui-284ed39-cti/deploy/apply-release.sh --cert /tmp/palapacloud.pem'
```

`apply-release.sh` bekerja berurutan dan berhenti aman di setiap tahap:

1. Memasang alat snapshot `/usr/local/sbin/haproxy-gui-snapshot`.
2. **Snapshot** kondisi saat ini ke `/var/backups/haproxy-gui/` (biner, helper, sudoers, unit, `env`, `haproxy.cfg`, folder `ssl`/`errors`/`maps`, dan database `app.db`). GUI dihentikan sebentar agar database konsisten; **HAProxy tidak dihentikan**. Jika snapshot gagal, update dibatalkan sebelum ada yang berubah.
3. Memasang biner, helper root, aturan sudoers, dan unit.
4. Restart `haproxy-gui`.
5. **Uji otomatis**: `GET /login` = 200, service aktif, `/traffic` `/alerts` `/certs` meminta login, sudoers mengizinkan helper pemasang sertifikat, `haproxy -c` lolos, tidak ada panic/fatal di log. **Jika ada yang gagal, otomatis rollback ke snapshot.**
6. Jika `--cert` diberikan dan berkas dengan nama yang sama sudah ada di `/etc/haproxy/ssl/`, sertifikat diganti lewat helper (cadangkan yang lama, `haproxy -c`, reload, rollback otomatis bila gagal). Jika namanya belum ada, hanya disiapkan di staging.

### ⏪ Rollback manual kapan saja

```bash
sudo haproxy-gui-snapshot list
sudo haproxy-gui-snapshot restore <nama-snapshot>      # atau: latest
```

Restore juga membuat snapshot `pre-restore` terlebih dahulu, jadi restore itu sendiri bisa dibatalkan. Berkas yang baru ada setelah snapshot (mis. helper baru, sertifikat baru) ikut dihapus, dan database kembali ke isi saat snapshot.

---

### 🔑 Akun admin awal (PENTING)

Akun lokal `konsolgw` (Super Admin) **dibuat hanya jika belum ada** dan tidak pernah ditimpa saat restart. Password awalnya:

* dari `KONSOLGW_BOOTSTRAP_PASSWORD` di `/etc/haproxy-gui/env` bila diisi, atau
* acak dan dicatat **sekali** di log: `sudo journalctl -u haproxy-gui | grep "created local admin"`.

Ganti password setelah login pertama. Tidak ada lagi password tetap bawaan.

---

### 🔐 Memasang sertifikat lewat GUI (alternatif, tanpa `--cert`)

Berkas `palapacloud.id.pem` adalah bundle lengkap (leaf → intermediate → root → private key), CN `*.palapacloud.id`, valid s/d 2 Apr 2027.

1. Buka **Sertifikat SSL** (`/certs`) sebagai admin.
2. Nama berkas `palapacloud.pem` (nama sama dengan berkas live di `/etc/haproxy/ssl/` agar menggantikan yang lama; `bind ... crt` tidak perlu diubah), pilih berkasnya, **Unggah & validasi**.
3. Muat ulang halaman, di daftar **Siap dipasang** klik **Pasang & reload**.
4. Verifikasi:
```bash
echo | openssl s_client -connect 127.0.0.1:443 -servername palapacloud.id 2>/dev/null | openssl x509 -noout -subject -dates
```

---

### 🗑️ Menghapus sertifikat

Di `/certs` ada tombol **Hapus** untuk sertifikat live dan berkas staging. Sertifikat live yang masih dirujuk `haproxy.cfg` (mis. di baris `bind ... crt`) **ditolak** oleh helper; selain itu dicadangkan ke `/etc/haproxy/backups/`, dihapus, `haproxy -c`, reload, dan dipulihkan otomatis jika gagal.

---

### 🧰 Backup & restore kode sumber (di mesin pengembang)

```bash
bash scripts/backup-source.sh [label]        # snapshot seluruh pohon kerja ke ../haproxy-cni-gui-backups
bash scripts/backup-source.sh list
bash scripts/restore-source.sh <nama|latest> [--dry-run] [--yes] [--with-git]
```
