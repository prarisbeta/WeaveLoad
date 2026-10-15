# Panduan Deploy Rilis ke Server (HAProxy GUI / Konsol Gateway)

Rilis `bbd75bc-sslfix2`: perbaikan upload SSL (HTTP 500 pada hasil upload), pemasangan sertifikat dari GUI, 2FA/manajemen user, traffic, alerts, AI investigation, serta sistem snapshot/rollback di server.

---

### 📦 Berkas Rilis

| Nama Berkas | Lokasi Lokal | SHA256 |
| :--- | :--- | :--- |
| **Tarball** | `dist/haproxy-gui-bbd75bc-sslfix2.tar.gz` | `d06056b938f871dd6bfb1b6e71c8b853f7dfd9438959b4f5b9ecd21e457d1b1b` |
| **haproxy-gui** | `dist/haproxy-gui-bbd75bc-sslfix2/bin/haproxy-gui` | `191dba33cfabe4d942c94504a4dee29ecd5f9be0743d960ab017705fea461264` |
| **konsolgw-mcp** | `dist/haproxy-gui-bbd75bc-sslfix2/bin/konsolgw-mcp` | `c74bbca3e268c9fd273345bfa5ea08f67ad741cc54159e0dcaeb91793a1b23df` |

---

### 🚀 Langkah 1: Upload (dari terminal lokal)

```bash
scp -P 2212 dist/haproxy-gui-bbd75bc-sslfix2.tar.gz dist/haproxy-gui-bbd75bc-sslfix2.tar.gz.sha256 "C:/Users/User/Downloads/palapacloud.id.pem" programmer@103.31.159.8:/tmp/palapacloud.pem
```

### ⚙️ Langkah 2: Update + uji + snapshot otomatis (satu perintah)

```bash
ssh -t -p 2212 programmer@103.31.159.8 'cd /tmp && sha256sum -c haproxy-gui-bbd75bc-sslfix2.tar.gz.sha256 && rm -rf haproxy-gui-bbd75bc-sslfix2 && tar xzf haproxy-gui-bbd75bc-sslfix2.tar.gz && sudo bash haproxy-gui-bbd75bc-sslfix2/deploy/apply-release.sh --cert /tmp/palapacloud.pem'
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

### 🧰 Backup & restore kode sumber (di mesin pengembang)

```bash
bash scripts/backup-source.sh [label]        # snapshot seluruh pohon kerja ke ../haproxy-cni-gui-backups
bash scripts/backup-source.sh list
bash scripts/restore-source.sh <nama|latest> [--dry-run] [--yes] [--with-git]
```
