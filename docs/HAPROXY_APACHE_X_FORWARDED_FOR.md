# Panduan Integrasi HAProxy ke Apache: Meneruskan & Membaca IP Asli Client (`X-Forwarded-For`)

Dokumen ini menjelaskan arsitektur, konfigurasi HAProxy, konfigurasi Apache (`mod_remoteip`), penyesuaian logging, dan langkah verifikasi untuk memastikan IP asli pengunjung/client diteruskan dari HAProxy dan terbaca dengan benar di web server Apache serta aplikasi backend (PHP/Laravel/Node.js).

---

## 1. Arsitektur Alur Request

```
[ Client / Browser ] (Contoh IP: 203.0.113.195)
        │
        ▼ (Port 80 / 443)
[ HAProxy Load Balancer / Konsol Gateway ] (IP: 103.31.159.8 / Internal: 192.168.200.1)
        │  * Menambahkan Header:
        │    - X-Forwarded-For: 203.0.113.195
        │    - X-Forwarded-Proto: https / http
        │    - X-Forwarded-Port: 443 / 80
        ▼ (Internal Network / LAN)
[ Apache Web Server (Backend Node) ] (IP: 192.168.200.108)
        │  * Menggunakan `mod_remoteip`
        │  * Memetakan X-Forwarded-For ke $_SERVER['REMOTE_ADDR']
        ▼
[ PHP / Framework / Web App ]
   --> $_SERVER['REMOTE_ADDR'] == '203.0.113.195' (IP Asli Client!)
```

---

## 2. Konfigurasi di Sisi HAProxy (`haproxy.cfg`)

Pastikan konfigurasi HAProxy menambahkan header `X-Forwarded-For` dan protokol terkait.

### Di Bagian `defaults` atau `frontend`:

```haproxy
defaults
    mode    http
    option  httplog
    option  dontlognull
    option  http-keep-alive
    
    # 1. Mengaktifkan penerusan X-Forwarded-For
    # except 127.0.0.0/8 mencegah penambahan jika request berasal dari localhost HAProxy sendiri
    option  forwardfor except 127.0.0.0/8

frontend http_in
    bind :::80 v4v6
    
    # 2. Teruskan proto asli jika belum ada dari reverse proxy hulu
    http-request set-header X-Forwarded-Proto http unless { req.hdr(x-forwarded-proto) -m found }
    http-request set-header X-Forwarded-Port %[dst_port]
    
    # Routing backend
    use_backend %[req.hdr(host),lower,field(1,:),map(/etc/haproxy/maps/hosts_http.map)]

frontend https_in
    bind :::443 v4v6 ssl crt /etc/ssl/certs/
    
    # 3. Informasikan backend bahwa client terhubung via HTTPS
    http-request set-header X-Forwarded-Proto https unless { req.hdr(x-forwarded-proto) -m found }
    http-request set-header X-Forwarded-Port %[dst_port]
    
    # Routing backend
    use_backend %[req.hdr(host),lower,field(1,:),map(/etc/haproxy/maps/hosts_https.map)]
```

---

## 3. Konfigurasi di Sisi Apache (Backend Node)

Secara default, tanpa `mod_remoteip`, Apache mencatat IP HAProxy (`192.168.200.1`) sebagai client IP. Modul `mod_remoteip` mengganti nilai internal client IP Apache dengan nilai dari header `X-Forwarded-For` khusus jika request berasal dari proxy internal terpercaya.

### Langkah 3.1: Pastikan Modul `remoteip` Aktif

- **Ubuntu / Debian**:
  ```bash
  sudo a2enmod remoteip
  ```

- **RHEL / CentOS 7/8/9 / AlmaLinux / Rocky**:
  `mod_remoteip` sudah ter-compile secara default. Pastikan baris berikut aktif di `/etc/httpd/conf.modules.d/00-base.conf`:
  ```apache
  LoadModule remoteip_module modules/mod_remoteip.so
  ```

---

### Langkah 3.2: Buat Berkas Konfigurasi `remoteip.conf`

Buat berkas konfigurasi baru:
- **Ubuntu/Debian**: `/etc/apache2/conf-available/remoteip.conf`
- **RHEL/CentOS**: `/etc/httpd/conf.d/remoteip.conf`

Isi dengan konfigurasi berikut:

```apache
<IfModule mod_remoteip.c>
    # Header yang digunakan untuk membaca IP asli
    RemoteIPHeader X-Forwarded-For

    # Daftarkan IP / Subnet HAProxy sebagai Trusted Internal Proxy
    # Sesuaikan dengan IP host / interface HAProxy Anda:
    RemoteIPInternalProxy 127.0.0.1
    RemoteIPInternalProxy 192.168.200.0/24
    RemoteIPInternalProxy 10.0.0.0/8
    RemoteIPInternalProxy 172.16.0.0/12
    RemoteIPInternalProxy 192.168.0.0/16
</IfModule>
```

> **Catatan Keamanan (`RemoteIPInternalProxy` vs `RemoteIPTrustedProxy`):**
> Gunakan `RemoteIPInternalProxy` untuk private network / node HAProxy lokal Anda. Perintah ini mencegah client eksternal melakukan *IP spoofing* dengan sengaja mengirimkan header `X-Forwarded-For` palsu.

---

### Langkah 3.3: Sesuaikan Format Log Apache (`LogFormat`)

Ubah format log Apache dari `%h` (Remote Host / Proxy) menjadi `%a` (Client IP yang sudah di-resolve oleh `mod_remoteip`).

Edit file konfigurasi utama Apache (`/etc/apache2/apache2.conf` di Ubuntu atau `/etc/httpd/conf/httpd.conf` di CentOS):

```apache
# Cari baris LogFormat dan sesuaikan:
LogFormat "%a %l %u %t \"%r\" %>s %b \"%{Referer}i\" \"%{User-Agent}i\"" combined
LogFormat "%a %l %u %t \"%r\" %>s %b" common

# (Opsional) Jika ingin mencatat seluruh rantai proxy dan IP:
LogFormat "%a (%{X-Forwarded-For}i) %l %u %t \"%r\" %>s %b \"%{Referer}i\" \"%{User-Agent}i\"" combined_forwarded
```

---

### Langkah 3.4: Aktifkan Konfigurasi & Reload Apache

- **Ubuntu / Debian**:
  ```bash
  sudo a2enconf remoteip
  sudo apache2ctl configtest
  sudo systemctl reload apache2
  ```

- **RHEL / CentOS**:
  ```bash
  sudo apachectl configtest
  sudo systemctl reload httpd
  ```

---

## 4. Efek pada Aplikasi Backend (PHP / Laravel / Node.js)

Dengan `mod_remoteip` aktif:
1. **PHP Native**: Variabel `$_SERVER['REMOTE_ADDR']` akan secara otomatis berisi IP asli client, bukan IP HAProxy.
2. **Framework PHP (Laravel / Symfony)**:
   - Di Laravel `bootstrap/app.php` atau `TrustProxies` middleware:
     ```php
     // Mengizinkan reverse proxy HAProxy
     ->withMiddleware(function (Middleware $middleware) {
         $middleware->trustProxies(at: [
             '192.168.200.0/24',
             '10.0.0.0/8',
             '127.0.0.1',
         ]);
     })
     ```
3. **Session & Security**: Modul rate-limiting, IP-based restriction, dan session di level aplikasi web akan mengenali pengunjung secara akurat per user.

---

## 5. Cara Pengujian & Validasi

### Uji 1: Menggunakan Skrip PHP Sederhana
Buat file `ip_test.php` di DocumentRoot Apache:
```php
<?php
header('Content-Type: text/plain');
echo "REMOTE_ADDR          : " . $_SERVER['REMOTE_ADDR'] . "\n";
echo "HTTP_X_FORWARDED_FOR : " . ($_SERVER['HTTP_X_FORWARDED_FOR'] ?? 'none') . "\n";
echo "HTTP_X_FORWARDED_PROTO : " . ($_SERVER['HTTP_X_FORWARDED_PROTO'] ?? 'none') . "\n";
```

Akses via browser atau curl melewati HAProxy:
```bash
curl -I https://appdev.cni.net.id/ip_test.php
```
Hasil yang diharapkan:
```
REMOTE_ADDR          : 203.0.113.195  <-- IP Publik / Laptop Anda
HTTP_X_FORWARDED_FOR : 203.0.113.195
HTTP_X_FORWARDED_PROTO : https
```

---

### Uji 2: Simulasi Header X-Forwarded-For dengan `curl`
```bash
curl -H "X-Forwarded-For: 198.51.100.77" http://<haproxy-ip>/ip_test.php
```
Periksa log Apache (`/var/log/httpd/access_log` atau `/var/log/apache2/access.log`):
Log harus mencatat IP client yang sesuai dan bukan IP internal HAProxy.
