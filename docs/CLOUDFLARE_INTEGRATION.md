# Integrasi Cloudflare dengan HAProxy & Apache (CNI Load Balancer)

Dokumen ini menjelaskan arsitektur dan konfigurasi penanganan traffic yang melewati CDN/Reverse Proxy **Cloudflare**, memastikan IP asli pengunjung (real client IP) tetap terbaca dengan benar, dan IP Proxy Cloudflare tidak terblokir secara massal oleh sistem Rate Limiting atau IP Filtering.

---

## 1. Mengapa Perlu Penanganan Khusus Cloudflare?

Ketika domain dilindungi atau diproxy oleh Cloudflare:
1. **IP Sumber Koneksi (`src`)**: HAProxy melihat alamat IP server Edge Cloudflare (misal `172.68.x.x` atau `108.162.x.x`), bukan IP asli pengunjung.
2. **Bahaya Rate Limiting Global**: Jika Rate Limiting bekerja pada level `src`, ribuan pengunjung berbeda yang melewati node Cloudflare yang sama akan dianggap satu klien &rarr; memicu **HTTP 429 Too Many Requests** massal (false positive).
3. **Bahaya IP Blocklist**: Jika IP Edge Cloudflare masuk daftar blokir, seluruh traffic yang melalui node tersebut akan terputus (HTTP 403).

---

## 2. Solusi: Smart Cloudflare IP Whitelist & Real IP Tracking

HAProxy GUI telah dilengkapi opsi:
> **🛡️ Abaikan IP Proxy Cloudflare (Track IP Asli via `CF-Connecting-IP`)**

### Subnet IP Resmi Cloudflare yang Dikenali Otomatis

**IPv4 CIDRs:**
- `173.245.48.0/20`
- `103.21.244.0/22`
- `103.22.200.0/22`
- `103.31.4.0/22`
- `141.101.64.0/18`
- `108.162.192.0/18`
- `190.93.240.0/20`
- `188.114.96.0/20`
- `197.234.240.0/22`
- `198.41.128.0/17`
- `162.158.0.0/15`
- `104.16.0.0/13`
- `104.24.0.0/14`
- `172.64.0.0/13`
- `131.0.72.0/22`

**IPv6 CIDRs:**
- `2400:cb00::/32`
- `2606:4700::/32`
- `2803:f800::/32`
- `2405:b500::/32`
- `2405:8100::/32`
- `2a06:98c0::/29`
- `2c0f:f248::/32`

---

## 3. Cara Kerja di HAProxy (`haproxy.cfg`)

### Konfigurasi Rate Limiting dengan Cloudflare Bypass
```haproxy
backend http_app
        # haproxy-gui:rate-limit rps=50 action=deny ignore_cf=true
        acl is_cloudflare src 173.245.48.0/20 103.21.244.0/22 ... 2c0f:f248::/32
        http-request deny deny_status 403 if { src -f /etc/haproxy/maps/blocklist_ip.lst } !is_cloudflare
        http-request deny deny_status 429 if { hdr(host) -i -f /etc/haproxy/maps/ratelimit_host.map }
        stick-table type ip size 100k expire 30s store http_req_rate(10s)
        http-request track-sc0 req.hdr(CF-Connecting-IP) if is_cloudflare { req.hdr(CF-Connecting-IP) -m found }
        http-request track-sc0 src if !is_cloudflare
        http-request deny deny_status 429 if { sc_http_req_rate(0) gt 50 } !{ src -f /etc/haproxy/maps/allowlist_ip.lst }
```

### Konfigurasi Forwarding Header ke Apache
Jika opsi **Dukungan Cloudflare** diaktifkan pada wizard Pool:
```haproxy
backend http_app
        mode http
        balance roundrobin
        http-request set-header X-Forwarded-For %[req.hdr(CF-Connecting-IP)] if { req.hdr(CF-Connecting-IP) -m found }
        option forwardfor except 127.0.0.0/8
        server node01 192.168.200.108:80 check
```

---

## 4. Konfigurasi di Sisi Apache Backend (`mod_remoteip`)

Di server Apache backend (misal Ubuntu/Debian di node OMS):

### 1. Aktifkan Module
```bash
sudo a2enmod remoteip
```

### 2. Tambahkan Konfigurasi di `/etc/apache2/conf-available/remoteip.conf`
```apache
<IfModule mod_remoteip.c>
    RemoteIPHeader X-Forwarded-For
    
    # Percayai HAProxy Load Balancer
    RemoteIPInternalProxy 192.168.200.0/24
    RemoteIPInternalProxy 127.0.0.1
    
    # Percayai IP Edge Cloudflare jika koneksi direct
    RemoteIPTrustedProxy 173.245.48.0/20
    RemoteIPTrustedProxy 103.21.244.0/22
    RemoteIPTrustedProxy 103.22.200.0/22
    RemoteIPTrustedProxy 103.31.4.0/22
    RemoteIPTrustedProxy 141.101.64.0/18
    RemoteIPTrustedProxy 108.162.192.0/18
    RemoteIPTrustedProxy 190.93.240.0/20
    RemoteIPTrustedProxy 188.114.96.0/20
    RemoteIPTrustedProxy 197.234.240.0/22
    RemoteIPTrustedProxy 198.41.128.0/17
    RemoteIPTrustedProxy 162.158.0.0/15
    RemoteIPTrustedProxy 104.16.0.0/13
    RemoteIPTrustedProxy 104.24.0.0/14
    RemoteIPTrustedProxy 172.64.0.0/13
    RemoteIPTrustedProxy 131.0.72.0/22
</IfModule>
```

### 3. Aktifkan dan Restart Apache
```bash
sudo a2enconf remoteip
sudo apachectl configtest
sudo systemctl restart apache2
```

---

## 5. Ringkasan Keuntungan

1. **Anti-False Positive**: Node Cloudflare tidak akan terkena pembatasan rate limit secara keliru.
2. **Akuntabilitas & Audit**: Log Apache dan HAProxy mencatat IP asli pelanggan secara presisi.
3. **Multi-Protocol & Security**: Bekerja mulus bersama Pool Wizard baru yang mendukung Web, MySQL, PostgreSQL, dan Redis.
