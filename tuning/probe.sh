#!/bin/bash
# Uji setiap server backend dari haproxy-cni dengan Host/SNI situs aslinya.
# Read-only. Jalankan: bash probe.sh | column -t
# Kolom: backend server ip:port skema host kode waktu(detik)
# kode 000 = tidak bisa konek / TLS gagal dalam 5 detik.

probe() { # backend server ip port scheme host
    local b=$1 s=$2 ip=$3 port=$4 sch=$5 host=$6 out
    if [ "$sch" = https ]; then
        out=$(curl -sk -o /dev/null -m 5 -w '%{http_code} %{time_total}' \
              --resolve "$host:$port:$ip" "https://$host:$port/")
    else
        out=$(curl -s -o /dev/null -m 5 -w '%{http_code} %{time_total}' \
              -H "Host: $host" "http://$ip:$port/")
    fi
    echo "$b $s $ip:$port $sch $host $out"
}

L1=192.168.200.108; L2=192.168.200.118; S3=192.168.200.103; S2=192.168.200.102
C1=103.31.159.17; C2=116.66.206.13; SOC=103.31.159.99; P29=116.66.206.29

# --- HTTP backends ---
probe http_appdev node1 $L1 80 http appdev.cni.net.id
for s in "node1 $L1" "node2 $L2" "node3 $S3"; do set -- $s; probe http_oms $1 $2 80 http oms.cni.net.id; done
for s in "node1 $S2" "node2 $S3"; do set -- $s; probe http_ticket $1 $2 80 http ticket.cni.net.id; done
for s in "node1 $L1" "node2 $S2"; do set -- $s; probe http_dcam $1 $2 80 http dcam.cni.net.id; done
for s in "node1 $L1" "node2 $S3"; do set -- $s; probe http_dcim $1 $2 80 http dcim.isc.id; done
for s in "node1 $L1" "node2 $S3"; do set -- $s; probe http_bantuan_cni $1 $2 80 http bantuan.cni.net.id; done
for s in "node1 $L1" "node2 $S3"; do set -- $s; probe http_bantuan_platinum $1 $2 80 http bantuan.platinum.net.id; done
for s in "node1 $L1" "node2 $L2"; do set -- $s; probe http_notifgw_cni $1 $2 80 http notifgw.cni.net.id; done
for s in "node1 $L1" "node2 $S3"; do set -- $s; probe http_cyberclass $1 $2 80 http cyberclass.cni.net.id; done
probe http_cybersoc node1 $SOC 80 http cybersoc.cni.net.id
probe http_notifpalapa node1 $P29 80 http notif.palapacloud.id

while read -r b host; do
    probe "$b" node01 $C1 80 http "$host"
    probe "$b" node02 $C2 80 http "$host"
done <<'EOF'
http_transtelekom transtelekom.id
http_rndweb rndweb.cnit.net.id
http_platinum platinum.net.id
http_palapacloud palapacloud.id
http_naibaho naibaho.id
http_jarmp jarmp.id
http_ixcni ix.cni.net.id
http_iscx iscx.isc.id
http_isc isc.id
http_hdnet hdnet.id
http_cybersat cybersat.platinum.net.id
http_cybernetworkglobal cybernetworkglobal.com
http_cdncni cdn.cni.net.id
http_cdnplatinum cdn.platinum.net.id
http_cdnpalapacloud cdn.palapacloud.id
http_bandung bandung.cni.net.id
http_bali bali.cni.net.id
http_aplikadata aplikadata.id
http_1dataid 1dataid.id
EOF

# --- HTTPS backends tanpa health check (atau yang bermasalah) ---
probe https_appdev node01 $L1 443 https appdev.cni.net.id
probe https_ixcni node01 $C1 443 https ix.cni.net.id
probe https_ixcni node02 $C2 443 https ix.cni.net.id
for s in "node01 $C1" "node02 $C2"; do set -- $s; probe https_rndweb $1 $2 443 https rndweb.cnit.net.id; done
probe https_platinum node01 $C1 443 https platinum.net.id
for s in "node01 $C1" "node02 $C2"; do set -- $s; probe https_cybersat $1 $2 443 https cybersat.platinum.net.id; done
for s in "node1 $L1" "node2 $S3"; do set -- $s; probe https_dcam $1 $2 443 https dcam.cni.net.id; done
for s in "node1 $L1" "node2 $S3"; do set -- $s; probe https_bantuan_cni $1 $2 443 https bantuan.cni.net.id; done
for s in "node1 $L1" "node2 $S3"; do set -- $s; probe https_bantuan_platinum $1 $2 443 https bantuan.platinum.net.id; done
for s in "node1 $L1" "node2 $S3"; do set -- $s; probe https_cyberclass $1 $2 443 https cyberclass.cni.net.id; done
probe https_cybersoc node1 $SOC 443 https cybersoc.cni.net.id
probe https_notifpalapa node1 $P29 443 https notif.palapacloud.id
probe https_cz_palapacloud node1 $P29 443 https clientzone.palapacloud.id
