package i18n

import (
	"fmt"
	"strings"
)

var idCatalog = map[string]string{
	// Navigasi
	"nav_dashboard": "Ringkasan Trafik",
	"nav_pools":     "Pools",
	"nav_nodes":     "Node",
	"nav_config":    "Konfigurasi",
	"nav_certs":     "Sertifikat SSL",
	"nav_acl":       "Aturan & Rute",
	"nav_audit":     "Riwayat Aktivitas",
	"nav_logs":      "Log Trafik",
	"nav_queue":     "Antrean",
	"nav_security":  "Keamanan",
	"nav_incidents": "Insiden",
	"nav_users":     "Pengguna",
	"nav_settings":  "Pengaturan",

	// Brand & Header
	"brand_name":      "Konsol Gateway",
	"brand_sub":       "Panel kendali jaringan",
	"skip_to_content": "Langsung ke konten",
	"open_nav":        "Buka menu navigasi",
	"home":            "Beranda",
	"logout":          "Keluar dari akun",
	"login":           "Masuk",
	"email":           "Alamat Email",
	"password":        "Kata Sandi",
	"save":            "Simpan",
	"cancel":          "Batal",
	"edit":            "Ubah",
	"delete":          "Hapus",
	"add":             "Tambah",
	"search":          "Cari...",
	"filter":          "Saring...",
	"refresh":         "Muat Ulang",
	"close":           "Tutup",
	"back":            "Kembali",
	"status":          "Status",
	"actions":         "Aksi",
	"name":            "Nama",
	"time":            "Waktu",
	"role":            "Peran",
	"active":          "Aktif",
	"inactive":        "Nonaktif",
	"enabled":         "Diaktifkan",
	"disabled":        "Dinonaktifkan",
	"yes":             "Ya",
	"no":              "Tidak",
	"healthy":         "Sehat",
	"unhealthy":       "Bermasalah",
	"all":             "Semua",
	"success":         "Berhasil",
	"failed":          "Gagal",
	"details":         "Detail",

	// Peran (Roles)
	"role_super_admin":    "Super Admin",
	"role_platform_admin": "Admin Platform",
	"role_noc_operator":   "Operator NOC",
	"role_soc_analyst":    "Analis SOC",
	"role_sre":            "SRE",
	"role_security_admin": "Admin Keamanan",
	"role_auditor":        "Auditor",
	"role_viewer":         "Pengamat",

	// Dashboard
	"dash_title":           "Ringkasan Trafik",
	"dash_hint":            "Kondisi jaringan saat ini, diperbarui otomatis setiap beberapa detik. Warna hijau berarti sehat, kuning berarti sengaja dinonaktifkan sementara, merah berarti butuh perhatian.",
	"dash_frontends_up":    "Pintu masuk aktif",
	"dash_backends_up":     "Kelompok server sehat",
	"dash_servers_down":    "Server bermasalah",
	"dash_active_conns":    "Koneksi aktif saat ini",
	"dash_sys_resources":   "Sumber daya server",
	"dash_sys_hint":        "Kondisi mesin yang menjalankan gateway ini, berfokus pada penggunaan sumber daya perangkat keras server.",
	"dash_net_interfaces":  "Antarmuka jaringan",
	"dash_net_hint":        "Kartu jaringan fisik/virtual di server ini dan total lalu lintas sejak server terakhir menyala.",
	"dash_no_net":          "Tidak ada antarmuka jaringan yang terdeteksi.",
	"dash_col_interface":   "Antarmuka",
	"dash_col_address":     "Alamat",
	"dash_col_tx_rx":       "Terkirim / Diterima",
	"dash_frontends_title": "Pintu masuk trafik",
	"dash_frontends_hint":  "Ini adalah alamat yang menerima permintaan dari pengguna sebelum diteruskan ke server tujuan.",
	"dash_backends_title":  "Kelompok server tujuan",
	"dash_backends_hint":   "Server-server yang menjalankan aplikasi Anda dan menerima trafik dari pintu masuk di atas.",
	"dash_no_frontends":    "Tidak ada frontend yang terkonfigurasi.",
	"dash_no_backends":     "Tidak ada backend yang terkonfigurasi.",
	"dash_col_rate":        "Laju Permintaan",
	"dash_col_conns":       "Koneksi",
	"dash_col_traffic":     "Trafik",

	// Pools & Nodes
	"pools_title":       "Pool Layanan",
	"pools_hint":        "Daftar kelompok server backend dan anggotanya.",
	"pools_search":      "Cari pool atau server...",
	"pools_btn_add":     "Tambah Pool",
	"pools_btn_member":  "Tambah Anggota",
	"nodes_title":       "Daftar Node Server",
	"nodes_hint":        "Semua node backend fisik/virtual yang terhubung.",
	"nodes_col_ip":      "IP & Port",
	"nodes_col_pools":   "Digunakan di Pool",
	"nodes_col_health":  "Status Kesehatan",
	"nodes_col_weight":  "Bobot",
	"nodes_no_nodes":    "Tidak ada node server yang ditemukan.",

	// Config
	"config_title":          "Editor Konfigurasi",
	"config_hint":           "Ubah konfigurasi dengan validasi dan pencadangan otomatis.",
	"config_btn_validate":   "Uji Konfigurasi (Validasi)",
	"config_btn_save_apply": "Simpan & Terapkan",
	"config_btn_restart":    "Restart Service",
	"config_backups_title":  "Riwayat Cadangan",
	"config_backups_hint":   "Pilih cadangan sebelumnya untuk melakukan rollback.",

	// Certs
	"certs_title":      "Sertifikat SSL / TLS",
	"certs_hint":       "Inventaris sertifikat SSL dan masa berlakunya.",
	"certs_btn_upload": "Unggah Sertifikat",
	"certs_col_domain": "Domain / Subjek",
	"certs_col_valid":  "Masa Berlaku",
	"certs_col_issuer": "Penerbit (CA)",

	// ACL & Map
	"acl_title":      "Aturan & Peta Rute (Maps / ACL)",
	"acl_hint":       "Kelola daftar IP blokir, allowlist, dan pemetaan domain runtime.",
	"acl_btn_entry":  "Tambah Entri",
	"acl_col_file":   "File Peta",
	"acl_col_count":  "Jumlah Entri",

	// Audit
	"audit_title":      "Riwayat Aktivitas",
	"audit_hint":       "Catatan permanen setiap tindakan administratif yang dilakukan.",
	"audit_col_actor":  "Pengguna",
	"audit_col_action": "Tindakan",
	"audit_col_target": "Target",
	"audit_col_detail": "Rincian",
	"audit_no_entries": "Belum ada riwayat aktivitas yang tercatat.",

	// Logs
	"logs_title":        "Log Trafik Langsung",
	"logs_hint":         "Aliran log lalu lintas real-time.",
	"logs_col_ip":       "IP Klien",
	"logs_col_method":   "Metode",
	"logs_col_uri":      "URI Path",
	"logs_col_status":   "Status HTTP",
	"logs_col_backend":  "Backend",
	"logs_col_duration": "Durasi",

	// Queue
	"queue_title":        "Antrean Pembatasan Laju",
	"queue_hint":         "Daftar klien yang sedang dibatasi laju permintaannya.",
	"queue_col_requests": "Permintaan",
	"queue_btn_unblock":  "Buka Blokir",

	// Users
	"users_title":        "Manajemen Pengguna",
	"users_hint":         "Kelola akun pengguna, peran, dan hak akses.",
	"users_btn_add":      "Tambah Pengguna Baru",
	"users_col_lastlogin": "Login Terakhir",

	// Settings
	"settings_title": "Pengaturan Sistem",
	"settings_hint":  "Konfigurasi koneksi Redis dan integrasi eksternal.",

	// Security & Incidents
	"sec_title": "Keamanan & Proteksi",
	"sec_hint":  "Monitoring ancaman dan aturan deteksi keamanan.",
	"inc_title": "Manajemen Insiden",
	"inc_hint":  "Daftar insiden dan status penanganannya.",
}

var enCatalog = map[string]string{
	// Navigasi
	"nav_dashboard": "Traffic Summary",
	"nav_pools":     "Pools",
	"nav_nodes":     "Nodes",
	"nav_config":    "Configuration",
	"nav_certs":     "SSL Certificates",
	"nav_acl":       "Rules & Routes",
	"nav_audit":     "Audit Log",
	"nav_logs":      "Traffic Logs",
	"nav_queue":     "Queue",
	"nav_security":  "Security",
	"nav_incidents": "Incidents",
	"nav_users":     "Users",
	"nav_settings":  "Settings",

	// Brand & Header
	"brand_name":      "Gateway Console",
	"brand_sub":       "Network control panel",
	"skip_to_content": "Skip to content",
	"open_nav":        "Open navigation menu",
	"home":            "Home",
	"logout":          "Log Out",
	"login":           "Log In",
	"email":           "Email Address",
	"password":        "Password",
	"save":            "Save",
	"cancel":          "Cancel",
	"edit":            "Edit",
	"delete":          "Delete",
	"add":             "Add",
	"search":          "Search...",
	"filter":          "Filter...",
	"refresh":         "Refresh",
	"close":           "Close",
	"back":            "Back",
	"status":          "Status",
	"actions":         "Actions",
	"name":            "Name",
	"time":            "Time",
	"role":            "Role",
	"active":          "Active",
	"inactive":        "Inactive",
	"enabled":         "Enabled",
	"disabled":        "Disabled",
	"yes":             "Yes",
	"no":              "No",
	"healthy":         "Healthy",
	"unhealthy":       "Unhealthy",
	"all":             "All",
	"success":         "Success",
	"failed":          "Failed",
	"details":         "Details",

	// Peran (Roles)
	"role_super_admin":    "Super Admin",
	"role_platform_admin": "Platform Admin",
	"role_noc_operator":   "NOC Operator",
	"role_soc_analyst":    "SOC Analyst",
	"role_sre":            "SRE",
	"role_security_admin": "Security Admin",
	"role_auditor":        "Auditor",
	"role_viewer":         "Viewer",

	// Dashboard
	"dash_title":           "Traffic Summary",
	"dash_hint":            "Live network status, automatically updated every few seconds. Green means healthy, yellow is temporarily disabled, red requires attention.",
	"dash_frontends_up":    "Active Frontends",
	"dash_backends_up":     "Healthy Backend Pools",
	"dash_servers_down":    "Down Servers",
	"dash_active_conns":    "Active Connections",
	"dash_sys_resources":   "Server Resources",
	"dash_sys_hint":        "Host machine resource consumption running this gateway.",
	"dash_net_interfaces":  "Network Interfaces",
	"dash_net_hint":        "Physical and virtual network interfaces on this server and traffic since boot.",
	"dash_no_net":          "No network interfaces detected.",
	"dash_col_interface":   "Interface",
	"dash_col_address":     "Address",
	"dash_col_tx_rx":       "Transmitted / Received",
	"dash_frontends_title": "Traffic Entrypoints (Frontends)",
	"dash_frontends_hint":  "Addresses receiving incoming user requests before routing to backend servers.",
	"dash_backends_title":  "Backend Target Pools",
	"dash_backends_hint":   "Servers running your services and handling routed traffic.",
	"dash_no_frontends":    "No frontends configured.",
	"dash_no_backends":     "No backends configured.",
	"dash_col_rate":        "Request Rate",
	"dash_col_conns":       "Connections",
	"dash_col_traffic":     "Traffic",

	// Pools & Nodes
	"pools_title":       "Service Pools",
	"pools_hint":        "List of backend server pools and member servers.",
	"pools_search":      "Search pools or servers...",
	"pools_btn_add":     "Add Pool",
	"pools_btn_member":  "Add Member",
	"nodes_title":       "Server Node Inventory",
	"nodes_hint":        "All physical and virtual backend nodes connected.",
	"nodes_col_ip":      "IP & Port",
	"nodes_col_pools":   "Used in Pools",
	"nodes_col_health":  "Health Status",
	"nodes_col_weight":  "Weight",
	"nodes_no_nodes":    "No server nodes found.",

	// Config
	"config_title":          "Configuration Editor",
	"config_hint":           "Edit HAProxy configuration with syntax validation and automatic backups.",
	"config_btn_validate":   "Validate Config",
	"config_btn_save_apply": "Save & Apply",
	"config_btn_restart":    "Restart Service",
	"config_backups_title":  "Backup History",
	"config_backups_hint":   "Select a previous backup snapshot to perform a rollback.",

	// Certs
	"certs_title":      "SSL / TLS Certificates",
	"certs_hint":       "Inventory of SSL certificates and their validity periods.",
	"certs_btn_upload": "Upload Certificate",
	"certs_col_domain": "Domain / Subject",
	"certs_col_valid":  "Validity",
	"certs_col_issuer": "Issuer (CA)",

	// ACL & Map
	"acl_title":      "Rules & Routing Maps (ACL)",
	"acl_hint":       "Manage IP blocklists, allowlists, and runtime domain maps.",
	"acl_btn_entry":  "Add Entry",
	"acl_col_file":   "Map File",
	"acl_col_count":  "Entries",

	// Audit
	"audit_title":      "Audit Trail",
	"audit_hint":       "Immutable log of all administrative actions performed.",
	"audit_col_actor":  "User",
	"audit_col_action": "Action",
	"audit_col_target": "Target",
	"audit_col_detail": "Details",
	"audit_no_entries": "No activity logs recorded yet.",

	// Logs
	"logs_title":        "Live Traffic Logs",
	"logs_hint":         "Real-time stream of incoming traffic logs.",
	"logs_col_ip":       "Client IP",
	"logs_col_method":   "Method",
	"logs_col_uri":      "URI Path",
	"logs_col_status":   "HTTP Status",
	"logs_col_backend":  "Backend",
	"logs_col_duration": "Duration",

	// Queue
	"queue_title":        "Rate Limit Queue",
	"queue_hint":         "Clients currently undergoing rate-limiting.",
	"queue_col_requests": "Requests",
	"queue_btn_unblock":  "Unblock",

	// Users
	"users_title":        "User Management",
	"users_hint":         "Manage user accounts, roles, and access permissions.",
	"users_btn_add":      "Add New User",
	"users_col_lastlogin": "Last Login",

	// Settings
	"settings_title": "System Settings",
	"settings_hint":  "Configure Redis connectivity and external integrations.",

	// Security & Incidents
	"sec_title": "Security & Protection",
	"sec_hint":  "Threat monitoring and security detection rules.",
	"inc_title": "Incident Management",
	"inc_hint":  "List of security incidents and resolution status.",
}

var zhCatalog = map[string]string{
	// Navigasi
	"nav_dashboard": "流量概览",
	"nav_pools":     "服务池",
	"nav_nodes":     "节点管理",
	"nav_config":    "配置管理",
	"nav_certs":     "SSL 证书",
	"nav_acl":       "规则与路由",
	"nav_audit":     "审计日志",
	"nav_logs":      "流量日志",
	"nav_queue":     "排队等待",
	"nav_security":  "安全防护",
	"nav_incidents": "安全事件",
	"nav_users":     "用户管理",
	"nav_settings":  "系统设置",

	// Brand & Header
	"brand_name":      "网关控制台",
	"brand_sub":       "网络控制面板",
	"skip_to_content": "跳转到内容",
	"open_nav":        "打开导航菜单",
	"home":            "首页",
	"logout":          "退出登录",
	"login":           "登录",
	"email":           "电子邮箱",
	"password":        "密码",
	"save":            "保存",
	"cancel":          "取消",
	"edit":            "编辑",
	"delete":          "删除",
	"add":             "添加",
	"search":          "搜索...",
	"filter":          "筛选...",
	"refresh":         "刷新",
	"close":           "关闭",
	"back":            "返回",
	"status":          "状态",
	"actions":         "操作",
	"name":            "名称",
	"time":            "时间",
	"role":            "角色",
	"active":          "活跃",
	"inactive":        "未启用",
	"enabled":         "已启用",
	"disabled":        "已禁用",
	"yes":             "是",
	"no":              "否",
	"healthy":         "健康",
	"unhealthy":       "异常",
	"all":             "全部",
	"success":         "成功",
	"failed":          "失败",
	"details":         "详情",

	// Peran (Roles)
	"role_super_admin":    "超级管理员",
	"role_platform_admin": "平台管理员",
	"role_noc_operator":   "NOC 运维员",
	"role_soc_analyst":    "SOC 安全分析师",
	"role_sre":            "SRE 工程师",
	"role_security_admin": "安全管理员",
	"role_auditor":        "审计员",
	"role_viewer":         "只读访客",

	// Dashboard
	"dash_title":           "流量概览",
	"dash_hint":            "实时网络运行状态，每隔几秒自动刷新。绿色表示健康，黄色表示临时维护，红色表示需要关注。",
	"dash_frontends_up":    "活跃入口 (Frontends)",
	"dash_backends_up":     "健康后端服务池",
	"dash_servers_down":    "故障节点服务器",
	"dash_active_conns":    "当前活跃连接数",
	"dash_sys_resources":   "服务器硬件资源",
	"dash_sys_hint":        "运行本网关的宿主机硬件资源占用情况。",
	"dash_net_interfaces":  "网络接口",
	"dash_net_hint":        "服务器上的物理与虚拟网卡及累计网络吞吐量。",
	"dash_no_net":          "未检测到网络接口。",
	"dash_col_interface":   "网卡接口",
	"dash_col_address":     "IP 地址",
	"dash_col_tx_rx":       "发送 / 接收",
	"dash_frontends_title": "流量入口集群",
	"dash_frontends_hint":  "接收客户端请求并分发到后端的入口监听地址。",
	"dash_backends_title":  "目标后端集群",
	"dash_backends_hint":   "实际承载应用服务并接收流量的后端服务器组。",
	"dash_no_frontends":    "未配置任何入口 (Frontend)。",
	"dash_no_backends":     "未配置任何后端 (Backend)。",
	"dash_col_rate":        "请求速率",
	"dash_col_conns":       "连接数",
	"dash_col_traffic":     "数据流量",

	// Pools & Nodes
	"pools_title":       "服务池管理",
	"pools_hint":        "后端服务池及其成员节点配置列表。",
	"pools_search":      "搜索服务池或服务器...",
	"pools_btn_add":     "添加服务池",
	"pools_btn_member":  "添加成员节点",
	"nodes_title":       "服务器节点清单",
	"nodes_hint":        "已连接的所有物理及虚拟后端服务器节点。",
	"nodes_col_ip":      "IP 与端口",
	"nodes_col_pools":   "所属服务池",
	"nodes_col_health":  "健康状态",
	"nodes_col_weight":  "权重",
	"nodes_no_nodes":    "未发现任何服务器节点。",

	// Config
	"config_title":          "配置编辑器",
	"config_hint":           "在线编辑 HAProxy 配置文件，支持语法校验与快速回滚。",
	"config_btn_validate":   "测试与验证配置",
	"config_btn_save_apply": "保存并立即应用",
	"config_btn_restart":    "重启服务",
	"config_backups_title":  "备份历史",
	"config_backups_hint":   "选择历史快照可一键回滚到指定状态。",

	// Certs
	"certs_title":      "SSL / TLS 证书",
	"certs_hint":       "SSL 证书清单及到期状态监控。",
	"certs_btn_upload": "上传证书",
	"certs_col_domain": "域名 / 主题",
	"certs_col_valid":  "有效期限",
	"certs_col_issuer": "颁发机构 (CA)",

	// ACL & Map
	"acl_title":      "规则与路由映射 (ACL)",
	"acl_hint":       "管理 IP 黑白名单及动态域名映射规则。",
	"acl_btn_entry":  "添加记录",
	"acl_col_file":   "映射文件",
	"acl_col_count":  "条目数",

	// Audit
	"audit_title":      "操作审计日志",
	"audit_hint":       "记录所有管理员操作行为的不可篡改日志。",
	"audit_col_actor":  "操作人",
	"audit_col_action": "操作行为",
	"audit_col_target": "目标对象",
	"audit_col_detail": "操作明细",
	"audit_no_entries": "暂无任何操作审计记录。",

	// Logs
	"logs_title":        "实时流量日志",
	"logs_hint":         "实时捕获并展示访问流量日志流。",
	"logs_col_ip":       "客户端 IP",
	"logs_col_method":   "请求方法",
	"logs_col_uri":      "URI 路径",
	"logs_col_status":   "HTTP 状态码",
	"logs_col_backend":  "后端服务",
	"logs_col_duration": "耗时",

	// Queue
	"queue_title":        "限速排队队列",
	"queue_hint":         "当前处于限速排队或受控的客户端列表。",
	"queue_col_requests": "请求数",
	"queue_btn_unblock":  "解除限制",

	// Users
	"users_title":        "用户与权限管理",
	"users_hint":         "管理系统用户账号、分配角色与访问权限。",
	"users_btn_add":      "添加新用户",
	"users_col_lastlogin": "最后登录时间",

	// Settings
	"settings_title": "系统全局设置",
	"settings_hint":  "配置 Redis 缓存连接及外部系统集成参数。",

	// Security & Incidents
	"sec_title": "安全防护监控",
	"sec_hint":  "威胁监控与安全防御检测规则。",
	"inc_title": "安全事件响应",
	"inc_hint":  "安全事件列表及处置状态跟踪。",
}

var jaCatalog = map[string]string{
	// Navigasi
	"nav_dashboard": "トラフィック概要",
	"nav_pools":     "プール一覧",
	"nav_nodes":     "ノード管理",
	"nav_config":    "設定管理",
	"nav_certs":     "SSL証明書",
	"nav_acl":       "ルール＆ルーティング",
	"nav_audit":     "アクティビティ履歴",
	"nav_logs":      "トラフィックログ",
	"nav_queue":     "待機キュー",
	"nav_security":  "セキュリティ",
	"nav_incidents": "インシデント",
	"nav_users":     "ユーザー管理",
	"nav_settings":  "システム設定",

	// Brand & Header
	"brand_name":      "ゲートウェイコンソール",
	"brand_sub":       "ネットワーク管理パネル",
	"skip_to_content": "コンテンツへスキップ",
	"open_nav":        "ナビゲーションを開く",
	"home":            "ホーム",
	"logout":          "ログアウト",
	"login":           "ログイン",
	"email":           "メールアドレス",
	"password":        "パスワード",
	"save":            "保存",
	"cancel":          "キャンセル",
	"edit":            "編集",
	"delete":          "削除",
	"add":             "追加",
	"search":          "検索...",
	"filter":          "フィルター...",
	"refresh":         "更新",
	"close":           "閉じる",
	"back":            "戻る",
	"status":          "ステータス",
	"actions":         "操作",
	"name":            "名前",
	"time":            "時間",
	"role":            "役割",
	"active":          "アクティブ",
	"inactive":        "非アクティブ",
	"enabled":         "有効",
	"disabled":        "無効",
	"yes":             "はい",
	"no":              "いいえ",
	"healthy":         "正常",
	"unhealthy":       "異常",
	"all":             "すべて",
	"success":         "成功",
	"failed":          "失敗",
	"details":         "詳細",

	// Peran (Roles)
	"role_super_admin":    "特権管理者",
	"role_platform_admin": "プラットフォーム管理者",
	"role_noc_operator":   "NOC オペレーター",
	"role_soc_analyst":    "SOC アナリスト",
	"role_sre":            "SRE",
	"role_security_admin": "セキュリティ管理者",
	"role_auditor":        "監査人",
	"role_viewer":         "閲覧者",

	// Dashboard
	"dash_title":           "トラフィック概要",
	"dash_hint":            "現在のネットワーク状態。数秒ごとに自動更新されます。緑は正常、黄はメンテナンス中、赤は注意が必要です。",
	"dash_frontends_up":    "アクティブなエントリ",
	"dash_backends_up":     "正常なバックエンドプール",
	"dash_servers_down":    "障害サーバー",
	"dash_active_conns":    "現在のアクティブ接続",
	"dash_sys_resources":   "サーバーリソース",
	"dash_sys_hint":        "このゲートウェイを実行しているサーバーのハードウェア使用状況。",
	"dash_net_interfaces":  "ネットワークインターフェース",
	"dash_net_hint":        "サーバー上の物理および仮想ネットワークカードと累積トラフィック。",
	"dash_no_net":          "ネットワークインターフェースが検出されませんでした。",
	"dash_col_interface":   "インターフェース",
	"dash_col_address":     "IP アドレス",
	"dash_col_tx_rx":       "送信 / 受信",
	"dash_frontends_title": "トラフィックエントリポイント",
	"dash_frontends_hint":  "バックエンドに転送される前の受信リクエストを受け付けるアドレスです。",
	"dash_backends_title":  "バックエンドターゲットグループ",
	"dash_backends_hint":   "サービスを実行し、トラフィックを処理するサーバーグループです。",
	"dash_no_frontends":    "フロントエンドが設定されていません。",
	"dash_no_backends":     "バックエンドが設定されていません。",
	"dash_col_rate":        "リクエストレート",
	"dash_col_conns":       "接続数",
	"dash_col_traffic":     "トラフィック",

	// Pools & Nodes
	"pools_title":       "サービスプール管理",
	"pools_hint":        "バックエンドサーバープールおよびメンバーサーバーの一覧。",
	"pools_search":      "プールやサーバーを検索...",
	"pools_btn_add":     "プール追加",
	"pools_btn_member":  "メンバー追加",
	"nodes_title":       "サーバーノード一覧",
	"nodes_hint":        "接続されているすべての物理および仮想バックエンドノード。",
	"nodes_col_ip":      "IP とポート",
	"nodes_col_pools":   "所属プール",
	"nodes_col_health":  "ヘルス状態",
	"nodes_col_weight":  "重み",
	"nodes_no_nodes":    "サーバーノードが見つかりませんでした。",

	// Config
	"config_title":          "設定エディター",
	"config_hint":           "HAProxy設定の編集。構文チェックと自動バックアップに対応。",
	"config_btn_validate":   "設定の検証",
	"config_btn_save_apply": "保存して適用",
	"config_btn_restart":    "サービス再起動",
	"config_backups_title":  "バックアップ履歴",
	"config_backups_hint":   "過去のスナップショットを選択してロールバックを実行できます。",

	// Certs
	"certs_title":      "SSL / TLS 証明書",
	"certs_hint":       "SSL証明書のインベントリと有効期限の監視。",
	"certs_btn_upload": "証明書アップロード",
	"certs_col_domain": "ドメイン / サブジェクト",
	"certs_col_valid":  "有効期限",
	"certs_col_issuer": "発行元 (CA)",

	// ACL & Map
	"acl_title":      "ルール＆ルーティングマップ (ACL)",
	"acl_hint":       "IPブロックリスト、ホワイトリスト、ドメインマッピングの管理。",
	"acl_btn_entry":  "エントリ追加",
	"acl_col_file":   "マップファイル",
	"acl_col_count":  "エントリ数",

	// Audit
	"audit_title":      "アクティビティ履歴（監査ログ）",
	"audit_hint":       "実行されたすべての管理者操作の改ざん不可能な記録。",
	"audit_col_actor":  "ユーザー",
	"audit_col_action": "操作内容",
	"audit_col_target": "対象",
	"audit_col_detail": "詳細情報",
	"audit_no_entries": "記録されたアクティビティはまだありません。",

	// Logs
	"logs_title":        "ライブトラフィックログ",
	"logs_hint":         "リアルタイムのトラフィックログストリーム。",
	"logs_col_ip":       "クライアント IP",
	"logs_col_method":   "メソッド",
	"logs_col_uri":      "URI パス",
	"logs_col_status":   "HTTP ステータス",
	"logs_col_backend":  "バックエンド",
	"logs_col_duration": "所要時間",

	// Queue
	"queue_title":        "レート制限待機キュー",
	"queue_hint":         "現在レート制限を受けているクライアント一覧。",
	"queue_col_requests": "リクエスト数",
	"queue_btn_unblock":  "制限解除",

	// Users
	"users_title":        "ユーザー・権限管理",
	"users_hint":         "ユーザーアカウント、役割、アクセス権限の管理。",
	"users_btn_add":      "新規ユーザー追加",
	"users_col_lastlogin": "最終ログイン日時",

	// Settings
	"settings_title": "システム設定",
	"settings_hint":  "Redis接続および外部連携の設定。",

	// Security & Incidents
	"sec_title": "セキュリティ＆脅威保護",
	"sec_hint":  "脅威監視とセキュリティ検知ルール。",
	"inc_title": "インシデント管理",
	"inc_hint":  "インシデント一覧と対応状況の追跡。",
}

// T translates a key into the given language.
// Supports "id" (Indonesian), "en" (English), "zh" (Chinese), and "ja" (Japanese).
func T(lang, key string, args ...any) string {
	lang = strings.ToLower(lang)
	switch {
	case strings.HasPrefix(lang, "ja"):
		lang = "ja"
	case strings.HasPrefix(lang, "zh"):
		lang = "zh"
	case strings.HasPrefix(lang, "en"):
		lang = "en"
	default:
		lang = "id"
	}

	var val string
	var ok bool

	switch lang {
	case "ja":
		val, ok = jaCatalog[key]
		if !ok {
			val, ok = enCatalog[key]
		}
	case "zh":
		val, ok = zhCatalog[key]
		if !ok {
			val, ok = enCatalog[key]
		}
	case "en":
		val, ok = enCatalog[key]
	default:
		val, ok = idCatalog[key]
	}

	if !ok {
		// Fallback to Indonesian if available, or return the key
		if idVal, idOk := idCatalog[key]; idOk {
			val = idVal
		} else {
			val = "[" + key + "]"
		}
	}

	if len(args) > 0 {
		return fmt.Sprintf(val, args...)
	}
	return val
}

// CheckMissingKeys verifies that idCatalog, enCatalog, zhCatalog, and jaCatalog have exactly the same keys.
func CheckMissingKeys() []string {
	var missing []string
	catalogs := map[string]map[string]string{
		"en": enCatalog,
		"zh": zhCatalog,
		"ja": jaCatalog,
	}

	for k := range idCatalog {
		for name, cat := range catalogs {
			if _, ok := cat[k]; !ok {
				missing = append(missing, fmt.Sprintf("%s missing: %s", name, k))
			}
		}
	}
	for name, cat := range catalogs {
		for k := range cat {
			if _, ok := idCatalog[k]; !ok {
				missing = append(missing, fmt.Sprintf("id missing from %s: %s", name, k))
			}
		}
	}
	return missing
}
