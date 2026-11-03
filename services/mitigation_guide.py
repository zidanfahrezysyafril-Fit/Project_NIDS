import json

MITIGATION_PLANS = {
    'SQL Injection': {
        'title': 'Panduan Mitigasi SQL Injection (Advisory Non-Blocking)',
        'description': 'Langkah terstruktur untuk menanggulangi percobaan penetrasi query database.',
        'severity_recommendation': 'Kritis',
        'checklist': [
            {
                'id': 'sqli_1',
                'task': 'Verifikasi Respon Server',
                'detail': 'Periksa log web dan database apakah query berbahaya tersebut memicu SQL syntax error (200 OK dengan data bocor) atau berhasil ditolak server (403/400).',
                'priority': 'Tinggi'
            },
            {
                'id': 'sqli_2',
                'task': 'Terapkan Pemblokiran IP Sementara di .htaccess',
                'detail': 'Tambahkan baris penolakan IP penyerang pada file .htaccess di root folder hosting Anda.',
                'priority': 'Segera'
            },
            {
                'id': 'sqli_3',
                'task': 'Terapkan Prepared Statements (Parameterized Queries)',
                'detail': 'Audit kode sumber backend. Pastikan semua input form dan parameter URL diproses melalui PDO / Prepared Statements, bukan penggabungan string (concatenation).',
                'priority': 'Krusial'
            },
            {
                'id': 'sqli_4',
                'task': 'Terapkan Prinsip Hak Akses Minimal (Least Privilege)',
                'detail': 'Pastikan user database MySQL/PostgreSQL pada aplikasi web tidak memiliki wewenang DROP TABLE, GRANT, atau akses tabel sistem (information_schema).',
                'priority': 'Pencegahan'
            },
            {
                'id': 'sqli_5',
                'task': 'Perbarui Versi CMS, Tema, & Plugin',
                'detail': 'Celah keamanan sering berasal dari plugin atau komponen third-party yang belum diperbarui. Segera perbarui seluruh ekstensi.',
                'priority': 'Sedang'
            },
            {
                'id': 'sqli_6',
                'task': 'Rotasi Kredensial Database',
                'detail': 'Jika terdapat bukti kebocoran data, segera ganti password user database dan secret keys aplikasi pada file konfigurasi (wp-config.php / .env).',
                'priority': 'Kondisional'
            }
        ]
    },
    'Cross-Site Scripting (XSS)': {
        'title': 'Panduan Mitigasi Cross-Site Scripting (XSS)',
        'description': 'Langkah pengamanan terhadap penyuntikan skrip JavaScript berbahaya ke browser pengguna.',
        'severity_recommendation': 'Kritis',
        'checklist': [
            {
                'id': 'xss_1',
                'task': 'Escape Output Kontekstual',
                'detail': 'Pastikan semua variabel yang ditampilkan kembali ke HTML browser telah di-escape (misal htmlspecialchars($str, ENT_QUOTES, "UTF-8") pada PHP).',
                'priority': 'Krusial'
            },
            {
                'id': 'xss_2',
                'task': 'Sanitasi Input Pengguna',
                'detail': 'Terapkan pustaka sanitasi HTML (seperti DOMPurify di frontend atau HTMLPurifier di backend) sebelum menyimpan data teks panjang.',
                'priority': 'Tinggi'
            },
            {
                'id': 'xss_3',
                'task': 'Pasang Response Header Content-Security-Policy (CSP)',
                'detail': 'Tambahkan header HTTP CSP pada web server: Content-Security-Policy: default-src \'self\'; script-src \'self\'; untuk melarang eksekusi inline script.',
                'priority': 'Tinggi'
            },
            {
                'id': 'xss_4',
                'task': 'Amankan Cookie Sesi (HttpOnly & Secure)',
                'detail': 'Konfigurasikan session cookie dengan flag HttpOnly, Secure, dan SameSite=Lax agar tidak dapat dibaca oleh script pencuri sesi JavaScript.',
                'priority': 'Pencegahan'
            },
            {
                'id': 'xss_5',
                'task': 'Audit Formulir Komentar & Parameter Pencarian',
                'detail': 'Periksa endpoint yang menerima masukan publik seperti kolom komentar, pencarian (?q=), dan formulir kontak.',
                'priority': 'Sedang'
            }
        ]
    },
    'DDoS': {
        'title': 'Panduan Mitigasi Serangan DDoS & HTTP Flooding (Layer 7)',
        'description': 'Langkah memulihkan ketersediaan server saat mengalami lonjakan lalu lintas ekstrem.',
        'severity_recommendation': 'Kritis',
        'checklist': [
            {
                'id': 'ddos_1',
                'task': 'Terapkan Rate Limiting pada Web Server',
                'detail': 'Konfigurasikan pembatasan frekuensi request per detik per IP pada web server (Nginx limit_req atau mod_evasive/mod_ratelimit pada Apache).',
                'priority': 'Segera'
            },
            {
                'id': 'ddos_2',
                'task': 'Aktifkan Reverse Proxy CDN (Cloudflare)',
                'detail': 'Alihkan DNS domain melalui Cloudflare. Aktifkan fitur "Under Attack Mode" untuk menyerap jutaan request bot sebelum menyentuh shared hosting Anda.',
                'priority': 'Krusial'
            },
            {
                'id': 'ddos_3',
                'task': 'Blokir IP Sumber Utama di cPanel / .htaccess',
                'detail': 'Gunakan fitur IP Blocker di cPanel atau masukkan aturan Deny from <IP> pada file .htaccess.',
                'priority': 'Tinggi'
            },
            {
                'id': 'ddos_4',
                'task': 'Hubungi Dukungan Teknis Hosting Provider',
                'detail': 'Jika shared hosting mengalami penangguhan (suspended) akibat overload CPU/RAM, laporkan insiden serangan kepada tim support hosting.',
                'priority': 'Sedang'
            },
            {
                'id': 'ddos_5',
                'task': 'Optimasi Caching Halaman Statis',
                'detail': 'Aktifkan plugin caching (WP Super Cache, LiteSpeed Cache) agar request tidak membebani proses PHP dan kueri database.',
                'priority': 'Pencegahan'
            }
        ]
    },
    'Brute Force': {
        'title': 'Panduan Mitigasi Serangan Login Brute Force',
        'description': 'Langkah proteksi halaman autentikasi (wp-login.php / admin login).',
        'severity_recommendation': 'Peringatan',
        'checklist': [
            {
                'id': 'bf_1',
                'task': 'Batasi Percobaan Login (Limit Login Attempts)',
                'detail': 'Pasang plugin pembatas percobaan login (kunci akun selama 30 menit setelah 5 kali gagal).',
                'priority': 'Krusial'
            },
            {
                'id': 'bf_2',
                'task': 'Aktifkan Otentikasi Dua Faktor (2FA)',
                'detail': 'Terapkan 2FA via Google Authenticator atau Email OTP untuk seluruh akun level administrator.',
                'priority': 'Tinggi'
            },
            {
                'id': 'bf_3',
                'task': 'Ubah URL Halaman Login Standar',
                'detail': 'Ganti alamat login default dari /wp-login.php atau /admin menjadi path acak khusus (misal /portal-rahasia).',
                'priority': 'Sedang'
            }
        ]
    },
    'PortScan': {
        'title': 'Panduan Mitigasi Pengintaian Port (Reconnaissance / PortScan)',
        'description': 'Langkah memperkuat postur keamanan dari pemindaian port terbuka.',
        'severity_recommendation': 'Dipantau',
        'checklist': [
            {
                'id': 'ps_1',
                'task': 'Tutup Port Layanan yang Tidak Digunakan',
                'detail': 'Tutup port terbuka yang tidak dibutuhkan publik (seperti port database 3306/5432 atau FTP 21).',
                'priority': 'Tinggi'
            },
            {
                'id': 'ps_2',
                'task': 'Ganti Port Default Manajemen',
                'detail': 'Ganti port default SSH (22) ke port tinggi kustom jika mengelola server mandiri/VPS.',
                'priority': 'Sedang'
            }
        ]
    }
}

def get_mitigation_plan(attack_type):
    """Returns the mitigation plan for a given attack type, with fallback for unknown types."""
    for key, plan in MITIGATION_PLANS.items():
        if key.lower() in attack_type.lower():
            return plan
    # Fallback
    return {
        'title': f'Panduan Mitigasi Insiden: {attack_type}',
        'description': 'Langkah umum mitigasi insiden keamanan jaringan dan aplikasi web.',
        'severity_recommendation': 'Peringatan',
        'checklist': [
            {
                'id': 'gen_1',
                'task': 'Analisis Log Permintaan',
                'detail': 'Periksa detail parameter, IP sumber, dan pola request pada log access server.',
                'priority': 'Tinggi'
            },
            {
                'id': 'gen_2',
                'task': 'Blokir IP Penyerang Jika Berulang',
                'detail': 'Terapkan pembatasan akses pada level firewall web server atau file .htaccess.',
                'priority': 'Sedang'
            },
            {
                'id': 'gen_3',
                'task': 'Verifikasi Keutuhan File Sistem',
                'detail': 'Pastikan tidak ada file backdoor atau script asing yang berhasil disuntikkan ke direktori publik.',
                'priority': 'Sedang'
            }
        ]
    }

def generate_htaccess_rules(ip_address, attack_type):
    """Generates ready-to-copy Apache .htaccess security rule snippet."""
    safe_ip = ip_address.replace("'", "").replace('"', '').strip()
    return f"""# ============================================================
# NIDS MONITOR - ATURAN BLOKIR OTOMATIS (ADVISORY ADAPTIVE)
# Serangan Terdeteksi: {attack_type}
# Tanggal Dibuat: {safe_ip}
# ============================================================
<RequireAll>
    Require all granted
    Require not ip {safe_ip}
</RequireAll>

# Alternatif untuk Apache 2.2 lama:
# Order Allow,Deny
# Allow from all
# Deny from {safe_ip}
"""


def get_mitigation(attack_type, ip_address=''):
    """
    Adapter function returning structured guide with steps, htaccess snippet, and references.
    """
    plan = get_mitigation_plan(attack_type)
    steps = []
    for item in plan.get('checklist', []):
        steps.append({
            'title': item.get('task', ''),
            'description': item.get('detail', ''),
            'priority': item.get('priority', 'Sedang')
        })
    htaccess = generate_htaccess_rules(ip_address or '192.168.1.100', attack_type)
    return {
        'title': plan.get('title', f'Panduan Mitigasi {attack_type}'),
        'description': plan.get('description', ''),
        'severity_recommendation': plan.get('severity_recommendation', 'Peringatan'),
        'steps': steps,
        'htaccess': htaccess,
        'references': [
            {'title': 'OWASP Top 10 Web Application Security', 'url': 'https://owasp.org/www-project-top-ten/'},
            {'title': 'Cloudflare DDoS Protection Learning Center', 'url': 'https://www.cloudflare.com/learning/ddos/what-is-a-ddos-attack/'},
            {'title': 'Apache HTTP Server Access Control (.htaccess)', 'url': 'https://httpd.apache.org/docs/2.4/howto/access.html'}
        ]
    }
