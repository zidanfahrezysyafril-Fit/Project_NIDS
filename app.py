"""
NIDS Monitor - Network Intrusion Detection System
Entry Point: app.py
Kelompok 10 - AI for Security
"""

import os
import sys

# Ensure this project folder is always on Python import path
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

import time
import secrets
from datetime import datetime, timedelta

from flask import Flask, render_template, redirect, url_for, request, flash, jsonify, session
from flask_login import LoginManager, login_user, logout_user, login_required, current_user

from config import Config
from models import db, User, Website, Alert, LogEntry, TrafficMetric, ChatMessage
from detectors.ddos_detector import ddos_detector
from detectors.web_attack_detector import web_attack_detector
from services.telegram_service import TelegramService
from services.assistant_service import answer_security_question
from services.mitigation_guide import get_mitigation
from services.live_sniffer import live_sniffer

# ── Init App ─────────────────────────────────────────────────────────────────
app = Flask(__name__)
app.config.from_object(Config)

db.init_app(app)

login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Silakan login terlebih dahulu.'

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

# Inisialisasi Live Sniffer Service
live_sniffer.app = app
live_sniffer.start(mode='Hybrid Live Sniffing')

import urllib.parse

@app.template_filter('wib')
def filter_to_wib(dt, fmt='%d/%m %H:%M:%S'):
    """Konversi waktu UTC ke Waktu Indonesia Barat (WIB, UTC+7)."""
    if not dt:
        return '–'
    dt_wib = dt + timedelta(hours=7)
    return dt_wib.strftime(fmt)

@app.template_filter('unquote')
def filter_unquote(val):
    """Decode string URL encoded ke teks terbaca."""
    if not val:
        return ''
    return urllib.parse.unquote(str(val))


# ── Routes: Auth ─────────────────────────────────────────────────────────────
@app.route('/')
def index():
    if current_user.is_authenticated:
        # Auto-resume: redirect ke website terakhir yang dipantau
        last_id = session.get('last_website_id')
        if last_id:
            # Pastikan website masih milik user ini
            site = Website.query.filter_by(id=last_id, user_id=current_user.id).first()
            if site:
                return redirect(url_for('dashboard', website_id=last_id))
        # Cek apakah user punya website, langsung ke dashboard website pertama
        first_site = Website.query.filter_by(user_id=current_user.id).first()
        if first_site:
            return redirect(url_for('dashboard', website_id=first_site.id))
        # Belum punya website
        return redirect(url_for('websites'))
    return redirect(url_for('login'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    if request.method == 'POST':
        email    = request.form.get('email', '').strip()
        password = request.form.get('password', '')
        user = User.query.filter_by(email=email).first()
        if user and user.check_password(password):
            login_user(user, remember=True)
            # Simpan last_website ke session jika ada
            last_target = user.last_selected_target_id
            if last_target:
                site = Website.query.filter_by(id=last_target, user_id=user.id).first()
                if site:
                    session['last_website_id'] = last_target
                    flash(f'Selamat datang kembali, {user.full_name or user.email}!', 'success')
                    return redirect(url_for('dashboard', website_id=last_target))
            # Cek website pertama user
            first_site = Website.query.filter_by(user_id=user.id).first()
            if first_site:
                session['last_website_id'] = first_site.id
                flash(f'Selamat datang, {user.full_name or user.email}!', 'success')
                return redirect(url_for('dashboard', website_id=first_site.id))
            # Belum punya website, arahkan ke halaman tambah
            flash(f'Selamat datang, {user.full_name or user.email}! Tambahkan website pertama Anda.', 'success')
            return redirect(url_for('websites'))
        flash('Email atau password salah.', 'danger')
    return render_template('auth/login.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    if request.method == 'POST':
        name     = request.form.get('name', '').strip()
        email    = request.form.get('email', '').strip()
        password = request.form.get('password', '')
        if not name or not email or not password:
            flash('Semua field wajib diisi.', 'warning')
            return redirect(url_for('register'))
        if len(password) < 8:
            flash('Password minimal 8 karakter.', 'warning')
            return redirect(url_for('register'))
        if User.query.filter_by(email=email).first():
            flash('Email sudah terdaftar. Silakan login.', 'warning')
            return redirect(url_for('login'))
        # Generate username unik dari prefix email
        username = email.split('@')[0]
        base = username
        counter = 1
        while User.query.filter_by(username=username).first():
            username = f"{base}{counter}"
            counter += 1
        user = User(username=username, full_name=name, email=email)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        # Jangan auto-login — arahkan ke login
        flash('Akun berhasil dibuat! Silakan login untuk melanjutkan.', 'success')
        return redirect(url_for('login'))
    return render_template('auth/register.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


# ── Routes: Website Management ────────────────────────────────────────────────
@app.route('/websites')
@login_required
def websites():
    user_sites = Website.query.filter_by(user_id=current_user.id).all()
    return render_template('websites/list.html', websites=user_sites)


@app.route('/websites/add', methods=['GET', 'POST'])
@login_required
def add_website():
    # Kebijakan 1 User = 1 Website: jika sudah ada, alihkan ke ubah website
    existing_site = Website.query.filter_by(user_id=current_user.id).first()
    if existing_site:
        flash('Setiap akun dibatasi memantau 1 website aktif. Anda dialihkan ke halaman ubah website.', 'info')
        return redirect(url_for('edit_website', website_id=existing_site.id))

    if request.method == 'POST':
        from urllib.parse import urlparse
        url      = request.form.get('url', '').strip().rstrip('/')
        name     = request.form.get('name', '').strip()
        platform = request.form.get('platform', 'php')

        # Validasi URL
        if not url:
            flash('URL website wajib diisi.', 'danger')
            return redirect(url_for('add_website'))
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        try:
            parsed = urlparse(url)
            if not parsed.netloc:
                raise ValueError
        except Exception:
            flash('Format URL tidak valid. Contoh: https://website.com atau http://localhost:8000', 'danger')
            return redirect(url_for('add_website'))

        # Auto-generate nama dari hostname jika kosong
        if not name:
            name = parsed.netloc.replace('www.', '').split('.')[0].capitalize()

        site = Website(
            user_id    = current_user.id,
            target_url = url,
            name       = name,
            api_key    = Website.generate_api_key(),
            status     = 'Menunggu Konektor',
        )
        db.session.add(site)
        current_user.last_selected_target_id = site.id
        db.session.commit()
        session['last_website_id'] = site.id

        # Redirect ke halaman setup (tampilkan API key & instruksi)
        return redirect(url_for('website_setup', website_id=site.id))
    return render_template('websites/add.html')


@app.route('/websites/<int:website_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_website(website_id):
    """Ubah konfigurasi target website (Nama, URL, Platform, DDoS Threshold)."""
    site = Website.query.filter_by(id=website_id, user_id=current_user.id).first_or_404()

    if request.method == 'POST':
        from urllib.parse import urlparse
        url      = request.form.get('url', '').strip().rstrip('/')
        name     = request.form.get('name', '').strip()
        ddos_req = request.form.get('ddos_threshold_req')
        ddos_win = request.form.get('ddos_window_sec')

        if not url:
            flash('URL website wajib diisi.', 'danger')
            return redirect(url_for('edit_website', website_id=site.id))

        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url

        try:
            parsed = urlparse(url)
            if not parsed.netloc:
                raise ValueError
        except Exception:
            flash('Format URL tidak valid. Contoh: https://website.com atau http://localhost:8000', 'danger')
            return redirect(url_for('edit_website', website_id=site.id))

        if not name:
            name = parsed.netloc.replace('www.', '').split('.')[0].capitalize()

        # Update properties
        site.name = name
        site.target_url = url
        if ddos_req:
            try:
                site.ddos_threshold_req = max(10, min(10000, int(ddos_req)))
            except ValueError:
                pass
        if ddos_win:
            try:
                site.ddos_window_sec = max(1, min(300, int(ddos_win)))
            except ValueError:
                pass

        db.session.commit()
        flash(f'Website berhasil diperbarui menjadi "{site.name}" ({site.target_url}).', 'success')
        return redirect(url_for('websites'))

    return render_template('websites/edit.html', site=site)


@app.route('/websites/<int:website_id>/setup')
@login_required
def website_setup(website_id):
    site = Website.query.filter_by(id=website_id, user_id=current_user.id).first_or_404()
    return render_template('websites/setup.html', site=site)


@app.route('/websites/<int:website_id>/download-agent')
@login_required
def download_php_agent(website_id):
    """Men-generate file nids_agent.php yang sudah langsung terisi API Key dan Server URL website ini."""
    site = Website.query.filter_by(id=website_id, user_id=current_user.id).first_or_404()

    template_path = os.path.join(app.root_path, 'connectors', 'nids_agent.php')
    if not os.path.exists(template_path):
        template_path = os.path.join(app.root_path, 'static', 'connectors', 'nids_agent.php')

    with open(template_path, 'r', encoding='utf-8') as f:
        content = f.read()

    host_url = request.host_url.rstrip('/')
    content = content.replace("define('NIDS_SERVER_URL', 'http://127.0.0.1:5000');", f"define('NIDS_SERVER_URL', '{host_url}');")
    content = content.replace("define('NIDS_API_KEY', 'MASUKKAN_API_KEY_ANDA_DISINI');", f"define('NIDS_API_KEY', '{site.api_key}');")

    from flask import Response
    resp = Response(content, mimetype='application/x-httpd-php')
    resp.headers["Content-Disposition"] = "attachment; filename=nids_agent.php"
    return resp


@app.route('/websites/<int:website_id>/delete', methods=['POST'])
@login_required
def delete_website(website_id):
    site = Website.query.filter_by(id=website_id, user_id=current_user.id).first_or_404()
    site_name = site.name
    db.session.delete(site)
    db.session.commit()
    if session.get('last_website_id') == website_id:
        session.pop('last_website_id', None)
    flash(f'Website "{site_name}" berhasil dihapus.', 'info')
    return redirect(url_for('websites'))


# ── Routes: Dashboard ─────────────────────────────────────────────────────────
@app.route('/dashboard/<int:website_id>')
@login_required
def dashboard(website_id):
    site = Website.query.filter_by(id=website_id, user_id=current_user.id).first_or_404()
    session['last_website_id'] = website_id  # simpan untuk auto-redirect
    current_user.last_selected_target_id = website_id
    db.session.commit()

    recent_alerts = Alert.query.filter_by(website_id=website_id)\
                               .order_by(Alert.created_at.desc()).limit(30).all()
    metrics = TrafficMetric.query.filter_by(website_id=website_id)\
                                 .order_by(TrafficMetric.timestamp.desc()).limit(60).all()

    # Precalculate stats to pass to template cleanly (avoids complex Jinja in HTML/JS)
    last_ts = int(recent_alerts[0].created_at.timestamp()) if recent_alerts else 0
    last_alert_id = recent_alerts[0].id if recent_alerts else 0
    stat_ddos = sum(1 for a in recent_alerts if a.attack_type == 'DDoS')
    stat_xss = sum(1 for a in recent_alerts if 'XSS' in a.attack_type)
    stat_sqli = sum(1 for a in recent_alerts if 'SQL' in a.attack_type)
    stat_other = max(0, len(recent_alerts) - (stat_ddos + stat_xss + stat_sqli))

    return render_template('dashboard/index.html',
                           site=site,
                           alerts=recent_alerts,
                           metrics=metrics,
                           last_ts=last_ts,
                           last_alert_id=last_alert_id,
                           stat_ddos=stat_ddos,
                           stat_xss=stat_xss,
                           stat_sqli=stat_sqli,
                           stat_other=stat_other)


# ── Routes: Dedicated Detection Pages (DDoS & Serangan Web) ────────────────────
@app.route('/detection/ddos/<int:website_id>', methods=['GET', 'POST'])
@login_required
def ddos_detection(website_id):
    """Halaman khusus Analisis & Mitigasi Serangan Volumetrik / DDoS & Flow Jaringan."""
    site = Website.query.filter_by(id=website_id, user_id=current_user.id).first_or_404()

    if request.method == 'POST':
        try:
            threshold = int(request.form.get('ddos_threshold_req', 100))
            window = int(request.form.get('ddos_window_sec', 10))
            site.ddos_threshold_req = max(10, min(10000, threshold))
            site.ddos_window_sec = max(1, min(300, window))
            db.session.commit()
            flash(f'Pengaturan Rate Limiter berhasil disimpan (Maks {site.ddos_threshold_req} req / {site.ddos_window_sec} detik).', 'success')
        except ValueError:
            flash('Nilai ambang batas tidak valid.', 'danger')
        return redirect(url_for('ddos_detection', website_id=website_id))

    flow_alerts = Alert.query.filter(
        Alert.website_id == website_id,
        (Alert.attack_type.ilike('%DDoS%')) |
        (Alert.attack_type.ilike('%DoS%')) |
        (Alert.attack_type.ilike('%PortScan%')) |
        (Alert.attack_type.ilike('%Patator%'))
    ).order_by(Alert.created_at.desc()).limit(50).all()

    count_ddos = sum(1 for a in flow_alerts if 'ddos' in a.attack_type.lower())
    count_dos_hulk = sum(1 for a in flow_alerts if 'hulk' in a.attack_type.lower())
    count_portscan = sum(1 for a in flow_alerts if 'portscan' in a.attack_type.lower())
    count_slowloris = sum(1 for a in flow_alerts if 'slowloris' in a.attack_type.lower())

    return render_template('dashboard/ddos.html',
                           site=site,
                           alerts=flow_alerts,
                           count_ddos=count_ddos,
                           count_dos_hulk=count_dos_hulk,
                           count_portscan=count_portscan,
                           count_slowloris=count_slowloris)


@app.route('/detection/web-attack/<int:website_id>')
@login_required
def web_attack_detection(website_id):
    """Halaman khusus Deteksi & Inspeksi Muatan Serangan Web (Layer 7: SQLi & XSS)."""
    site = Website.query.filter_by(id=website_id, user_id=current_user.id).first_or_404()

    web_alerts = Alert.query.filter(
        Alert.website_id == website_id,
        (Alert.attack_type.ilike('%SQL%')) |
        (Alert.attack_type.ilike('%XSS%')) |
        (Alert.attack_type.ilike('%Brute Force%')) |
        (Alert.attack_type.ilike('%Web Attack%'))
    ).order_by(Alert.created_at.desc()).limit(50).all()

    count_sqli = sum(1 for a in web_alerts if 'sql' in a.attack_type.lower())
    count_xss = sum(1 for a in web_alerts if 'xss' in a.attack_type.lower())
    count_other = max(0, len(web_alerts) - (count_sqli + count_xss))

    return render_template('dashboard/web_attack.html',
                           site=site,
                           alerts=web_alerts,
                           count_sqli=count_sqli,
                           count_xss=count_xss,
                           count_other=count_other)


@app.route('/api/test-payload', methods=['POST'])
@login_required
def api_test_payload():
    """Menguji muatan teks (URI/parameter) secara interaktif dengan web attack detector."""
    from detectors.web_attack_detector import web_attack_detector
    data = request.get_json(silent=True) or {}
    payload = data.get('payload', '').strip()
    if not payload:
        return jsonify({'error': 'Payload tidak boleh kosong'}), 400

    is_attack, label, desc, conf, sample = web_attack_detector.inspect_request(payload)
    return jsonify({
        'is_attack': is_attack,
        'label': label,
        'description': desc,
        'confidence': round(conf, 1),
        'sample': sample,
        'payload_input': payload
    })


# ── Routes: Alert API ─────────────────────────────────────────────────────────
@app.route('/api/alerts/<int:website_id>')
@login_required
def api_alerts(website_id):
    """Endpoint polling alert terbaru (live update via JS)"""
    since_id = request.args.get('since_id', 0, type=int)
    since = request.args.get('since', 0, type=float)
    query = Alert.query.filter(Alert.website_id == website_id)
    if since_id > 0:
        query = query.filter(Alert.id > since_id)
    elif since > 0:
        query = query.filter(Alert.created_at > datetime.fromtimestamp(since))
    alerts = query.order_by(Alert.id.desc()).limit(50).all()
    return jsonify([{
        'id': a.id,
        'type': a.attack_type,
        'severity': a.severity,
        'status': a.status,
        'source_ip': a.source_ip,
        'detail': a.detail,
        'created_at': a.created_at.isoformat()
    } for a in alerts])


# ── Routes: Ingest API (Konektor Plugin WP / PHP Agent / VPS) ──────────────────
@app.route('/api/ingest', methods=['POST'])
def api_ingest():
    """
    Menerima log request dari konektor (WordPress plugin / PHP script).
    Menjalankan 3 lapis deteksi secara otomatis:
      Layer 1 - DDoS Rate Limiter (selalu aktif)
      Layer 2 - Web Attack Detector: Regex + Text ML (selalu aktif)
      Layer 3 - CICIDS2017 Flow Model: XGBoost/RF (aktif jika model .pkl tersedia)
    """
    from detectors.cicids_flow_detector import flow_detector

    # 1. Validasi API Key
    api_key = request.headers.get('X-NIDS-KEY')
    data = request.get_json(silent=True) or {}
    if not api_key:
        api_key = data.get('api_key') or request.form.get('api_key')

    if not api_key:
        return jsonify({'error': 'Missing API key'}), 401

    site = Website.query.filter_by(api_key=api_key).first()
    if not site:
        return jsonify({'error': 'Invalid API key'}), 403

    # Update status koneksi
    now = datetime.utcnow()
    site.last_ping_at = now
    if site.status == 'Menunggu Konektor':
        site.status = 'Terhubung'
    site.total_requests_received = (site.total_requests_received or 0) + 1

    # Extract log details
    ip = data.get('ip_address') or data.get('ip') or request.form.get('ip') or request.remote_addr or '127.0.0.1'
    method = (data.get('method') or request.form.get('method') or 'GET').upper()
    uri = data.get('uri') or data.get('request_uri') or request.form.get('uri') or '/'
    user_agent = data.get('user_agent') or request.form.get('user_agent') or ''
    post_body = data.get('post_body') or request.form.get('post_body') or ''
    status_code = int(data.get('status_code') or request.form.get('status_code') or 200)
    response_size = int(data.get('response_size') or data.get('bytes_sent') or 0)
    response_time_ms = float(data.get('response_time_ms') or 0.0)

    # Ingest ke Live Traffic Sniffer & Flow Aggregator
    pkg_len = max(len(uri) + len(post_body) + 64, 64)
    live_sniffer.ingest_packet(
        src_ip=ip,
        dst_ip='127.0.0.1',
        src_port=54321,
        dst_port=5000,
        protocol='TCP',
        length=pkg_len,
        flags='P' if method == 'POST' else 'S',
        window=64240
    )

    # ── LAYER 1: Deteksi DDoS (Rate Limiting) ────────────────────────────────
    current_rps = ddos_detector.record_request(site.id, ip)
    is_ddos, ddos_rate, ddos_conf = ddos_detector.evaluate_ip_rate(
        site.id, ip, threshold_req=site.ddos_threshold_req, window_sec=site.ddos_window_sec
    )

    # ── LAYER 2: Deteksi Web Attack (SQLi & XSS via Regex + Text Model) ──────
    is_web_attack, attack_type, pattern_desc, conf_score, payload_sample = web_attack_detector.inspect_request(
        uri=uri, method=method, post_body=post_body
    )

    # ── LAYER 3: CICIDS2017 Flow Model (Otomatis, jika model .pkl ada) ────────
    # Estimasi fitur flow dari data HTTP yang tersedia.
    # Model CICIDS2017 butuh 55 fitur jaringan — kita estimasi dari request HTTP.
    is_flow_attack = False
    flow_label = 'BENIGN'
    flow_conf = 0.0
    flow_source = 'CICIDS Flow XGBoost'

    try:
        # Konstruksi estimasi fitur flow dari HTTP metadata
        uri_len = len(uri)
        body_len = len(post_body)
        is_post = 1 if method == 'POST' else 0
        is_suspicious_ua = 1 if any(k in user_agent.lower() for k in ['sqlmap','nikto','nmap','masscan','zgrab','curl/','python-requests','bot','scan']) else 0

        # Perkiraan flow duration dari response time (ms → microseconds)
        est_flow_duration = max(response_time_ms * 1000, 1.0)
        # RPS ke flow packets/s (setiap HTTP request ≈ beberapa TCP packets)
        est_flow_pkts_s = current_rps * 5.0
        # Estimasi packet length dari ukuran URI + body
        est_pkt_len_mean = max(uri_len + body_len, 64)
        est_pkt_len_max  = max(est_pkt_len_mean * 1.5, 100)
        # SYN flood indicator: banyak request dari 1 IP dengan body kecil
        est_syn_flags = min(int(current_rps / 2), 20) if is_post == 0 else 0
        # Init window size: normal browser = 64240, bot biasanya rendah
        est_init_win = 64240 if not is_suspicious_ua else 512
        # ACK flags: setiap request HTTP = 1 ACK
        est_ack_flags = 1

        flow_features = {
            'Destination Port':        443 if 'https' in uri.lower() else 80,
            'Flow Duration':           est_flow_duration,
            'Total Fwd Packets':       max(1, int(current_rps)),
            'Fwd Packet Length Max':   est_pkt_len_max,
            'Fwd Packet Length Min':   min(64, est_pkt_len_mean),
            'Fwd Packet Length Mean':  est_pkt_len_mean,
            'Bwd Packet Length Max':   max(response_size, 100),
            'Bwd Packet Length Min':   min(response_size, 64) if response_size > 0 else 0,
            'Flow Bytes/s':            max((uri_len + body_len + response_size) / max(response_time_ms/1000, 0.001), 0),
            'Flow Packets/s':          est_flow_pkts_s,
            'Flow IAT Mean':           max(1000.0 / max(current_rps, 0.01), 1),
            'Flow IAT Std':            50.0 if is_suspicious_ua else 200.0,
            'Flow IAT Max':            max(1000.0 / max(current_rps, 0.01) * 2, 1),
            'Flow IAT Min':            1.0,
            'Fwd IAT Total':           est_flow_duration,
            'Fwd IAT Mean':            max(est_flow_duration / max(current_rps, 1), 1),
            'Fwd IAT Std':             10.0,
            'Fwd IAT Max':             est_flow_duration,
            'Fwd IAT Min':             1.0,
            'Bwd IAT Total':           est_flow_duration * 0.8,
            'Bwd IAT Mean':            max(est_flow_duration * 0.8 / max(current_rps, 1), 1),
            'Bwd IAT Std':             5.0,
            'Bwd IAT Max':             est_flow_duration,
            'Bwd IAT Min':             1.0,
            'Fwd PSH Flags':           is_post,
            'Bwd PSH Flags':           0,
            'Fwd URG Flags':           0,
            'Bwd URG Flags':           0,
            'Fwd Header Length':       20 + uri_len,
            'Bwd Header Length':       20,
            'Fwd Packets/s':           est_flow_pkts_s * 0.6,
            'Bwd Packets/s':           est_flow_pkts_s * 0.4,
            'Min Packet Length':       min(64, est_pkt_len_mean),
            'Max Packet Length':       est_pkt_len_max,
            'Packet Length Mean':      est_pkt_len_mean,
            'Packet Length Variance':  (est_pkt_len_max - est_pkt_len_mean) ** 2,
            'FIN Flag Count':          1,
            'SYN Flag Count':          est_syn_flags,
            'RST Flag Count':          1 if status_code >= 500 else 0,
            'PSH Flag Count':          is_post,
            'ACK Flag Count':          est_ack_flags,
            'URG Flag Count':          0,
            'CWE Flag Count':          0,
            'ECE Flag Count':          0,
            'Down/Up Ratio':           max(response_size / max(uri_len + body_len, 1), 0),
            'Average Packet Size':     est_pkt_len_mean,
            'Avg Fwd Segment Size':    est_pkt_len_mean,
            'Avg Bwd Segment Size':    response_size if response_size > 0 else est_pkt_len_mean,
            'Subflow Fwd Packets':     max(1, int(current_rps)),
            'Subflow Fwd Bytes':       uri_len + body_len,
            'Subflow Bwd Packets':     1,
            'Subflow Bwd Bytes':       response_size,
            'Init_Win_bytes_forward':  est_init_win,
            'Init_Win_bytes_backward': 64240,
            'act_data_pkt_fwd':        max(1, is_post),
        }

        flow_result = flow_detector.predict_flow(
            flow_features,
            exclude_dest_port=site.exclude_destination_port
        )

        if flow_result.get('is_attack'):
            is_flow_attack = True
            flow_label = flow_result.get('primary_label', 'Anomaly')
            flow_conf = flow_result.get('confidence', 85.0)
            # Hanya pakai flow result jika tidak sudah terdeteksi layer 1/2
            # dan confidence cukup tinggi (>= 85%)
            if flow_conf < 85.0:
                is_flow_attack = False

    except Exception:
        pass  # Model tidak ada atau gagal — lanjut tanpa layer 3

    # ── Buat Alert berdasarkan hasil deteksi ──────────────────────────────────
    alert_obj = None
    norm_type = 'BENIGN'

    if is_ddos:
        cutoff_ddos = datetime.utcnow() - timedelta(seconds=30)
        recent_ddos = Alert.query.filter(
            Alert.website_id == site.id,
            Alert.attack_type == 'DDoS',
            Alert.source_ip == ip,
            Alert.created_at >= cutoff_ddos
        ).first()

        if not recent_ddos:
            norm_type = 'DDoS'
            alert_obj = Alert(
                website_id=site.id,
                attack_type='DDoS',
                severity='Kritis',
                status='Terdeteksi',
                source_ip=ip,
                target_endpoint=uri[:250],
                payload_sample=f"Lonjakan trafik: {ddos_rate} request dalam {site.ddos_window_sec} detik (RPS: {current_rps:.1f})",
                pattern_detected=f"HTTP Flood Rate Limit Exceeded ({ddos_rate} reqs)",
                confidence_score=ddos_conf,
                detector_source='Layer 1 – Rate Limiter + CICIDS Flow',
                notes=f'Lonjakan request per IP melebihi ambang batas aman. Flow model: {flow_label} ({flow_conf:.0f}%).'
            )
            db.session.add(alert_obj)
            db.session.flush()
            site.status = 'Serangan Aktif'
            site.total_alerts_count = (site.total_alerts_count or 0) + 1

    elif is_web_attack:
        norm_type = 'XSS' if 'XSS' in attack_type else ('SQL Injection' if 'SQL' in attack_type else attack_type)
        alert_obj = Alert(
            website_id=site.id,
            attack_type=norm_type,
            severity='Kritis' if 'SQL' in norm_type else 'Peringatan',
            status='Terdeteksi',
            source_ip=ip,
            target_endpoint=uri[:250],
            payload_sample=payload_sample[:250],
            pattern_detected=pattern_desc[:200],
            confidence_score=conf_score,
            detector_source='Layer 2 – Regex + Text ML',
            notes=f'Terdeteksi upaya eksploitasi {norm_type} pada endpoint {uri}. Flow model: {flow_label} ({flow_conf:.0f}%).'
        )
        db.session.add(alert_obj)
        db.session.flush()
        site.status = 'Serangan Aktif'
        site.total_alerts_count = (site.total_alerts_count or 0) + 1

    elif is_flow_attack:
        # Layer 3 saja yang mendeteksi — model CICIDS2017
        if 'DDoS' in flow_label or 'DoS' in flow_label or 'Bot' in flow_label:
            norm_type = 'DDoS'
            severity = 'Kritis'
        elif 'SQL' in flow_label:
            norm_type = 'SQL Injection'
            severity = 'Kritis'
        elif 'XSS' in flow_label:
            norm_type = 'XSS'
            severity = 'Peringatan'
        elif 'PortScan' in flow_label:
            norm_type = 'PortScan'
            severity = 'Tinggi'
        elif 'Brute' in flow_label or 'Patator' in flow_label:
            norm_type = 'Brute Force'
            severity = 'Tinggi'
        elif 'Heartbleed' in flow_label or 'Infiltration' in flow_label:
            norm_type = flow_label
            severity = 'Kritis'
        else:
            norm_type = flow_label
            severity = 'Peringatan'

        alert_obj = Alert(
            website_id=site.id,
            attack_type=norm_type,
            severity=severity,
            status='Terdeteksi',
            source_ip=ip,
            target_endpoint=uri[:250],
            payload_sample=f"Flow anomaly dari {ip} | RPS: {current_rps:.1f} | Method: {method}",
            pattern_detected=f"CICIDS2017 Model: {flow_label} (confidence: {flow_conf:.1f}%)",
            confidence_score=flow_conf,
            detector_source='Layer 3 – CICIDS2017 XGBoost/RF',
            notes=f'Terdeteksi oleh model ML terlatih CICIDS2017. Label: {flow_label}.'
        )
        db.session.add(alert_obj)
        db.session.flush()
        site.status = 'Serangan Aktif'
        site.total_alerts_count = (site.total_alerts_count or 0) + 1

    # Simpan log entry
    log_entry = LogEntry(
        website_id=site.id,
        alert_id=alert_obj.id if alert_obj else None,
        ip_address=ip,
        http_method=method,
        request_uri=uri,
        status_code=status_code,
        user_agent=user_agent[:250],
        is_suspicious=(is_ddos or is_web_attack or is_flow_attack),
        attack_label=norm_type if (is_ddos or is_web_attack or is_flow_attack) else 'BENIGN',
        confidence=(conf_score if is_web_attack else (ddos_conf if is_ddos else (flow_conf if is_flow_attack else 0.0)))
    )
    db.session.add(log_entry)

    # Update / create traffic metric
    metric = TrafficMetric(
        website_id=site.id,
        timestamp=now,
        request_count=1,
        suspicious_count=(1 if (is_ddos or is_web_attack or is_flow_attack) else 0),
        unique_ips=1,
        current_rps=current_rps
    )
    db.session.add(metric)

    db.session.commit()

    # Kirim notifikasi Telegram jika ada alert dan user mengaktifkannya
    if alert_obj:
        try:
            owner = site.owner
            TelegramService.send_alert_notification(owner, site, alert_obj)
        except Exception:
            pass

    verdict = norm_type if (is_ddos or is_web_attack or is_flow_attack) else 'BENIGN'
    return jsonify({
        'status': 'ok',
        'verdict': verdict,
        'layers': {
            'ddos_rate_limiter': is_ddos,
            'web_attack_ml': is_web_attack,
            'cicids_flow_model': is_flow_attack,
        },
        'alert_created': alert_obj is not None,
        'alert_id': alert_obj.id if alert_obj else None
    })


# ── Routes: Simulation / Attack Demo ──────────────────────────────────────────
@app.route('/api/simulate/<int:website_id>', methods=['POST'])
@login_required
def simulate_attack(website_id):
    """
    Memudahkan demo/pengujian deteksi NIDS:
    Memicu simulasi SQLi, XSS, DDoS, atau Ping bersih langsung ke /api/ingest.
    """
    site = Website.query.filter_by(id=website_id, user_id=current_user.id).first_or_404()
    data = request.get_json(silent=True) or {}
    sim_type = data.get('type', 'sqli')

    test_ip = f"198.51.100.{secrets.randbelow(150) + 10}"

    if sim_type == 'sqli':
        payload = {
            'api_key': site.api_key,
            'ip_address': test_ip,
            'method': 'GET',
            'request_uri': "/wp-login.php?user=admin' UNION SELECT 1,2,password FROM wp_users--",
            'user_agent': 'sqlmap/1.6#stable (https://sqlmap.org)',
            'status_code': 200
        }
        with app.test_client() as client:
            resp = client.post('/api/ingest', json=payload)
            res_data = resp.get_json()
        return jsonify({'message': 'Simulasi SQL Injection berhasil dikirim.', 'result': res_data})

    elif sim_type == 'xss':
        payload = {
            'api_key': site.api_key,
            'ip_address': test_ip,
            'method': 'POST',
            'request_uri': "/search?q=<script>alert(document.cookie)</script>",
            'user_agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
            'post_body': "comment=<svg onload=alert('XSS')>",
            'status_code': 200
        }
        with app.test_client() as client:
            resp = client.post('/api/ingest', json=payload)
            res_data = resp.get_json()
        return jsonify({'message': 'Simulasi XSS Attack berhasil dikirim.', 'result': res_data})

    elif sim_type == 'ddos':
        # Simulasikan lonjakan request dari IP yang sama untuk melebihi threshold
        results = []
        with app.test_client() as client:
            # Kirim request melampaui ddos_threshold_req
            threshold = site.ddos_threshold_req or 50
            for i in range(min(110, threshold + 5)):
                payload = {
                    'api_key': site.api_key,
                    'ip_address': test_ip,
                    'method': 'GET',
                    'request_uri': f"/api/endpoint?req={i}",
                    'user_agent': 'DDoS-Botnet/3.0',
                    'status_code': 200
                }
                resp = client.post('/api/ingest', json=payload)
                results.append(resp.get_json())
        return jsonify({'message': f'Simulasi DDoS Flood ({len(results)} request cepat) berhasil dikirim dari {test_ip}.', 'count': len(results)})

    else:
        # Ping normal
        payload = {
            'api_key': site.api_key,
            'ip_address': test_ip,
            'method': 'GET',
            'request_uri': "/home",
            'user_agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)',
            'status_code': 200
        }
        with app.test_client() as client:
            resp = client.post('/api/ingest', json=payload)
            res_data = resp.get_json()
        return jsonify({'message': 'Ping trafik normal berhasil dikirim.', 'result': res_data})


# ── Routes: AI Assistant ──────────────────────────────────────────────────────
@app.route('/assistant/<int:website_id>', methods=['GET', 'POST'])
@login_required
def assistant(website_id):
    site = Website.query.filter_by(id=website_id, user_id=current_user.id).first_or_404()
    if request.method == 'POST':
        question = (request.json or {}).get('question', '')
        answer = answer_security_question(question, website_id=website_id)
        msg = ChatMessage(user_id=current_user.id, website_id=website_id, role='user', content=question)
        db.session.add(msg)
        msg2 = ChatMessage(user_id=current_user.id, website_id=website_id, role='assistant', content=answer)
        db.session.add(msg2)
        db.session.commit()
        return jsonify({'answer': answer})
    history = ChatMessage.query.filter_by(website_id=website_id)\
                               .order_by(ChatMessage.created_at).all()
    return render_template('dashboard/assistant.html', site=site, history=history)


# ── Routes: Mitigation Guide ──────────────────────────────────────────────────
@app.route('/mitigation/<int:alert_id>')
@login_required
def mitigation(alert_id):
    alert = db.get_or_404(Alert, alert_id)
    site  = Website.query.filter_by(id=alert.website_id, user_id=current_user.id).first_or_404()
    guide = get_mitigation(alert.attack_type, alert.source_ip)
    return render_template('dashboard/mitigation.html', alert=alert, site=site, guide=guide)


# ── Routes: Upload & Analisis CSV CICIDS2017 ──────────────────────────────────
@app.route('/api/model-status')
@login_required
def api_model_status():
    """Cek apakah model CICIDS2017 (.pkl) sudah dimuat atau menggunakan fallback heuristik."""
    from detectors.cicids_flow_detector import flow_detector
    return jsonify({
        'xgb_loaded': flow_detector.xgb_model is not None,
        'scaler_loaded': flow_detector.scaler is not None,
        'algorithm': flow_detector.algorithm,
    })



@app.route('/analyze/<int:website_id>', methods=['GET', 'POST'])
@login_required
def analyze_csv(website_id):
    """
    Upload file CSV CICIDS2017 (atau log CSV custom) dan jalankan analisis
    menggunakan cicids_flow_detector (XGBoost/RF) + web_attack_detector.
    """
    site = Website.query.filter_by(id=website_id, user_id=current_user.id).first_or_404()

    if request.method == 'POST':
        import csv
        import io

        file = request.files.get('csv_file')
        if not file or not file.filename:
            flash('Pilih file CSV terlebih dahulu.', 'warning')
            return redirect(url_for('analyze_csv', website_id=website_id))

        if not file.filename.lower().endswith('.csv'):
            flash('Hanya file CSV yang didukung.', 'danger')
            return redirect(url_for('analyze_csv', website_id=website_id))

        # Baca file CSV
        try:
            content = file.read().decode('utf-8', errors='replace')
        except Exception as e:
            flash(f'Gagal membaca file: {e}', 'danger')
            return redirect(url_for('analyze_csv', website_id=website_id))

        reader = csv.DictReader(io.StringIO(content))
        # Bersihkan nama kolom (strip whitespace)
        if not reader.fieldnames:
            flash('File CSV kosong atau tidak punya header.', 'danger')
            return redirect(url_for('analyze_csv', website_id=website_id))

        rows = list(reader)
        max_rows = 5000  # batasi agar tidak hang
        rows = rows[:max_rows]

        from detectors.cicids_flow_detector import flow_detector, CICIDS_55_FEATURES

        total = 0
        attack_count = 0
        alerts_created = 0
        label_counts = {}

        now = datetime.utcnow()

        for row in rows:
            # Normalize kolom: strip whitespace di key
            row = {k.strip(): v.strip() for k, v in row.items()}
            total += 1

            # Prediksi flow
            result = flow_detector.predict_flow(row, exclude_dest_port=True)
            label = result.get('primary_label', 'BENIGN')
            conf = result.get('confidence', 0.0)

            label_counts[label] = label_counts.get(label, 0) + 1

            if result.get('is_attack'):
                attack_count += 1

                # Map label CICIDS ke attack_type sistem
                if 'DDoS' in label or 'DoS' in label or 'Bot' in label:
                    attack_type = 'DDoS'
                    severity = 'Kritis'
                elif 'SQL' in label:
                    attack_type = 'SQL Injection'
                    severity = 'Kritis'
                elif 'XSS' in label:
                    attack_type = 'XSS'
                    severity = 'Peringatan'
                elif 'PortScan' in label:
                    attack_type = 'PortScan'
                    severity = 'Tinggi'
                elif 'Brute' in label or 'Patator' in label:
                    attack_type = 'Brute Force'
                    severity = 'Tinggi'
                else:
                    attack_type = label
                    severity = 'Peringatan'

                src_ip = row.get('Source IP', row.get('Src IP', f'192.168.{(total%254)+1}.{(total%100)+1}'))
                dst_port = row.get('Destination Port', row.get('Dst Port', '0'))

                alert_obj = Alert(
                    website_id=site.id,
                    attack_type=attack_type,
                    severity=severity,
                    status='Terdeteksi',
                    source_ip=src_ip[:50],
                    target_endpoint=f'Port {dst_port}'[:250],
                    payload_sample=f'CSV Row #{total}: Label={label}',
                    pattern_detected=f'CICIDS2017 ML: {label} (confidence: {conf:.1f}%)',
                    confidence_score=conf,
                    detector_source='CICIDS Flow XGBoost',
                    notes=f'Terdeteksi dari upload CSV CICIDS2017. Agreement: {result.get("model_agreement", False)}'
                )
                db.session.add(alert_obj)
                alerts_created += 1

                # Batch commit setiap 100 alert
                if alerts_created % 100 == 0:
                    db.session.commit()

        db.session.commit()

        # Update site stats
        site.total_alerts_count = (site.total_alerts_count or 0) + alerts_created
        if attack_count > 0:
            site.status = 'Serangan Aktif'
        db.session.commit()

        # Buat summary message
        top_labels = sorted(label_counts.items(), key=lambda x: x[1], reverse=True)[:5]
        summary = ', '.join([f'{k}: {v}' for k, v in top_labels])
        flash(
            f'✅ Analisis selesai! {total} baris diproses. '
            f'{attack_count} serangan terdeteksi ({alerts_created} alert dibuat). '
            f'Distribusi: {summary}',
            'success'
        )
        return redirect(url_for('dashboard', website_id=website_id))

    return render_template('dashboard/analyze.html', site=site)


# ── Routes: Live Sniffer API ──────────────────────────────────────────────────
@app.route('/api/sniffer/status', methods=['GET'])
def api_sniffer_status():
    """Mengembalikan status dan telemetri live packet sniffer & flow engine."""
    return jsonify(live_sniffer.stats)


@app.route('/api/sniffer/simulate', methods=['POST'])
@login_required
def api_sniffer_simulate():
    """Menembakkan burst paket serangan live ke sniffer untuk pengujian/demo."""
    data = request.get_json(silent=True) or {}
    attack_type = data.get('attack_type', 'DDoS')
    src_ip = data.get('src_ip', '192.168.1.185')
    count = int(data.get('count', 150))
    live_sniffer.simulate_attack_burst(attack_type=attack_type, src_ip=src_ip, packet_count=count)
    return jsonify({
        'success': True,
        'message': f'Burst paket {attack_type} ({count} pkt) berhasil ditembakkan ke Live Sniffer & dianalisis XGBoost!'
    })


@app.route('/api/sniffer/toggle', methods=['POST'])
@login_required
def api_sniffer_toggle():
    """Menghidupkan atau mematikan thread live packet sniffer secara dinamis dari dashboard."""
    if live_sniffer.is_running:
        success, msg = live_sniffer.stop()
    else:
        success, msg = live_sniffer.start(mode='Gateway Ingestion & Simulation')
    return jsonify({
        'success': success,
        'message': msg,
        'status': live_sniffer.stats['status'],
        'is_running': live_sniffer.is_running
    })


@app.route('/api/alerts/<int:alert_id>/status', methods=['POST'])
@login_required
def api_update_alert_status(alert_id):
    """Memperbarui status alert (Ditangani, False Positive, Perlu tindakan) oleh analis SOC."""
    alert = Alert.query.get_or_404(alert_id)
    # Verifikasi kepemilikan website
    site = Website.query.filter_by(id=alert.website_id, user_id=current_user.id).first()
    if not site:
        return jsonify({'error': 'Akses ditolak'}), 403

    data = request.get_json(silent=True) or {}
    new_status = data.get('status')
    notes = data.get('notes', '')
    allowed = ['Ditangani', 'False Positive', 'Terdeteksi', 'Perlu tindakan']
    if new_status in allowed:
        alert.status = new_status
        if notes:
            now_str = datetime.utcnow().strftime('%Y-%m-%d %H:%M')
            alert.notes = f"{alert.notes or ''}\n[{now_str}] {notes}".strip()
        db.session.commit()
        return jsonify({
            'success': True,
            'message': f'Status alert #{alert_id} berhasil diubah menjadi {new_status}',
            'status': alert.status
        })
    return jsonify({'error': 'Status tidak valid'}), 400


@app.route('/dashboard/<int:website_id>/export', methods=['GET'])
@login_required
def export_alerts_csv(website_id):
    """Mengunduh riwayat insiden / alert keamanan dalam format CSV untuk audit forensik."""
    import csv
    from io import StringIO
    from flask import Response

    site = Website.query.filter_by(id=website_id, user_id=current_user.id).first_or_404()
    alerts = Alert.query.filter_by(website_id=site.id).order_by(Alert.id.desc()).all()

    si = StringIO()
    cw = csv.writer(si)
    cw.writerow([
        'ID Alert', 'Waktu (WIB / UTC+7)', 'Tipe Serangan', 'Tingkat Bahaya',
        'IP Sumber', 'Target Endpoint', 'Confidence (%)', 'Detector Source',
        'Status', 'Detail / Payload'
    ])

    for a in alerts:
        wib_time = (a.created_at + timedelta(hours=7)).strftime('%Y-%m-%d %H:%M:%S WIB') if a.created_at else ''
        cw.writerow([
            a.id,
            wib_time,
            a.attack_type,
            a.severity,
            a.source_ip,
            urllib.parse.unquote(a.target_endpoint or ''),
            f"{a.confidence_score:.1f}",
            a.detector_source,
            a.status,
            a.detail
        ])

    clean_name = "".join(c for c in site.name if c.isalnum() or c in (' ', '_', '-')).strip().replace(' ', '_')
    filename = f"nids_alerts_{clean_name}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.csv"
    output = Response(si.getvalue(), mimetype='text/csv')
    output.headers["Content-Disposition"] = f"attachment; filename={filename}"
    return output


def ensure_database_exists():
    """Memastikan database MySQL dibuat otomatis di XAMPP jika belum ada."""
    try:
        import pymysql
        user = app.config.get('DB_USER', 'root')
        password = app.config.get('DB_PASSWORD', '')
        host = app.config.get('DB_HOST', '127.0.0.1')
        port = int(app.config.get('DB_PORT', 3306))
        dbname = app.config.get('DB_NAME', 'nids_monitor')

        conn = pymysql.connect(host=host, port=port, user=user, password=password)
        with conn.cursor() as cursor:
            cursor.execute(f"CREATE DATABASE IF NOT EXISTS `{dbname}` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;")
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"[INFO] Auto-create database check: {e}")


# ── Bootstrap DB & Run ────────────────────────────────────────────────────────
if __name__ == '__main__':
    ensure_database_exists()
    with app.app_context():
        db.create_all()
        print("[OK] Database siap.")
    app.run(debug=True, host='0.0.0.0', port=5000)
