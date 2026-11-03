import secrets
from datetime import datetime, date
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash

db = SQLAlchemy()

class User(UserMixin, db.Model):
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    full_name = db.Column(db.String(120), default='')
    role = db.Column(db.String(20), default='analyst') # analyst, admin
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Auto-resume feature: remember last viewed target website
    last_selected_target_id = db.Column(db.Integer, nullable=True)
    
    # Telegram Alert Configuration per User
    telegram_bot_token = db.Column(db.String(150), default='')
    telegram_chat_id = db.Column(db.String(100), default='')
    telegram_enabled = db.Column(db.Boolean, default=False)
    telegram_alert_level = db.Column(db.String(20), default='Kritis') # Kritis, Semua
    
    # Rate limiting for Security Assistant Chatbot
    llm_questions_today = db.Column(db.Integer, default=0)
    llm_last_reset_date = db.Column(db.Date, default=date.today)
    
    # Relationships
    websites = db.relationship('Website', backref='owner', lazy=True, cascade='all, delete-orphan')
    chat_messages = db.relationship('ChatMessage', backref='user', lazy=True, cascade='all, delete-orphan')

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash((self.password_hash or '').strip(), password)

    def can_ask_llm(self, limit=50):
        today = date.today()
        if self.llm_last_reset_date != today:
            self.llm_questions_today = 0
            self.llm_last_reset_date = today
            db.session.commit()
        return self.llm_questions_today < limit

    def record_llm_question(self):
        self.llm_questions_today += 1
        db.session.commit()


class Website(db.Model):
    __tablename__ = 'websites'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), nullable=False, index=True)
    name = db.Column(db.String(120), nullable=False)
    target_url = db.Column(db.String(255), nullable=False)
    api_key = db.Column(db.String(64), unique=True, nullable=False, index=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Status
    status = db.Column(db.String(30), default='Menunggu Konektor') # Menunggu Konektor, Terhubung, Peringatan, Serangan Aktif
    last_ping_at = db.Column(db.DateTime, nullable=True)
    
    # Configurable detection thresholds
    ddos_threshold_req = db.Column(db.Integer, default=100) # req count
    ddos_window_sec = db.Column(db.Integer, default=10)    # time window in seconds
    
    # Flow model settings (Destination port toggle)
    exclude_destination_port = db.Column(db.Boolean, default=True)
    
    # Counters
    total_requests_received = db.Column(db.Integer, default=0)
    total_alerts_count = db.Column(db.Integer, default=0)
    
    # Relationships
    alerts = db.relationship('Alert', backref='website', lazy=True, cascade='all, delete-orphan')
    log_entries = db.relationship('LogEntry', backref='website', lazy=True, cascade='all, delete-orphan')
    traffic_metrics = db.relationship('TrafficMetric', backref='website', lazy=True, cascade='all, delete-orphan')

    @property
    def url(self):
        return self.target_url

    @property
    def is_active(self):
        return self.status == 'Terhubung'

    @staticmethod
    def generate_api_key():
        return f"nids_live_{secrets.token_hex(20)}"


class Alert(db.Model):
    __tablename__ = 'alerts'
    
    id = db.Column(db.Integer, primary_key=True)
    website_id = db.Column(db.Integer, db.ForeignKey('websites.id', ondelete='CASCADE'), nullable=False, index=True)
    
    # Attack Type
    # DDoS, SQL Injection, Cross-Site Scripting (XSS), Brute Force, PortScan, Botnet, Flow Anomaly
    attack_type = db.Column(db.String(80), nullable=False, index=True)
    
    # Severity & Status
    # Severity: Kritis, Peringatan, Dipantau
    severity = db.Column(db.String(20), default='Peringatan', index=True)
    # Status: Terdeteksi, Perlu tindakan, Ditangani
    status = db.Column(db.String(30), default='Terdeteksi', index=True)
    
    # Technical Details
    source_ip = db.Column(db.String(50), nullable=False, index=True)
    target_endpoint = db.Column(db.String(255), default='/')
    payload_sample = db.Column(db.Text, default='')
    pattern_detected = db.Column(db.String(200), default='')
    confidence_score = db.Column(db.Float, default=95.0) # percentage 0-100%
    
    # Detector Source: 'Log Rate Limiter', 'Regex + Text ML', 'CICIDS Flow XGBoost', 'Upload Log Analisis'
    detector_source = db.Column(db.String(80), default='Regex + Text ML')
    
    # Checklist and Mitigation
    mitigation_checklist = db.Column(db.Text, default='[]') # JSON string of checklist items
    htaccess_rule = db.Column(db.Text, default='')
    notes = db.Column(db.Text, default='')
    
    # Timestamps
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    chat_messages = db.relationship('ChatMessage', backref='alert', lazy=True, cascade='all, delete-orphan')

    @property
    def detail(self):
        return self.pattern_detected or self.payload_sample or self.target_endpoint or 'Pola anomali'


class LogEntry(db.Model):
    __tablename__ = 'log_entries'
    
    id = db.Column(db.Integer, primary_key=True)
    website_id = db.Column(db.Integer, db.ForeignKey('websites.id', ondelete='CASCADE'), nullable=False, index=True)
    alert_id = db.Column(db.Integer, db.ForeignKey('alerts.id', ondelete='SET NULL'), nullable=True)
    
    ip_address = db.Column(db.String(50), nullable=False, index=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    http_method = db.Column(db.String(10), default='GET')
    request_uri = db.Column(db.Text, nullable=False)
    status_code = db.Column(db.Integer, default=200)
    bytes_sent = db.Column(db.Integer, default=0)
    referer = db.Column(db.Text, default='')
    user_agent = db.Column(db.Text, default='')
    
    is_suspicious = db.Column(db.Boolean, default=False, index=True)
    attack_label = db.Column(db.String(50), default='BENIGN')
    confidence = db.Column(db.Float, default=0.0)
    is_manual_upload = db.Column(db.Boolean, default=False)


class TrafficMetric(db.Model):
    __tablename__ = 'traffic_metrics'
    
    id = db.Column(db.Integer, primary_key=True)
    website_id = db.Column(db.Integer, db.ForeignKey('websites.id', ondelete='CASCADE'), nullable=False, index=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    request_count = db.Column(db.Integer, default=0)
    suspicious_count = db.Column(db.Integer, default=0)
    unique_ips = db.Column(db.Integer, default=0)
    current_rps = db.Column(db.Float, default=0.0)


class ChatMessage(db.Model):
    __tablename__ = 'chat_messages'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), nullable=False)
    website_id = db.Column(db.Integer, nullable=True, index=True)
    alert_id = db.Column(db.Integer, db.ForeignKey('alerts.id', ondelete='CASCADE'), nullable=True)
    
    role = db.Column(db.String(20), nullable=False) # user, assistant, system
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
