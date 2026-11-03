import os
from datetime import timedelta
from dotenv import load_dotenv

BASE_DIR = os.path.abspath(os.path.dirname(__file__))

# Muat variabel environment dari file .env jika ada
load_dotenv(os.path.join(BASE_DIR, '.env'))

def _find_model(filename):
    """Cari model file di root project dulu, lalu di subfolder data/."""
    root_path = os.path.join(BASE_DIR, filename)
    data_path = os.path.join(BASE_DIR, 'data', filename)
    if os.path.exists(root_path):
        return root_path
    if os.path.exists(data_path):
        return data_path
    return data_path  # default path (meski belum ada)

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY', 'nids-monitor-kelompok10-cybersecurity-secret-key-2026')

    # Konfigurasi Database XAMPP (MySQL / MariaDB)
    DB_USER = os.environ.get('DB_USER', 'root')
    DB_PASSWORD = os.environ.get('DB_PASSWORD', '')
    DB_HOST = os.environ.get('DB_HOST', '127.0.0.1')
    DB_PORT = os.environ.get('DB_PORT', '3306')
    DB_NAME = os.environ.get('DB_NAME', 'nids_monitor')

    # Format URI MySQL menggunakan driver PyMySQL
    MYSQL_DEFAULT_URI = f"mysql+pymysql://{DB_USER}:{DB_PASSWORD}@{DB_HOST}:{DB_PORT}/{DB_NAME}?charset=utf8mb4"
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL', MYSQL_DEFAULT_URI)
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # Session config (30 days persistence)
    PERMANENT_SESSION_LIFETIME = timedelta(days=30)
    REMEMBER_COOKIE_DURATION = timedelta(days=30)
    REMEMBER_COOKIE_REFRESH_EACH_REQUEST = True
    
    # Upload folder for manual access logs
    UPLOAD_FOLDER = os.path.join(BASE_DIR, 'data', 'uploads')
    MAX_CONTENT_LENGTH = 200 * 1024 * 1024  # 200 MB max (untuk CSV CICIDS2017)

    # Model paths — dicari di root project dulu, lalu di data/
    CICIDS_MODEL_PATH = _find_model('cicids_flow_model.pkl')
    WEB_ATTACK_MODEL_PATH = _find_model('web_attack_model.pkl')
    
    # DDoS Default Thresholds
    DEFAULT_DDOS_THRESHOLD_REQ = 100  # requests
    DEFAULT_DDOS_WINDOW_SEC = 10      # seconds
    
    # Security Assistant LLM Config
    LLM_PROVIDER = os.environ.get('LLM_PROVIDER', 'mock') # mock, openai, gemini, etc.
    LLM_API_KEY = os.environ.get('LLM_API_KEY', '')
    LLM_MODEL = os.environ.get('LLM_MODEL', 'gemini-1.5-flash')
    LLM_DAILY_LIMIT_PER_USER = 50
    
    # Telegram Default Configuration
    TELEGRAM_BOT_TOKEN = os.environ.get('TELEGRAM_BOT_TOKEN', '')
    
os.makedirs(Config.UPLOAD_FOLDER, exist_ok=True)
os.makedirs(os.path.join(BASE_DIR, 'data'), exist_ok=True)
