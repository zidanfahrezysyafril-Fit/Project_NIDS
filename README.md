# NIDS Monitor - Network Intrusion Detection System
**Kelompok 10 | AI for Security**

## 📋 Deskripsi
Platform berbasis web (Flask/Python) untuk memantau serangan siber pada website pengguna secara real-time.
Mendukung deteksi DDoS, XSS, SQL Injection, dan serangan umum lainnya.

---

## 🚀 Cara Menjalankan

### 1. Install dependensi
```bash
pip install -r requirements.txt
```

### 2. Jalankan aplikasi
```bash
python app.py
```
Buka browser: `http://localhost:5000`

> **Tidak perlu Laragon** — proyek ini berbasis Python Flask, bukan PHP.

---

## 📁 Struktur Folder

```
Project NIDS/
├── app.py                  ← Entry point utama
├── config.py               ← Konfigurasi Flask & database
├── models.py               ← Model database (SQLAlchemy)
├── requirements.txt        ← Dependensi Python
│
├── detectors/
│   ├── ddos_detector.py        ← Deteksi DDoS (sliding window)
│   ├── web_attack_detector.py  ← Deteksi XSS/SQLi (Regex + ML)
│   ├── cicids_flow_detector.py ← Deteksi via CICIDS2017 (XGBoost)
│   └── train_text_model.py     ← Script training model teks
│
├── services/
│   ├── telegram_service.py     ← Notifikasi Telegram Bot
│   ├── mitigation_guide.py     ← Panduan mitigasi & .htaccess
│   └── assistant_service.py   ← AI Security Assistant
│
├── templates/              ← Template HTML (Jinja2)
├── static/                 ← CSS, JS, gambar
├── data/                   ← Model ML tersimpan (.pkl)
└── connectors/             ← Konektor plugin WordPress
```

---

## 🛠️ Stack Teknologi
| Komponen | Teknologi |
|---|---|
| Backend | Python Flask |
| Database | SQLite (SQLAlchemy) |
| ML - DDoS | XGBoost + Random Forest (CICIDS2017) |
| ML - Web Attack | TF-IDF n-gram + Random Forest |
| Auth | Flask-Login |
| Notifikasi | Telegram Bot API |
| Scheduler | APScheduler |

---

## 🔑 Fitur Utama
1. **Login & Session Persisten** — auto-redirect ke website terakhir dipantau
2. **Deteksi DDoS** — sliding window request rate per IP
3. **Deteksi Web Attack** — XSS, SQL Injection via regex + model ML
4. **Live Alert** — polling API JSON setiap 5 detik
5. **AI Assistant** — tanya jawab keamanan dengan anonymizer IP
6. **Notifikasi Telegram** — alert otomatis ke chat Telegram
7. **Panduan Mitigasi** — langkah perbaikan + generate .htaccess
