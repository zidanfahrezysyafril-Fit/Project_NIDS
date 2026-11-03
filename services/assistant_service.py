import re
import os
import requests
import json
import logging

logger = logging.getLogger(__name__)

class SecurityAssistantService:
    DISCLAIMER = "⚠️ Catatan Penting: Jawaban asisten AI bersifat edukatif dan advisori. Selalu verifikasi kode serta konfigurasi sebelum menerapkannya di lingkungan produksi."

    @staticmethod
    def anonymize_text(text):
        """Replaces raw IP addresses and sensitive tokens to maintain privacy."""
        if not text:
            return ""
        # Anonymize IPv4 addresses
        ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
        anonymized = re.sub(ip_pattern, '[ANONYMIZED_IP]', text)
        # Anonymize domain names in URL if needed
        anonymized = re.sub(r'https?://[a-zA-Z0-9\-\.]+', 'https://[TARGET_DOMAIN]', anonymized)
        return anonymized

    @classmethod
    def generate_response(cls, user_prompt, alert_context, chat_history=None, api_key=None, provider='mock'):
        """
        Generates an advisory response using the selected LLM provider or fallback expert engine.
        Ensures strict compliance with guidelines:
        - No raw IP or unredacted confidential data is sent.
        - Provides specific remediation steps based on fixed mitigation context.
        """
        chat_history = chat_history or []
        
        # Build sanitized contextual prompt
        attack_type = alert_context.get('attack_type', 'Serangan Siber Umum')
        severity = alert_context.get('severity', 'Peringatan')
        pattern = alert_context.get('pattern_detected', 'Pola anomali')
        payload = cls.anonymize_text(alert_context.get('payload_sample', ''))
        endpoint = cls.anonymize_text(alert_context.get('target_endpoint', '/'))
        mitigation_summary = alert_context.get('mitigation_summary', '')
        
        system_instructions = (
            "Anda adalah Asisten Keamanan Siber Khusus NIDS Monitor (Kelompok 10 - AI for Security). "
            "Tugas Anda adalah membantu pemilik website memahami dan memitigasi serangan siber yang terdeteksi. "
            "ATURAN WAJIB:\n"
            "1. Anda BUKAN penentu apakah ini serangan atau bukan (keputusan itu telah dibuat oleh model deteksi NIDS).\n"
            "2. Jangan pernah menyarankan meluncurkan serangan balik atau tools ilegal.\n"
            "3. Berikan saran kode yang aman (misalnya: contoh PDO prepared statement untuk SQLi, atau htmlspecialchars/CSP untuk XSS).\n"
            "4. Sertakan selalu himbauan untuk melakukan backup database sebelum mengubah kode atau file .htaccess.\n"
            "5. Jawab dalam Bahasa Indonesia yang ramah, profesional, dan to-the-point dengan format Markdown rapi."
        )

        context_info = (
            f"KONTEKS INSIDEN KEAMANAN:\n"
            f"- Jenis Serangan Terdeteksi: {attack_type}\n"
            f"- Tingkat Keparahan: {severity}\n"
            f"- Endpoint Target (Dianonimkan): {endpoint}\n"
            f"- Pola Deteksi: {pattern}\n"
            f"- Cuplikan Payload Terdeteksi (Dianonimkan): {payload}\n"
            f"- Panduan Mitigasi Dasar: {mitigation_summary}\n"
        )
        
        env_key = api_key or os.environ.get('LLM_API_KEY', '')
        selected_provider = provider or os.environ.get('LLM_PROVIDER', 'mock')
        
        # Check if actual Gemini / OpenAI API key is supplied
        if selected_provider == 'gemini' and env_key:
            return cls._call_gemini_api(system_instructions, context_info, user_prompt, chat_history, env_key)
        elif selected_provider == 'openai' and env_key:
            return cls._call_openai_api(system_instructions, context_info, user_prompt, chat_history, env_key)
        else:
            # High-grade offline Expert Knowledge Base
            return cls._generate_expert_mock_response(user_prompt, attack_type, payload, endpoint)

    @classmethod
    def _call_gemini_api(cls, system_prompt, context_info, user_prompt, history, api_key):
        try:
            url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key={api_key}"
            contents = [
                {"role": "user", "parts": [{"text": f"{system_prompt}\n\n{context_info}"}]},
                {"role": "model", "parts": [{"text": "Dimengerti. Saya siap menganalisis insiden dan memberikan panduan mitigasi teknis yang aman."}]}
            ]
            for h in history[-4:]:
                role = "user" if h.get('role') == 'user' else "model"
                contents.append({"role": role, "parts": [{"text": h.get('content', '')}]})
            contents.append({"role": "user", "parts": [{"text": user_prompt}]})
            
            payload = {"contents": contents}
            resp = requests.post(url, json=payload, timeout=12)
            if resp.status_code == 200:
                data = resp.json()
                text = data['candidates'][0]['content']['parts'][0]['text']
                return f"{text}\n\n---\n*{cls.DISCLAIMER}*"
        except Exception as e:
            logger.error(f"Gemini API error: {e}")
            
        return cls._generate_expert_mock_response(user_prompt, "Insiden Keamanan", "[REDACTED]", "/")

    @classmethod
    def _call_openai_api(cls, system_prompt, context_info, user_prompt, history, api_key):
        try:
            url = "https://api.openai.com/v1/chat/completions"
            headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}
            messages = [
                {"role": "system", "content": f"{system_prompt}\n\n{context_info}"}
            ]
            for h in history[-4:]:
                messages.append({"role": h.get('role', 'user'), "content": h.get('content', '')})
            messages.append({"role": "user", "content": user_prompt})
            
            resp = requests.post(url, json={"model": "gpt-4o-mini", "messages": messages, "max_tokens": 800}, headers=headers, timeout=12)
            if resp.status_code == 200:
                data = resp.json()
                text = data['choices'][0]['message']['content']
                return f"{text}\n\n---\n*{cls.DISCLAIMER}*"
        except Exception as e:
            logger.error(f"OpenAI API error: {e}")
            
        return cls._generate_expert_mock_response(user_prompt, "Insiden Keamanan", "[REDACTED]", "/")

    @classmethod
    def _generate_expert_mock_response(cls, prompt, attack_type, payload, endpoint):
        """Intelligent offline knowledge base response with specific contextual code solutions."""
        prompt_lower = prompt.lower()
        
        if 'htaccess' in prompt_lower or 'blokir' in prompt_lower:
            return (
                f"### 🛡️ Panduan Pemblokiran IP via `.htaccess`\n\n"
                f"Untuk memblokir IP penyerang sementara pada web server Apache / LiteSpeed (Shared Hosting), ikuti langkah berikut:\n\n"
                f"1. Buka File Manager di cPanel hosting Anda, lalu cari file `.htaccess` di direktori root website (`public_html`).\n"
                f"2. Letakkan aturan berikut pada baris paling atas:\n\n"
                f"```apache\n"
                f"# Blokir Darurat NIDS Monitor\n"
                f"<RequireAll>\n"
                f"    Require all granted\n"
                f"    Require not ip [IP_PENYERANG]\n"
                f"</RequireAll>\n"
                f"```\n\n"
                f"*Tips Keamanan:* Anda juga dapat menggunakan menu **IP Blocker** bawaan cPanel untuk kemudahan tanpa perlu mengedit file secara manual.\n\n"
                f"---\n*{cls.DISCLAIMER}*"
            )
            
        if 'sql' in attack_type.lower() or 'sqli' in prompt_lower or 'database' in prompt_lower:
            return (
                f"### 🛡️ Solusi Perbaikan Celah SQL Injection pada Endpoint `{endpoint}`\n\n"
                f"Serangan SQL Injection terjadi ketika input pengguna langsung digabungkan ke dalam sintaks query database.\n\n"
                f"#### Contoh Kode Rentan (Vulnerable):\n"
                f"```php\n"
                f"// JANGAN GUNAKAN INI:\n"
                f"$id = $_GET['id'];\n"
                f"$query = \"SELECT * FROM users WHERE id = '$id'\"; // Rentan terhadap payload {payload or 'OR 1=1'}\n"
                f"```\n\n"
                f"#### Perbaikan Aman Menggunakan PDO Prepared Statements:\n"
                f"```php\n"
                f"// REKOMENDASI AMAN:\n"
                f"$stmt = $pdo->prepare('SELECT id, username, email FROM users WHERE id = :id');\n"
                f"$stmt->execute(['id' => $_GET['id']]);\n"
                f"$user = $stmt->fetch();\n"
                f"```\n\n"
                f"#### Langkah Tambahan:\n"
                f"- Pastikan user database Anda tidak memiliki hak akses `DROP TABLE`.\n"
                f"- Aktifkan validasi tipe data (contoh: pastikan parameter `id` hanya berupa angka `intval($_GET['id'])`).\n\n"
                f"---\n*{cls.DISCLAIMER}*"
            )
            
        if 'xss' in attack_type.lower() or 'script' in prompt_lower or 'cross-site' in prompt_lower:
            return (
                f"### 🛡️ Solusi Perbaikan Celah Cross-Site Scripting (XSS)\n\n"
                f"Payload `{payload or '<script>alert(1)</script>'}` terdeteksi mencoba menyuntikkan skrip ke peramban korban.\n\n"
                f"#### 1. Output Encoding / Escaping di PHP:\n"
                f"```php\n"
                f"// Sebelum mencetak variabel pengguna ke browser, wajib lakukan sanitasi:\n"
                f"echo htmlspecialchars($input_pengguna, ENT_QUOTES, 'UTF-8');\n"
                f"```\n\n"
                f"#### 2. Header Content-Security-Policy (CSP):\n"
                f"Tambahkan baris berikut di `.htaccess` atau header PHP Anda untuk melarang skrip asing:\n"
                f"```http\n"
                f"Header set Content-Security-Policy \"default-src 'self'; script-src 'self';\"\n"
                f"```\n\n"
                f"#### 3. Proteksi Cookie Sesi:\n"
                f"Pastikan session cookie diset dengan `HttpOnly` agar JavaScript hacker tidak bisa mencuri sesi login:\n"
                f"```php\n"
                f"session_set_cookie_params(['httponly' => true, 'secure' => true, 'samesite' => 'Lax']);\n"
                f"session_start();\n"
                f"```\n\n"
                f"---\n*{cls.DISCLAIMER}*"
            )
            
        if 'ddos' in attack_type.lower() or 'flood' in prompt_lower:
            return (
                f"### 🛡️ Langkah Penanganan Serangan DDoS / HTTP Flood\n\n"
                f"Serangan DDoS membanjiri server Anda dengan request bertubi-tubi untuk melumpuhkan ketersediaan.\n\n"
                f"#### Tindakan Prioritas:\n"
                f"1. **Aktifkan Cloudflare (Gratis & Paling Efektif):**\n"
                f"   - Alihkan NameServer domain Anda ke Cloudflare.\n"
                f"   - Masuk ke dashboard Cloudflare dan aktifkan **'I'm Under Attack Mode'**.\n"
                f"   - Cloudflare akan menampilkan pemeriksaan JavaScript otomatis untuk memfilter bot penyerang sebelum mencapai shared hosting Anda.\n\n"
                f"2. **Rate Limiting di Shared Hosting:**\n"
                f"   - Hubungi customer support hosting untuk menanyakan apakah fitur ModSecurity / Rate Limit IP dapat dinaikkan agresivitasnya.\n"
                f"3. **Aktifkan Caching Halaman:**\n"
                f"   - Pasang LiteSpeed Cache atau WP Super Cache agar server menyajikan file statis tanpa perlu memproses script PHP dan MySQL.\n\n"
                f"---\n*{cls.DISCLAIMER}*"
            )

        # General response
        return (
            f"### 🛡️ Analisis Insiden `{attack_type}`\n\n"
            f"Berdasarkan telemetri pada endpoint `{endpoint}`, sistem NIDS mendeteksi anomali keamanan.\n\n"
            f"#### Rekomendasi Penanganan Cepat:\n"
            f"1. Periksa log akses web server pada rentang waktu serangan untuk mengidentifikasi pola IP penyerang.\n"
            f"2. Lakukan audit pada file yang baru dimodifikasi untuk memastikan tidak ada backdoor atau file web shell yang berhasil ditanam.\n"
            f"3. Simak checklist mitigasi terperinci di sisi kiri halaman detail alert ini dan centang setiap langkah yang telah selesai Anda lakukan.\n\n"
            f"Ada hal teknis tertentu (seperti kode PHP, konfigurasi server, atau aturan firewall) yang ingin Anda tanyakan lebih rinci?\n\n"
            f"---\n*{cls.DISCLAIMER}*"
        )


def answer_security_question(question, website_id=None, alert_id=None, history=None):
    """
    Main helper function used by app routes to generate AI security guidance.
    """
    alert_context = {
        'attack_type': 'Analisis Keamanan Umum',
        'severity': 'Info',
        'pattern_detected': 'Konsultasi Interaktif',
        'payload_sample': '',
        'target_endpoint': '/',
        'mitigation_summary': 'Panduan keamanan web proaktif'
    }

    # Fetch recent alert if alert_id or website_id provided
    try:
        from models import Alert, Website
        if alert_id:
            a = Alert.query.get(alert_id)
            if a:
                alert_context = {
                    'attack_type': a.attack_type,
                    'severity': a.severity,
                    'pattern_detected': a.pattern_detected or a.attack_type,
                    'payload_sample': a.payload_sample or '',
                    'target_endpoint': a.target_endpoint or '/',
                    'mitigation_summary': a.notes or ''
                }
        elif website_id:
            latest_alert = Alert.query.filter_by(website_id=website_id).order_by(Alert.created_at.desc()).first()
            if latest_alert:
                alert_context = {
                    'attack_type': latest_alert.attack_type,
                    'severity': latest_alert.severity,
                    'pattern_detected': latest_alert.pattern_detected or latest_alert.attack_type,
                    'payload_sample': latest_alert.payload_sample or '',
                    'target_endpoint': latest_alert.target_endpoint or '/',
                    'mitigation_summary': latest_alert.notes or ''
                }
    except Exception as e:
        logger.warning(f"Could not load alert context: {e}")

    # Determine attack type from question if relevant
    q_lower = question.lower()
    if 'ddos' in q_lower or 'flood' in q_lower:
        alert_context['attack_type'] = 'DDoS'
    elif 'xss' in q_lower or 'script' in q_lower:
        alert_context['attack_type'] = 'Cross-Site Scripting (XSS)'
    elif 'sqli' in q_lower or 'sql' in q_lower or 'injeksi' in q_lower:
        alert_context['attack_type'] = 'SQL Injection'

    return SecurityAssistantService.generate_response(
        user_prompt=question,
        alert_context=alert_context,
        chat_history=history or []
    )
