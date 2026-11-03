import logging
import requests

logger = logging.getLogger(__name__)

class TelegramService:
    @staticmethod
    def send_message(bot_token, chat_id, message_text, parse_mode='Markdown'):
        """Sends a text message via Telegram Bot API."""
        if not bot_token or not chat_id:
            logger.warning("Telegram send skipped: Missing bot_token or chat_id.")
            return False, "Token bot atau Chat ID belum dikonfigurasi."
        
        endpoint = f"https://api.telegram.org/bot{bot_token.strip()}/sendMessage"
        payload = {
            'chat_id': str(chat_id).strip(),
            'text': message_text,
            'parse_mode': parse_mode
        }
        
        try:
            response = requests.post(endpoint, json=payload, timeout=4)
            data = response.json()
            if response.status_code == 200 and data.get('ok'):
                return True, "Pesan notifikasi Telegram berhasil terkirim."
            else:
                err_desc = data.get('description', 'Telegram API returned error.')
                logger.error(f"Telegram API error: {err_desc}")
                return False, f"Telegram API error: {err_desc}"
        except requests.exceptions.Timeout:
            logger.error("Telegram API request timed out.")
            return False, "Waktu koneksi ke Telegram API habis (timeout)."
        except Exception as e:
            logger.error(f"Failed to send Telegram message: {e}")
            return False, f"Gagal mengirim pesan: {str(e)}"

    @classmethod
    def send_alert_notification(cls, user, website, alert):
        """Sends an incident alert if user has enabled Telegram notifications."""
        if not user or not user.telegram_enabled:
            return False, "Notifikasi Telegram dinonaktifkan oleh pengguna."
        
        # Check level filter: if user wants only 'Kritis', don't send 'Peringatan' or 'Dipantau'
        if user.telegram_alert_level == 'Kritis' and alert.severity != 'Kritis':
            return False, f"Alert dilewati karena level '{alert.severity}' di bawah filter 'Kritis'."
            
        bot_token = user.telegram_bot_token or ""
        chat_id = user.telegram_chat_id or ""
        
        if not bot_token or not chat_id:
            return False, "Pengaturan bot Telegram pengguna belum lengkap."
            
        emoji_level = "🚨" if alert.severity == "Kritis" else ("⚠️" if alert.severity == "Peringatan" else "ℹ️")
        
        # Format markdown message
        msg = (
            f"{emoji_level} *NIDS MONITOR ALERT - {alert.severity.upper()}*\n"
            f"━━━━━━━━━━━━━━━━━━━━━━\n"
            f"*Website Target:* `{website.name}` ({website.target_url})\n"
            f"*Jenis Serangan:* *{alert.attack_type}*\n"
            f"*Tingkat Keyakinan:* `{alert.confidence_score:.1f}%`\n"
            f"*Detektor:* `{alert.detector_source}`\n"
            f"*IP Penyerang:* `{alert.source_ip}`\n"
            f"*Endpoint:* `{alert.target_endpoint[:100]}`\n"
        )
        
        if alert.pattern_detected:
            msg += f"*Pola Terdeteksi:* `{alert.pattern_detected[:120]}`\n"
            
        if alert.payload_sample:
            clean_sample = alert.payload_sample[:100].replace('`', "'")
            msg += f"*Contoh Payload:* `{clean_sample}`\n"
            
        msg += (
            f"\n💡 *Langkah Mitigasi Cepat:*\n"
            f"Buka detail insiden di dashboard NIDS Monitor untuk melihat checklist penanganan & saran aturan .htaccess.\n"
            f"━━━━━━━━━━━━━━━━━━━━━━\n"
            f"_Mode Operasional: Advisory (Non-Blocking)_"
        )
        
        return cls.send_message(bot_token, chat_id, msg)

    @classmethod
    def test_connection(cls, bot_token, chat_id):
        """Sends a test ping to verify token and chat ID."""
        test_msg = (
            "🤖 *NIDS MONITOR - TES KONEKSI BOT TELEGRAM*\n"
            "━━━━━━━━━━━━━━━━━━━━━━\n"
            "Status: ✅ *Koneksi Berhasil Terhubung!*\n"
            "Sistem NIDS Monitor siap mengirimkan notifikasi insiden serangan siber (DDoS, SQL Injection, XSS) secara real-time ke akun/grup ini.\n"
            "━━━━━━━━━━━━━━━━━━━━━━\n"
            "_Kelompok 10 - AI for Security PjBL 2026_"
        )
        return cls.send_message(bot_token, chat_id, test_msg)
