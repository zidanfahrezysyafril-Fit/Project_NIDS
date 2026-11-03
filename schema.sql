-- ============================================================
-- NIDS Monitor - Database Schema untuk MySQL / MariaDB (XAMPP)
-- ============================================================

CREATE DATABASE IF NOT EXISTS `nids_monitor` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE `nids_monitor`;

CREATE TABLE IF NOT EXISTS `users` (
    `id` INT AUTO_INCREMENT PRIMARY KEY,
    `username` VARCHAR(80) NOT NULL UNIQUE,
    `email` VARCHAR(120) NOT NULL UNIQUE,
    `password_hash` VARCHAR(255) NOT NULL,
    `full_name` VARCHAR(120) DEFAULT '',
    `role` VARCHAR(20) DEFAULT 'analyst',
    `created_at` DATETIME DEFAULT CURRENT_TIMESTAMP,
    `last_selected_target_id` INT NULL,
    `telegram_bot_token` VARCHAR(150) DEFAULT '',
    `telegram_chat_id` VARCHAR(100) DEFAULT '',
    `telegram_enabled` BOOLEAN DEFAULT FALSE,
    `telegram_alert_level` VARCHAR(20) DEFAULT 'Kritis',
    `llm_questions_today` INT DEFAULT 0,
    `llm_last_reset_date` DATE NULL,
    INDEX `ix_users_username` (`username`),
    INDEX `ix_users_email` (`email`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS `websites` (
    `id` INT AUTO_INCREMENT PRIMARY KEY,
    `user_id` INT NOT NULL,
    `name` VARCHAR(120) NOT NULL,
    `target_url` VARCHAR(255) NOT NULL,
    `api_key` VARCHAR(64) NOT NULL UNIQUE,
    `created_at` DATETIME DEFAULT CURRENT_TIMESTAMP,
    `status` VARCHAR(30) DEFAULT 'Menunggu Konektor',
    `last_ping_at` DATETIME NULL,
    `ddos_threshold_req` INT DEFAULT 100,
    `ddos_window_sec` INT DEFAULT 10,
    `exclude_destination_port` BOOLEAN DEFAULT TRUE,
    `total_requests_received` INT DEFAULT 0,
    `total_alerts_count` INT DEFAULT 0,
    INDEX `ix_websites_user_id` (`user_id`),
    INDEX `ix_websites_api_key` (`api_key`),
    CONSTRAINT `fk_websites_user` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS `alerts` (
    `id` INT AUTO_INCREMENT PRIMARY KEY,
    `website_id` INT NOT NULL,
    `attack_type` VARCHAR(80) NOT NULL,
    `severity` VARCHAR(20) DEFAULT 'Peringatan',
    `status` VARCHAR(30) DEFAULT 'Terdeteksi',
    `source_ip` VARCHAR(50) NOT NULL,
    `target_endpoint` VARCHAR(255) DEFAULT '/',
    `payload_sample` LONGTEXT,
    `pattern_detected` VARCHAR(200) DEFAULT '',
    `confidence_score` FLOAT DEFAULT 95.0,
    `detector_source` VARCHAR(80) DEFAULT 'Regex + Text ML',
    `mitigation_checklist` LONGTEXT,
    `htaccess_rule` LONGTEXT,
    `notes` LONGTEXT,
    `created_at` DATETIME DEFAULT CURRENT_TIMESTAMP,
    `updated_at` DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX `ix_alerts_website_id` (`website_id`),
    INDEX `ix_alerts_attack_type` (`attack_type`),
    INDEX `ix_alerts_severity` (`severity`),
    INDEX `ix_alerts_status` (`status`),
    INDEX `ix_alerts_source_ip` (`source_ip`),
    INDEX `ix_alerts_created_at` (`created_at`),
    CONSTRAINT `fk_alerts_website` FOREIGN KEY (`website_id`) REFERENCES `websites` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS `log_entries` (
    `id` INT AUTO_INCREMENT PRIMARY KEY,
    `website_id` INT NOT NULL,
    `alert_id` INT NULL,
    `ip_address` VARCHAR(50) NOT NULL,
    `timestamp` DATETIME DEFAULT CURRENT_TIMESTAMP,
    `http_method` VARCHAR(10) DEFAULT 'GET',
    `request_uri` TEXT NOT NULL,
    `status_code` INT DEFAULT 200,
    `bytes_sent` INT DEFAULT 0,
    `referer` TEXT,
    `user_agent` TEXT,
    `is_suspicious` BOOLEAN DEFAULT FALSE,
    `attack_label` VARCHAR(50) DEFAULT 'BENIGN',
    `confidence` FLOAT DEFAULT 0.0,
    `is_manual_upload` BOOLEAN DEFAULT FALSE,
    INDEX `ix_log_entries_website_id` (`website_id`),
    INDEX `ix_log_entries_alert_id` (`alert_id`),
    INDEX `ix_log_entries_ip_address` (`ip_address`),
    INDEX `ix_log_entries_timestamp` (`timestamp`),
    INDEX `ix_log_entries_is_suspicious` (`is_suspicious`),
    CONSTRAINT `fk_logs_website` FOREIGN KEY (`website_id`) REFERENCES `websites` (`id`) ON DELETE CASCADE,
    CONSTRAINT `fk_logs_alert` FOREIGN KEY (`alert_id`) REFERENCES `alerts` (`id`) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS `traffic_metrics` (
    `id` INT AUTO_INCREMENT PRIMARY KEY,
    `website_id` INT NOT NULL,
    `timestamp` DATETIME DEFAULT CURRENT_TIMESTAMP,
    `request_count` INT DEFAULT 0,
    `suspicious_count` INT DEFAULT 0,
    `unique_ips` INT DEFAULT 0,
    `current_rps` FLOAT DEFAULT 0.0,
    INDEX `ix_traffic_metrics_website_id` (`website_id`),
    INDEX `ix_traffic_metrics_timestamp` (`timestamp`),
    CONSTRAINT `fk_traffic_website` FOREIGN KEY (`website_id`) REFERENCES `websites` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS `chat_messages` (
    `id` INT AUTO_INCREMENT PRIMARY KEY,
    `user_id` INT NOT NULL,
    `website_id` INT NULL,
    `alert_id` INT NULL,
    `role` VARCHAR(20) NOT NULL,
    `content` TEXT NOT NULL,
    `created_at` DATETIME DEFAULT CURRENT_TIMESTAMP,
    INDEX `ix_chat_messages_website_id` (`website_id`),
    CONSTRAINT `fk_chat_user` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE CASCADE,
    CONSTRAINT `fk_chat_alert` FOREIGN KEY (`alert_id`) REFERENCES `alerts` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

