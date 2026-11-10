<?php
/**
 * NIDS Monitor - Standalone PHP Connector Agent
 * Kelompok 10 - AI for Security
 * 
 * Cara Penggunaan:
 * 1. Letakkan file ini di root folder website (atau di dalam folder public/ jika menggunakan Laravel).
 * 2. Konfigurasi NIDS_SERVER_URL dan NIDS_API_KEY di bawah (jika tidak otomatis).
 * 3. Tambahkan baris pemanggil di baris paling atas file index.php website Anda:
 *    if (file_exists(__DIR__ . '/nids_agent.php')) {
 *        require_once __DIR__ . '/nids_agent.php';
 *    }
 */

// ── Konfigurasi ─────────────────────────────────────────────────────────────
if (!defined('NIDS_SERVER_URL')) {
    define('NIDS_SERVER_URL', 'http://127.0.0.1:5000'); // Ganti dengan URL platform NIDS Anda
}
if (!defined('NIDS_API_KEY')) {
    define('NIDS_API_KEY', 'MASUKKAN_API_KEY_ANDA_DISINI'); // Ganti dengan API Key website Anda
}

// ── Logika Pemantauan ────────────────────────────────────────────────────────
(function() {
    // Abaikan jika dipanggil dari command line (CLI)
    if (php_sapi_name() === 'cli') return;

    $server_url = rtrim(NIDS_SERVER_URL, '/');
    $api_key    = trim(NIDS_API_KEY);

    if (empty($api_key) || $api_key === 'MASUKKAN_API_KEY_ANDA_DISINI') {
        return;
    }

    // Tangkap IP pengunjung (support Reverse Proxy, Cloudflare, VPN, & Testbed)
    $client_ip = '127.0.0.1';
    if (!empty($_SERVER['HTTP_X_ATTACKER_IP'])) {
        $client_ip = trim($_SERVER['HTTP_X_ATTACKER_IP']);
    } elseif (!empty($_GET['simulate_ip'])) {
        $client_ip = trim($_GET['simulate_ip']);
    } elseif (!empty($_SERVER['HTTP_CF_CONNECTING_IP'])) {
        $client_ip = $_SERVER['HTTP_CF_CONNECTING_IP'];
    } elseif (!empty($_SERVER['HTTP_X_REAL_IP'])) {
        $client_ip = $_SERVER['HTTP_X_REAL_IP'];
    } elseif (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
        $parts = explode(',', $_SERVER['HTTP_X_FORWARDED_FOR']);
        $client_ip = trim($parts[0]);
    } elseif (!empty($_SERVER['HTTP_CLIENT_IP'])) {
        $client_ip = $_SERVER['HTTP_CLIENT_IP'];
    } elseif (!empty($_SERVER['REMOTE_ADDR'])) {
        $client_ip = $_SERVER['REMOTE_ADDR'];
    }

    if ($client_ip === '::1') {
        $client_ip = '127.0.0.1';
    }

    $uri = isset($_SERVER['REQUEST_URI']) ? $_SERVER['REQUEST_URI'] : '/';

    // Abaikan aset statis (CSS, JS, gambar, font)
    if (preg_match('/\.(css|js|jpg|jpeg|png|gif|ico|svg|woff|woff2|ttf|eot)$/i', $uri)) {
        return;
    }

    $method = isset($_SERVER['REQUEST_METHOD']) ? strtoupper($_SERVER['REQUEST_METHOD']) : 'GET';
    $user_agent = isset($_SERVER['HTTP_USER_AGENT']) ? $_SERVER['HTTP_USER_AGENT'] : '';

    $post_body = '';
    if ($method === 'POST' && !empty($_POST)) {
        $post_body = substr(http_build_query($_POST), 0, 1000);
    } elseif ($method === 'POST') {
        // Fallback untuk raw JSON payload
        $raw_input = @file_get_contents('php://input');
        if (!empty($raw_input)) {
            $post_body = substr($raw_input, 0, 1000);
        }
    }

    $payload = json_encode([
        'api_key'     => $api_key,
        'ip_address'  => $client_ip,
        'method'      => $method,
        'request_uri' => $uri,
        'user_agent'  => $user_agent,
        'post_body'   => $post_body,
        'status_code' => 200,
    ]);

    $endpoint = $server_url . '/api/ingest';

    // Kirim secara non-blocking via curl jika tersedia (timeout 500ms agar aplikasi web tidak lambat)
    if (function_exists('curl_init')) {
        $ch = curl_init($endpoint);
        curl_setopt($ch, CURLOPT_POST, true);
        curl_setopt($ch, CURLOPT_POSTFIELDS, $payload);
        curl_setopt($ch, CURLOPT_HTTPHEADER, [
            'Content-Type: application/json',
            'X-NIDS-KEY: ' . $api_key,
        ]);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_TIMEOUT_MS, 500);
        curl_setopt($ch, CURLOPT_CONNECTTIMEOUT_MS, 300);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
        curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, false);
        @curl_exec($ch);
        @curl_close($ch);
    } elseif (function_exists('file_get_contents')) {
        $opts = [
            'http' => [
                'method'  => 'POST',
                'header'  => "Content-Type: application/json\r\n" .
                             "X-NIDS-KEY: " . $api_key . "\r\n",
                'content' => $payload,
                'timeout' => 0.5,
                'ignore_errors' => true,
            ]
        ];
        $context = stream_context_create($opts);
        @file_get_contents($endpoint, false, $context);
    }
})();
