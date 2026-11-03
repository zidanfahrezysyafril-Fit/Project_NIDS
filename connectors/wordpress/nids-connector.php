<?php
/**
 * Plugin Name: NIDS Monitor Connector
 * Plugin URI: https://github.com/kelompok10/nids-monitor
 * Description: Konektor pemantauan keamanan real-time untuk platform NIDS Monitor (AI for Security - Kelompok 10). Menganalisis percobaan DDoS, SQL Injection, dan XSS secara non-blocking.
 * Version: 1.0.0
 * Author: Kelompok 10 - AI for Security
 * License: GPLv2 or later
 * Text Domain: nids-monitor
 */

if (!defined('ABSPATH')) {
    exit;
}

class NIDS_Connector {

    private static $instance = null;
    private $option_key = 'nids_monitor_settings';

    public static function get_instance() {
        if (null === self::$instance) {
            self::$instance = new self();
        }
        return self::$instance;
    }

    public function __construct() {
        // Admin menu & settings
        add_action('admin_menu', array($this, 'add_admin_menu'));
        add_action('admin_init', array($this, 'register_settings'));

        // Traffic capture hook (init hook to catch all requests before page render)
        add_action('init', array($this, 'capture_traffic'), 1);
    }

    /**
     * Daftarkan menu Pengaturan -> NIDS Monitor
     */
    public function add_admin_menu() {
        add_options_page(
            'NIDS Monitor Pengaturan',
            '🛡️ NIDS Monitor',
            'manage_options',
            'nids-monitor',
            array($this, 'render_settings_page')
        );
    }

    public function register_settings() {
        register_setting('nids_settings_group', $this->option_key);
    }

    /**
     * Dapatkan IP asli pengunjung (support Cloudflare / Proxy)
     */
    private function get_client_ip() {
        if (!empty($_SERVER['HTTP_CF_CONNECTING_IP'])) {
            return sanitize_text_field($_SERVER['HTTP_CF_CONNECTING_IP']);
        }
        if (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
            $parts = explode(',', $_SERVER['HTTP_X_FORWARDED_FOR']);
            return sanitize_text_field(trim($parts[0]));
        }
        return !empty($_SERVER['REMOTE_ADDR']) ? sanitize_text_field($_SERVER['REMOTE_ADDR']) : '127.0.0.1';
    }

    /**
     * Tangkap dan kirim lalu lintas ke platform NIDS secara non-blocking
     */
    public function capture_traffic() {
        // Jangan pantau jika di WP CLI atau request internal cron
        if (defined('DOING_CRON') && DOING_CRON) return;
        if (defined('WP_CLI') && WP_CLI) return;

        // Skip static file assets jika ada
        $uri = isset($_SERVER['REQUEST_URI']) ? $_SERVER['REQUEST_URI'] : '/';
        if (preg_match('/\.(css|js|jpg|jpeg|png|gif|ico|svg|woff|woff2|ttf|eot)$/i', $uri)) {
            return;
        }

        $opts = get_option($this->option_key, array());
        $api_key    = !empty($opts['api_key']) ? trim($opts['api_key']) : '';
        $server_url = !empty($opts['server_url']) ? rtrim(trim($opts['server_url']), '/') : '';

        if (empty($api_key) || empty($server_url)) {
            return;
        }

        $client_ip = $this->get_client_ip();
        $method    = !empty($_SERVER['REQUEST_METHOD']) ? strtoupper(sanitize_text_field($_SERVER['REQUEST_METHOD'])) : 'GET';
        $user_agent = !empty($_SERVER['HTTP_USER_AGENT']) ? sanitize_text_field($_SERVER['HTTP_USER_AGENT']) : '';

        // Tangkap cuplikan post body jika metode POST (maksimal 500 karakter untuk keamanan privasi)
        $post_body = '';
        if ($method === 'POST' && !empty($_POST)) {
            $post_body = substr(http_build_query($_POST), 0, 500);
        }

        $payload = array(
            'api_key'     => $api_key,
            'ip_address'  => $client_ip,
            'method'      => $method,
            'request_uri' => $uri,
            'user_agent'  => $user_agent,
            'post_body'   => $post_body,
            'status_code' => 200,
        );

        $endpoint = $server_url . '/api/ingest';

        // Kirim non-blocking agar tidak menambah latency website sama sekali
        wp_remote_post($endpoint, array(
            'method'      => 'POST',
            'blocking'    => false, // NON-BLOCKING!
            'timeout'     => 1,
            'redirection' => 0,
            'headers'     => array(
                'Content-Type' => 'application/json; charset=utf-8',
                'X-NIDS-KEY'   => $api_key,
            ),
            'body'        => wp_json_encode($payload),
            'sslverify'   => false,
        ));
    }

    /**
     * Render Halaman Pengaturan
     */
    public function render_settings_page() {
        $opts = get_option($this->option_key, array());
        $api_key    = !empty($opts['api_key']) ? $opts['api_key'] : '';
        $server_url = !empty($opts['server_url']) ? $opts['server_url'] : 'http://127.0.0.1:5000';

        $test_result = '';
        if (isset($_POST['nids_test_conn']) && check_admin_referer('nids_test_action')) {
            $test_endpoint = rtrim($server_url, '/') . '/api/ingest';
            $test_resp = wp_remote_post($test_endpoint, array(
                'headers' => array(
                    'Content-Type' => 'application/json',
                    'X-NIDS-KEY'   => $api_key,
                ),
                'body' => wp_json_encode(array(
                    'api_key'     => $api_key,
                    'ip_address'  => $this->get_client_ip(),
                    'method'      => 'GET',
                    'request_uri' => '/ping-nids-test',
                    'user_agent'  => 'WordPress-NIDS-Plugin-Test',
                )),
                'timeout' => 5,
                'sslverify' => false,
            ));

            if (is_wp_error($test_resp)) {
                $test_result = '<div class="notice notice-error"><p>❌ Gagal terhubung ke platform NIDS: ' . esc_html($test_resp->get_error_message()) . '</p></div>';
            } else {
                $code = wp_remote_retrieve_response_code($test_resp);
                $body = wp_remote_retrieve_body($test_resp);
                if ($code === 200) {
                    $test_result = '<div class="notice notice-success"><p>✅ <strong>Berhasil terhubung!</strong> Platform NIDS menerima ping konektor.</p></div>';
                } else {
                    $test_result = '<div class="notice notice-warning"><p>⚠️ Respon server (' . $code . '): ' . esc_html($body) . '</p></div>';
                }
            }
        }
        ?>
        <div class="wrap">
            <h1>🛡️ Pengaturan NIDS Monitor Connector</h1>
            <p>Sambungkan website WordPress Anda ke platform deteksi serangan siber NIDS Monitor (Kelompok 10 - AI for Security).</p>

            <?php echo $test_result; ?>

            <form method="post" action="options.php" style="max-width:650px;background:#fff;padding:20px;border-radius:8px;border:1px solid #ccd0d4;margin-top:15px;">
                <?php
                settings_fields('nids_settings_group');
                do_settings_sections('nids_settings_group');
                ?>
                <table class="form-table">
                    <tr>
                        <th scope="row"><label for="nids_server_url">URL Platform NIDS</label></th>
                        <td>
                            <input name="<?php echo $this->option_key; ?>[server_url]" type="url" id="nids_server_url" value="<?php echo esc_attr($server_url); ?>" class="regular-text" placeholder="http://127.0.0.1:5000" required />
                            <p class="description">Alamat server NIDS Monitor Anda (contoh: <code>http://127.0.0.1:5000</code> atau <code>https://nids.domain.com</code>).</p>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row"><label for="nids_api_key">API Key Website</label></th>
                        <td>
                            <input name="<?php echo $this->option_key; ?>[api_key]" type="text" id="nids_api_key" value="<?php echo esc_attr($api_key); ?>" class="large-text" placeholder="nids_live_..." required />
                            <p class="description">Salin API Key unik dari halaman Setup Website di platform NIDS.</p>
                        </td>
                    </tr>
                </table>

                <?php submit_button('💾 Simpan Pengaturan'); ?>
            </form>

            <?php if (!empty($api_key) && !empty($server_url)): ?>
            <div style="max-width:650px;background:#fff;padding:20px;border-radius:8px;border:1px solid #ccd0d4;margin-top:20px;">
                <h3>🔍 Tes Koneksi ke NIDS</h3>
                <p>Kirim sinyal uji coba untuk memastikan server NIDS Anda dapat dihubungi dari WordPress ini.</p>
                <form method="post">
                    <?php wp_nonce_field('nids_test_action'); ?>
                    <button type="submit" name="nids_test_conn" class="button button-secondary">
                        📡 Tes Sinyal Sekarang
                    </button>
                </form>
            </div>
            <?php endif; ?>
        </div>
        <?php
    }
}

// Inisialisasi plugin
add_action('plugins_loaded', array('NIDS_Connector', 'get_instance'));
