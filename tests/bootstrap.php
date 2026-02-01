<?php

/**
 * PHPUnit bootstrap with WordPress security function mocks.
 *
 * @phpcs:disable PSR1.Files.SideEffects
 */

declare(strict_types=1);

require_once dirname(__DIR__) . '/vendor/autoload.php';

// Mock WP_Error class
if (!class_exists('WP_Error')) {
    class WP_Error
    {
        private string $code;
        private string $message;
        private array $data;

        public function __construct(string $code = '', string $message = '', mixed $data = '')
        {
            $this->code = $code;
            $this->message = $message;
            $this->data = is_array($data) ? $data : [];
        }

        public function get_error_code(): string
        {
            return $this->code;
        }

        public function get_error_message(): string
        {
            return $this->message;
        }

        public function get_error_data(): array
        {
            return $this->data;
        }
    }
}

// Mock WordPress security functions

if (!function_exists('wp_create_nonce')) {
    function wp_create_nonce(string $action): string
    {
        return md5('nonce_' . $action . '_salt');
    }
}

if (!function_exists('wp_verify_nonce')) {
    function wp_verify_nonce(string $nonce, string $action): bool
    {
        return $nonce === md5('nonce_' . $action . '_salt');
    }
}

if (!function_exists('current_user_can')) {
    function current_user_can(string $capability, ...$args): bool
    {
        return $GLOBALS['test_user_caps'][$capability] ?? false;
    }
}

if (!function_exists('wp_die')) {
    function wp_die(string $message = '', string $title = '', array $args = []): void
    {
        throw new \RuntimeException($message);
    }
}

if (!function_exists('sanitize_text_field')) {
    function sanitize_text_field(string $str): string
    {
        return trim(strip_tags($str));
    }
}

if (!function_exists('sanitize_email')) {
    function sanitize_email(string $email): string
    {
        return filter_var($email, FILTER_SANITIZE_EMAIL) ?: '';
    }
}

if (!function_exists('esc_url_raw')) {
    function esc_url_raw(string $url): string
    {
        return filter_var($url, FILTER_SANITIZE_URL) ?: '';
    }
}

if (!function_exists('sanitize_key')) {
    function sanitize_key(string $key): string
    {
        return preg_replace('/[^a-z0-9_\-]/', '', strtolower($key));
    }
}

if (!function_exists('wp_kses_post')) {
    function wp_kses_post(string $html): string
    {
        return strip_tags($html, '<p><br><strong><em><a><ul><ol><li>');
    }
}

// Escaping functions
if (!function_exists('esc_html')) {
    function esc_html(string $text): string
    {
        return htmlspecialchars($text, ENT_QUOTES, 'UTF-8');
    }
}

if (!function_exists('esc_html__')) {
    function esc_html__(string $text, string $domain = 'default'): string
    {
        return htmlspecialchars($text, ENT_QUOTES, 'UTF-8');
    }
}

if (!function_exists('__')) {
    function __(string $text, string $domain = 'default'): string
    {
        return $text;
    }
}

if (!function_exists('size_format')) {
    function size_format(int $bytes, int $decimals = 0): string
    {
        $units = ['B', 'KB', 'MB', 'GB', 'TB'];
        $factor = floor((strlen((string) $bytes) - 1) / 3);
        return sprintf("%.{$decimals}f %s", $bytes / pow(1024, $factor), $units[$factor]);
    }
}

// Transient functions (in-memory mock)
$GLOBALS['test_transients'] = [];

if (!function_exists('get_transient')) {
    function get_transient(string $transient): mixed
    {
        $data = $GLOBALS['test_transients'][$transient] ?? null;
        if ($data === null) {
            return false;
        }
        if ($data['expiration'] !== 0 && $data['expiration'] < time()) {
            unset($GLOBALS['test_transients'][$transient]);
            return false;
        }
        return $data['value'];
    }
}

if (!function_exists('set_transient')) {
    function set_transient(string $transient, mixed $value, int $expiration = 0): bool
    {
        $GLOBALS['test_transients'][$transient] = [
            'value' => $value,
            'expiration' => $expiration > 0 ? time() + $expiration : 0,
        ];
        return true;
    }
}

if (!function_exists('delete_transient')) {
    function delete_transient(string $transient): bool
    {
        unset($GLOBALS['test_transients'][$transient]);
        return true;
    }
}

// File upload mocks
if (!function_exists('wp_check_filetype_and_ext')) {
    function wp_check_filetype_and_ext(string $file, string $filename, ?array $mimes = null): array
    {
        $ext = pathinfo($filename, PATHINFO_EXTENSION);
        $type = match ($ext) {
            'jpg', 'jpeg' => 'image/jpeg',
            'png' => 'image/png',
            'gif' => 'image/gif',
            'pdf' => 'application/pdf',
            default => '',
        };
        return [
            'ext' => $type ? $ext : false,
            'type' => $type ?: false,
            'proper_filename' => false,
        ];
    }
}

if (!function_exists('wp_handle_upload')) {
    function wp_handle_upload(array $file, array $overrides = []): array
    {
        return [
            'file' => '/tmp/' . $file['name'],
            'url' => 'http://example.com/wp-content/uploads/' . $file['name'],
            'type' => $file['type'],
        ];
    }
}

// Initialize test globals
$GLOBALS['test_user_caps'] = [];
$GLOBALS['test_transients'] = [];
