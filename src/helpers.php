<?php

/**
 * Global escape helper functions for templates.
 *
 * These functions provide short, convenient aliases for WordPress
 * escaping functions. All templates should use these helpers.
 *
 * @package WPZylos\Framework\Security
 */

declare(strict_types=1);

if (!function_exists('wpzylos_e')) {
    /**
     * Escape for HTML output.
     *
     * @param string $text Text to escape
     *
     * @return string Escaped text
     */
    function wpzylos_e(string $text): string
    {
        return esc_html($text);
    }
}

if (!function_exists('wpzylos_ea')) {
    /**
     * Escape for HTML attribute output.
     *
     * @param string $text Text to escape
     *
     * @return string Escaped text
     */
    function wpzylos_ea(string $text): string
    {
        return esc_attr($text);
    }
}

if (!function_exists('wpzylos_eu')) {
    /**
     * Escape URL for output.
     *
     * @param string $url URL to escape
     *
     * @return string Escaped URL
     */
    function wpzylos_eu(string $url): string
    {
        return esc_url($url);
    }
}

if (!function_exists('wpzylos_ej')) {
    /**
     * Escape for JavaScript.
     *
     * @param string $text Text to escape
     *
     * @return string Escaped text
     */
    function wpzylos_ej(string $text): string
    {
        return esc_js($text);
    }
}

if (!function_exists('wpzylos_kses')) {
    /**
     * Filter HTML to allowed tags.
     *
     * @param string $html HTML to filter
     * @param string $context Context: 'post', 'data', or 'strip'
     *
     * @return string Filtered HTML
     */
    function wpzylos_kses(string $html, string $context = 'post'): string
    {
        return match ($context) {
            'data' => wp_kses_data($html),
            'strip' => wp_kses($html, []),
            default => wp_kses_post($html),
        };
    }
}

if (!function_exists('wpzylos_e_json')) {
    /**
     * Encode and escape JSON for safe HTML embedding.
     *
     * @param mixed $data Data to encode
     * @param int   $flags JSON encoding flags
     *
     * @return string JSON string safe for HTML
     *
     * @throws \JsonException
     */
    function wpzylos_e_json(
        mixed $data,
        int $flags = JSON_HEX_TAG | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_HEX_AMP
    ): string {
        return (string) json_encode($data, JSON_THROW_ON_ERROR | $flags);
    }
}
