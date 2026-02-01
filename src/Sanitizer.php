<?php

declare(strict_types=1);

namespace WPZylos\Framework\Security;

/**
 * Input sanitizer.
 *
 * Provides field-level sanitization using WordPress sanitization functions.
 *
 * @package WPZylos\Framework\Security
 */
class Sanitizer
{
    /**
     * Sanitize a text field (single line).
     *
     * @param string $value Input value
     * @return string Sanitized value
     */
    public function text(string $value): string
    {
        return sanitize_text_field($value);
    }

    /**
     * Sanitize a textarea (multiline text).
     *
     * @param string $value Input value
     * @return string Sanitized value
     */
    public function textarea(string $value): string
    {
        return sanitize_textarea_field($value);
    }

    /**
     * Sanitize HTML content (post content level).
     *
     * @param string $value Input value
     * @return string Sanitized value
     */
    public function html(string $value): string
    {
        return wp_kses_post($value);
    }

    /**
     * Sanitize an email address.
     *
     * @param string $value Input value
     * @return string Sanitized email or empty string
     */
    public function email(string $value): string
    {
        return sanitize_email($value);
    }

    /**
     * Sanitize a URL.
     *
     * @param string $value Input value
     * @param string[] $protocols Allowed protocols
     * @return string Sanitized URL
     */
    public function url(string $value, ?array $protocols = null): string
    {
        $allowedProtocols = $protocols ?? ['http', 'https'];
        return esc_url_raw($value, $allowedProtocols);
    }
    /**
     * Sanitize an integer.
     *
     * @param mixed $value Input value
     * @return int Sanitized integer
     */
    public function int(mixed $value): int
    {
        return (int) $value;
    }

    /**
     * Sanitize an absolute integer (always positive).
     *
     * @param mixed $value Input value
     * @return int Absolute integer
     */
    public function absint(mixed $value): int
    {
        return absint($value);
    }

    /**
     * Sanitize a float.
     *
     * @param mixed $value Input value
     * @return float Sanitized float
     */
    public function float(mixed $value): float
    {
        return (float) filter_var($value, FILTER_SANITIZE_NUMBER_FLOAT, FILTER_FLAG_ALLOW_FRACTION);
    }

    /**
     * Sanitize a boolean.
     *
     * @param mixed $value Input value
     * @return bool
     */
    public function bool(mixed $value): bool
    {
        return filter_var($value, FILTER_VALIDATE_BOOLEAN);
    }

    /**
     * Sanitize a slug.
     *
     * @param string $value Input value
     * @return string Sanitized slug
     */
    public function slug(string $value): string
    {
        return sanitize_title($value);
    }

    /**
     * Sanitize a key (lowercase alphanumeric + dashes + underscores).
     *
     * @param string $value Input value
     * @return string Sanitized key
     */
    public function key(string $value): string
    {
        return sanitize_key($value);
    }

    /**
     * Sanitize a file name.
     *
     * @param string $value Input value
     * @return string Sanitized filename
     */
    public function filename(string $value): string
    {
        return sanitize_file_name($value);
    }

    /**
     * Sanitize a CSS class name.
     *
     * @param string $value Input value
     * @return string Sanitized class name
     */
    public function htmlClass(string $value): string
    {
        return sanitize_html_class($value);
    }

    /**
     * Sanitize an array by applying a sanitizer to each element.
     *
     * @param array $values Input array
     * @param string $type Sanitizer type to apply
     * @return array Sanitized array
     */
    public function array(array $values, string $type = 'text'): array
    {
        return array_map(fn($v) => $this->sanitize($v, $type), $values);
    }

    /**
     * Sanitize a value using a specified type.
     *
     * @param mixed $value Input value
     * @param string $type Sanitizer type
     * @return mixed Sanitized value
     */
    public function sanitize(mixed $value, string $type): mixed
    {
        if ($value === null) {
            return null;
        }

        return match ($type) {
            'text' => $this->text((string) $value),
            'textarea' => $this->textarea((string) $value),
            'html' => $this->html((string) $value),
            'email' => $this->email((string) $value),
            'url' => $this->url((string) $value),
            'int', 'integer' => $this->int($value),
            'absint' => $this->absint($value),
            'float' => $this->float($value),
            'bool', 'boolean' => $this->bool($value),
            'slug' => $this->slug((string) $value),
            'key' => $this->key((string) $value),
            'filename' => $this->filename((string) $value),
            'htmlClass' => $this->htmlClass((string) $value),
            default => $this->text((string) $value),
        };
    }

    /**
     * Sanitize multiple values using a type map.
     *
     * @param array<string, mixed> $values Input values
     * @param array<string, string> $typeMap Field => type mapping
     * @return array<string, mixed> Sanitized values
     */
    public function sanitizeMany(array $values, array $typeMap): array
    {
        $sanitized = [];

        foreach ($typeMap as $field => $type) {
            if (array_key_exists($field, $values)) {
                $sanitized[$field] = $this->sanitize($values[$field], $type);
            }
        }

        return $sanitized;
    }
}
