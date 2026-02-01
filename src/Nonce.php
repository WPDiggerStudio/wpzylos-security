<?php

declare(strict_types=1);

namespace WPZylos\Framework\Security;

use WPZylos\Framework\Core\Contracts\ContextInterface;

/**
 * Nonce manager for CSRF protection.
 *
 * Wraps WordPress nonce functions with plugin-scoped actions.
 *
 * @package WPZylos\Framework\Security
 */
class Nonce
{
    /**
     * @var ContextInterface Plugin context
     */
    private ContextInterface $context;

    /**
     * Create a nonce manager.
     *
     * @param ContextInterface $context Plugin context
     */
    public function __construct(ContextInterface $context)
    {
        $this->context = $context;
    }

    /**
     * Create a nonce string.
     *
     * @param string $action Action name (will be prefixed)
     *
     * @return string Nonce token
     */
    public function create(string $action): string
    {
        return wp_create_nonce($this->context->hook($action));
    }

    /**
     * Verify a nonce.
     *
     * @param string $nonce Nonce to verify
     * @param string $action Action name (will be prefixed)
     *
     * @return bool|int False if invalid, 1 if <12 hours old, 2 if <24 hours
     */
    public function verify(string $nonce, string $action): bool|int
    {
        return wp_verify_nonce($nonce, $this->context->hook($action));
    }

    /**
     * Create nonce field HTML for forms.
     *
     * @param string $action Action name (will be prefixed)
     * @param string $name Field name (default: '_wpnonce')
     * @param bool $referrer Include referer field
     * @param bool $echo Echo the field (default: true)
     *
     * @return string HTML field
     */
    public function field(
        string $action,
        string $name = '_wpnonce',
        bool $referrer = true,
        bool $echo = true
    ): string {
        return wp_nonce_field(
            $this->context->hook($action),
            $name,
            $referrer,
            $echo
        );
    }

    /**
     * Create nonce URL.
     *
     * @param string $url URL to add nonce to
     * @param string $action Action name (will be prefixed)
     * @param string $name Query arg name (default: '_wpnonce')
     *
     * @return string URL with nonce
     */
    public function url(string $url, string $action, string $name = '_wpnonce'): string
    {
        return wp_nonce_url($url, $this->context->hook($action), $name);
    }

    /**
     * Check admin referer with nonce.
     *
     * @param string $action Action name (will be prefixed)
     * @param string $name Query arg name (default: '_wpnonce')
     *
     * @return bool|int False if failed, 1 or 2 if succeeded
     */
    public function checkAdminReferer(string $action, string $name = '_wpnonce'): bool|int
    {
        return check_admin_referer($this->context->hook($action), $name);
    }

    /**
     * Check AJAX referer with nonce.
     *
     * @param string $action Action name (will be prefixed)
     * @param string $name Query arg name (default: '_wpnonce')
     * @param bool $die Die on failure (default: true)
     *
     * @return bool|int
     */
    public function checkAjaxReferer(
        string $action,
        string $name = '_wpnonce',
        bool $die = true
    ): bool|int {
        return check_ajax_referer($this->context->hook($action), $name, $die);
    }
}
