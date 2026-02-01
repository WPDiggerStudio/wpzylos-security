<?php

declare(strict_types=1);

namespace WPZylos\Framework\Security\Middleware;

use WPZylos\Framework\Security\Nonce;

/**
 * Nonce verification middleware.
 *
 * Verifies CSRF nonce before allowing the request to proceed.
 *
 * @package WPZylos\Framework\Security
 */
final class NonceMiddleware
{
    /**
     * @var Nonce Nonce manager
     */
    private Nonce $nonce;

    /**
     * @var string Nonce action name
     */
    private string $action;

    /**
     * @var string Field name containing nonce
     */
    private string $field;

    /**
     * Create nonce middleware.
     *
     * @param Nonce $nonce Nonce manager
     * @param string $action Nonce action name (will be prefixed)
     * @param string $field Field name (default: '_wpnonce')
     */
    public function __construct(Nonce $nonce, string $action, string $field = '_wpnonce')
    {
        $this->nonce = $nonce;
        $this->action = $action;
        $this->field = $field;
    }

    /**
     * Handle the request.
     *
     * @param mixed $request Request object
     * @param callable $next Next middleware
     *
     * @return mixed
     */
    public function handle(mixed $request, callable $next): mixed
    {
        $nonceValue = $this->extractNonce($request);

        if (!$nonceValue || !$this->nonce->verify($nonceValue, $this->action)) {
            wp_die(
                esc_html__('Security check failed. Please refresh and try again.', 'default'),
                esc_html__('Security Error', 'default'),
                ['response' => 403]
            );
        }

        return $next($request);
    }

    /**
     * Extract nonce from request.
     *
     * @param mixed $request Request object
     *
     * @return string|null
     */
    private function extractNonce(mixed $request): ?string
    {
        // Try POST first
        if (isset($_POST[$this->field])) {
            return sanitize_text_field(wp_unslash($_POST[$this->field]));
        }

        // Then GET
        if (isset($_GET[$this->field])) {
            return sanitize_text_field(wp_unslash($_GET[$this->field]));
        }

        // Check if a request object has the method
        if (is_object($request) && method_exists($request, 'input')) {
            return $request->input($this->field);
        }

        return null;
    }

    /**
     * Create middleware for a specific action.
     *
     * @param Nonce $nonce Nonce manager
     * @param string $action Nonce action
     * @param string $field Field name
     *
     * @return self
     */
    public static function for(Nonce $nonce, string $action, string $field = '_wpnonce'): self
    {
        return new self($nonce, $action, $field);
    }
}
