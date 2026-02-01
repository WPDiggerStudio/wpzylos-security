<?php

declare(strict_types=1);

namespace WPZylos\Framework\Security\Middleware;

use WPZylos\Framework\Security\Gate;

/**
 * Authentication middleware.
 *
 * Checks user capabilities before allowing the request to proceed.
 *
 * @package WPZylos\Framework\Security
 */
final class AuthMiddleware
{
    /**
     * @var Gate Authorization gate
     */
    private Gate $gate;

    /**
     * @var string|string[] Required capability/capabilities
     */
    private string|array $capability;

    /**
     * @var string Check mode: 'any' or 'all'
     */
    private string $mode;

    /**
     * Create auth middleware.
     *
     * @param Gate $gate Authorization gate
     * @param string|string[] $capability Required capability or array of capabilities
     * @param string $mode 'any' (default) or 'all'
     */
    public function __construct(Gate $gate, string|array $capability, string $mode = 'any')
    {
        $this->gate = $gate;
        $this->capability = $capability;
        $this->mode = $mode;
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
        if (!$this->isAuthorized()) {
            wp_die(
                esc_html__('You are not authorized to access this resource.', 'default'),
                esc_html__('Forbidden', 'default'),
                ['response' => 403]
            );
        }

        return $next($request);
    }

    /**
     * Check if the user is authorized.
     *
     * @return bool
     */
    private function isAuthorized(): bool
    {
        $capabilities = (array) $this->capability;

        if ($this->mode === 'all') {
            return $this->gate->canAll($capabilities);
        }

        return $this->gate->canAny($capabilities);
    }

    /**
     * Create middleware that requires any of the given capabilities.
     *
     * @param Gate $gate Gate instance
     * @param string|string[] $capability Capability or capabilities
     *
     * @return self
     */
    public static function any(Gate $gate, string|array $capability): self
    {
        return new self($gate, $capability, 'any');
    }

    /**
     * Create middleware that requires all the given capabilities.
     *
     * @param Gate $gate Gate instance
     * @param string[] $capabilities Required capabilities
     *
     * @return self
     */
    public static function all(Gate $gate, array $capabilities): self
    {
        return new self($gate, $capabilities, 'all');
    }
}
