<?php

declare(strict_types=1);

namespace WPZylos\Framework\Security;

use WPZylos\Framework\Core\Contracts\ContextInterface;

/**
 * Rate limiter using WordPress transients.
 *
 * Provides request throttling for AJAX, REST, and form submissions.
 * Uses transients for persistence, compatible with object cache.
 *
 * @package WPZylos\Framework\Security
 */
class RateLimiter
{
    /**
     * @var ContextInterface Plugin context
     */
    private ContextInterface $context;

    /**
     * @var int Maximum attempts allowed
     */
    private int $maxAttempts;

    /**
     * @var int Decay period in seconds
     */
    private int $decaySeconds;

    /**
     * Create rate limiter.
     *
     * @param ContextInterface $context Plugin context
     * @param int $maxAttempts Maximum attempts (default: 60)
     * @param int $decaySeconds Decay period (default: 60 seconds)
     */
    public function __construct(
        ContextInterface $context,
        int $maxAttempts = 60,
        int $decaySeconds = 60
    ) {
        $this->context = $context;
        $this->maxAttempts = $maxAttempts;
        $this->decaySeconds = $decaySeconds;
    }

    /**
     * Record a hit for the given key.
     *
     * @param string $key Rate limit key (e.g., user ID, IP address)
     * @return int Current hit count
     */
    public function hit(string $key): int
    {
        $cacheKey = $this->getCacheKey($key);
        $data = $this->getData($cacheKey);

        $data['hits']++;
        $data['expires'] = time() + $this->decaySeconds;

        set_transient($cacheKey, $data, $this->decaySeconds);

        return $data['hits'];
    }

    /**
     * Check if too many attempts have been made.
     *
     * @param string $key Rate limit key
     * @return bool True if limit exceeded
     */
    public function tooManyAttempts(string $key): bool
    {
        $data = $this->getData($this->getCacheKey($key));
        return $data['hits'] >= $this->maxAttempts;
    }

    /**
     * Get remaining attempts.
     *
     * @param string $key Rate limit key
     * @return int Remaining attempts
     */
    public function remaining(string $key): int
    {
        $data = $this->getData($this->getCacheKey($key));
        return max(0, $this->maxAttempts - $data['hits']);
    }

    /**
     * Get seconds until rate limit resets.
     *
     * @param string $key Rate limit key
     * @return int Seconds until reset (0 if not limited)
     */
    public function availableIn(string $key): int
    {
        $data = $this->getData($this->getCacheKey($key));

        if ($data['hits'] < $this->maxAttempts) {
            return 0;
        }

        return max(0, $data['expires'] - time());
    }

    /**
     * Clear rate limit for a key.
     *
     * @param string $key Rate limit key
     * @return bool True if cleared
     */
    public function clear(string $key): bool
    {
        return delete_transient($this->getCacheKey($key));
    }

    /**
     * Attempt an action with rate limiting.
     *
     * @param string $key Rate limit key
     * @param callable $callback Callback to execute if allowed
     * @param callable|null $onLimited Callback when limited (receives wait seconds)
     * @return mixed Callback result or onLimited result
     */
    public function attempt(string $key, callable $callback, ?callable $onLimited = null): mixed
    {
        if ($this->tooManyAttempts($key)) {
            if ($onLimited !== null) {
                return $onLimited($this->availableIn($key));
            }
            return null;
        }

        $this->hit($key);
        return $callback();
    }

    /**
     * Create rate limiter for current user.
     *
     * @param string $action Action identifier
     * @return string Rate limit key
     */
    public function forUser(string $action): string
    {
        $userId = get_current_user_id();
        return $userId > 0 ? "user_{$userId}_{$action}" : $this->forIp($action);
    }

    /**
     * Create rate limiter for current IP.
     *
     * @param string $action Action identifier
     * @return string Rate limit key
     */
    public function forIp(string $action): string
    {
        $ip = $this->getClientIp();
        return "ip_" . md5($ip) . "_{$action}";
    }

    /**
     * Get client IP address.
     *
     * @return string IP address
     */
    private function getClientIp(): string
    {
        $headers = [
            'HTTP_CF_CONNECTING_IP', // Cloudflare
            'HTTP_X_FORWARDED_FOR',
            'HTTP_X_REAL_IP',
            'REMOTE_ADDR',
        ];

        foreach ($headers as $header) {
            if (!empty($_SERVER[$header])) {
                $ip = $_SERVER[$header];
                // Handle comma-separated IPs (X-Forwarded-For)
                if (str_contains($ip, ',')) {
                    $ip = trim(explode(',', $ip)[0]);
                }
                if (filter_var($ip, FILTER_VALIDATE_IP)) {
                    return $ip;
                }
            }
        }

        return '127.0.0.1';
    }

    /**
     * Get cache key for rate limiting.
     *
     * @param string $key User-provided key
     * @return string Prefixed cache key
     */
    private function getCacheKey(string $key): string
    {
        return $this->context->transientKey('rate_' . md5($key));
    }

    /**
     * Get rate limit data.
     *
     * @param string $cacheKey Cache key
     * @return array{hits: int, expires: int} Rate limit data
     */
    private function getData(string $cacheKey): array
    {
        $data = get_transient($cacheKey);

        if (!is_array($data)) {
            return ['hits' => 0, 'expires' => 0];
        }

        // Check if expired
        if (isset($data['expires']) && $data['expires'] < time()) {
            delete_transient($cacheKey);
            return ['hits' => 0, 'expires' => 0];
        }

        return $data;
    }
}
