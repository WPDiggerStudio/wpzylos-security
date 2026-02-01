<?php

declare(strict_types=1);

namespace WPZylos\Framework\Security;

use WPZylos\Framework\Core\Contracts\ApplicationInterface;
use WPZylos\Framework\Core\ServiceProvider;

/**
 * Security service provider.
 *
 * Registers Nonce, Gate, and Sanitizer with the container.
 *
 * @package WPZylos\Framework\Security
 */
class SecurityServiceProvider extends ServiceProvider
{
    /**
     * {@inheritDoc}
     */
    public function register(ApplicationInterface $app): void
    {
        parent::register($app);

        $this->singleton(Nonce::class, fn() => new Nonce($app->context()));
        $this->singleton('nonce', fn() => $this->make(Nonce::class));

        $this->singleton(Gate::class, fn() => new Gate());
        $this->singleton('gate', fn() => $this->make(Gate::class));

        $this->singleton(Sanitizer::class, fn() => new Sanitizer());
        $this->singleton('sanitizer', fn() => $this->make(Sanitizer::class));
    }
}
