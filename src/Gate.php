<?php

declare(strict_types=1);

namespace WPZylos\Framework\Security;

/**
 * Authorization gate for capability checks.
 *
 * Provides a fluent API for checking user capabilities.
 *
 * @package WPZylos\Framework\Security
 */
class Gate
{
    /**
     * Check if current user has a capability.
     *
     * @param string $capability Capability name
     * @param mixed ...$args Optional arguments for capability check
     * @return bool
     */
    public function can(string $capability, mixed ...$args): bool
    {
        return current_user_can($capability, ...$args);
    }

    /**
     * Check if current user lacks a capability.
     *
     * @param string $capability Capability name
     * @param mixed ...$args Optional arguments
     * @return bool
     */
    public function cannot(string $capability, mixed ...$args): bool
    {
        return !$this->can($capability, ...$args);
    }

    /**
     * Check if a specific user has a capability.
     *
     * @param int $userId User ID
     * @param string $capability Capability name
     * @param mixed ...$args Optional arguments
     * @return bool
     */
    public function userCan(int $userId, string $capability, mixed ...$args): bool
    {
        return user_can($userId, $capability, ...$args);
    }

    /**
     * Check if current user is an administrator.
     *
     * @return bool
     */
    public function isAdmin(): bool
    {
        return $this->can('manage_options');
    }

    /**
     * Check if current user can manage the plugin.
     *
     * Default plugin management requires 'manage_options'.
     *
     * @param string $capability Override capability (default: 'manage_options')
     * @return bool
     */
    public function canManagePlugin(string $capability = 'manage_options'): bool
    {
        return $this->can($capability);
    }

    /**
     * Check if current user can edit posts.
     *
     * @return bool
     */
    public function canEdit(): bool
    {
        return $this->can('edit_posts');
    }

    /**
     * Check if current user can publish.
     *
     * @return bool
     */
    public function canPublish(): bool
    {
        return $this->can('publish_posts');
    }

    /**
     * Check if current user can delete.
     *
     * @return bool
     */
    public function canDelete(): bool
    {
        return $this->can('delete_posts');
    }

    /**
     * Abort if user lacks capability.
     *
     * Uses wp_die() to terminate with an authorization error if the current
     * user does not have the specified capability.
     *
     * @param string $capability Required capability
     * @param string $message Error message
     * @param int $statusCode HTTP status code
     */
    public function authorize(
        string $capability,
        string $message = 'You are not authorized to perform this action.',
        int $statusCode = 403
    ): void {
        if ($this->cannot($capability)) {
            wp_die(
                esc_html($message),
                esc_html__('Forbidden', 'default'),
                ['response' => $statusCode]
            );
        }
    }

    /**
     * Check if current user is logged in.
     *
     * @return bool
     */
    public function isLoggedIn(): bool
    {
        return is_user_logged_in();
    }

    /**
     * Check if current user is a guest (not logged in).
     *
     * @return bool
     */
    public function isGuest(): bool
    {
        return !$this->isLoggedIn();
    }

    /**
     * Get current user ID.
     *
     * @return int User ID or 0 if not logged in
     */
    public function userId(): int
    {
        return get_current_user_id();
    }

    /**
     * Check if current user has any of the given capabilities.
     *
     * @param string[] $capabilities List of capabilities
     * @param mixed ...$args Optional arguments
     * @return bool
     */
    public function canAny(array $capabilities, mixed ...$args): bool
    {
        foreach ($capabilities as $capability) {
            if ($this->can($capability, ...$args)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Check if current user has all of the given capabilities.
     *
     * @param string[] $capabilities List of capabilities
     * @param mixed ...$args Optional arguments
     * @return bool
     */
    public function canAll(array $capabilities, mixed ...$args): bool
    {
        foreach ($capabilities as $capability) {
            if ($this->cannot($capability, ...$args)) {
                return false;
            }
        }
        return true;
    }
}
