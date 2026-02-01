<?php

declare(strict_types=1);

namespace WPZylos\Framework\Security\Tests\Unit;

use PHPUnit\Framework\TestCase;
use WPZylos\Framework\Security\Gate;

/**
 * Tests for Gate class.
 */
class GateTest extends TestCase
{
    private Gate $gate;

    protected function setUp(): void
    {
        $GLOBALS['test_user_caps'] = [];
        $this->gate = new Gate();
    }

    public function testCanReturnsTrueWhenUserHasCapability(): void
    {
        $GLOBALS['test_user_caps']['manage_options'] = true;

        $this->assertTrue($this->gate->can('manage_options'));
    }

    public function testCanReturnsFalseWhenUserLacksCapability(): void
    {
        $GLOBALS['test_user_caps']['manage_options'] = false;

        $this->assertFalse($this->gate->can('manage_options'));
    }

    public function testCannotReturnsInverseOfCan(): void
    {
        $GLOBALS['test_user_caps']['edit_posts'] = true;

        $this->assertFalse($this->gate->cannot('edit_posts'));
    }

    public function testAuthorizeThrowsWhenUnauthorized(): void
    {
        $GLOBALS['test_user_caps']['delete_users'] = false;

        $this->expectException(\RuntimeException::class);

        $this->gate->authorize('delete_users');
    }

    public function testAuthorizePassesWhenAuthorized(): void
    {
        $GLOBALS['test_user_caps']['manage_options'] = true;

        // Should not throw
        $this->gate->authorize('manage_options');
        $this->assertTrue(true);
    }
}
