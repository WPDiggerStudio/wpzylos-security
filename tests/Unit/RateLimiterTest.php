<?php

declare(strict_types=1);

namespace WPZylos\Framework\Security\Tests\Unit;

use PHPUnit\Framework\TestCase;
use WPZylos\Framework\Core\Contracts\ContextInterface;
use WPZylos\Framework\Security\RateLimiter;

/**
 * Tests for RateLimiter class.
 */
class RateLimiterTest extends TestCase
{
    private ContextInterface $context;
    private RateLimiter $limiter;

    protected function setUp(): void
    {
        // Reset transients for each test
        $GLOBALS['test_transients'] = [];

        $this->context = $this->createMock(ContextInterface::class);
        $this->context->method('transientKey')
            ->willReturnCallback(fn($key) => 'test_' . $key);

        $this->limiter = new RateLimiter($this->context, 5, 60);
    }

    protected function tearDown(): void
    {
        $GLOBALS['test_transients'] = [];
    }

    public function testHitIncrementsCount(): void
    {
        $count1 = $this->limiter->hit('test_key');
        $count2 = $this->limiter->hit('test_key');

        $this->assertSame(1, $count1);
        $this->assertSame(2, $count2);
    }

    public function testTooManyAttemptsReturnsFalseUnderLimit(): void
    {
        $this->limiter->hit('test_key');
        $this->limiter->hit('test_key');

        $this->assertFalse($this->limiter->tooManyAttempts('test_key'));
    }

    public function testTooManyAttemptsReturnsTrueAtLimit(): void
    {
        for ($i = 0; $i < 5; $i++) {
            $this->limiter->hit('test_key');
        }

        $this->assertTrue($this->limiter->tooManyAttempts('test_key'));
    }

    public function testRemainingReturnsCorrectCount(): void
    {
        $this->limiter->hit('test_key');
        $this->limiter->hit('test_key');

        $this->assertSame(3, $this->limiter->remaining('test_key'));
    }

    public function testClearResetsLimit(): void
    {
        for ($i = 0; $i < 5; $i++) {
            $this->limiter->hit('test_key');
        }

        $this->assertTrue($this->limiter->tooManyAttempts('test_key'));
        $this->limiter->clear('test_key');
        $this->assertFalse($this->limiter->tooManyAttempts('test_key'));
    }

    public function testAttemptExecutesCallbackWhenAllowed(): void
    {
        $executed = false;

        $this->limiter->attempt('test_key', function () use (&$executed) {
            $executed = true;
            return 'success';
        });

        $this->assertTrue($executed);
    }

    public function testAttemptCallsOnLimitedWhenExceeded(): void
    {
        for ($i = 0; $i < 5; $i++) {
            $this->limiter->hit('test_key');
        }

        $limited = false;
        $this->limiter->attempt(
            'test_key',
            fn() => 'success',
            function ($wait) use (&$limited) {
                $limited = true;
                return 'limited';
            }
        );

        $this->assertTrue($limited);
    }
}
