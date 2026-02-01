<?php

declare(strict_types=1);

namespace WPZylos\Framework\Security\Tests\Unit;

use PHPUnit\Framework\TestCase;
use WPZylos\Framework\Security\Sanitizer;

/**
 * Tests for Sanitizer class.
 */
class SanitizerTest extends TestCase
{
    private Sanitizer $sanitizer;

    protected function setUp(): void
    {
        $this->sanitizer = new Sanitizer();
    }

    public function testTextRemovesHtmlTags(): void
    {
        $result = $this->sanitizer->text('<script>alert(1)</script>Hello');

        $this->assertStringNotContainsString('<script>', $result);
        $this->assertStringContainsString('Hello', $result);
    }

    public function testEmailSanitizesEmail(): void
    {
        $result = $this->sanitizer->email('test@example.com');

        $this->assertSame('test@example.com', $result);
    }

    public function testUrlSanitizesUrl(): void
    {
        $result = $this->sanitizer->url('https://example.com/path');

        $this->assertStringContainsString('example.com', $result);
    }

    public function testIntReturnsInteger(): void
    {
        $result = $this->sanitizer->int('42abc');

        $this->assertSame(42, $result);
    }

    public function testFloatReturnsFloat(): void
    {
        $result = $this->sanitizer->float('3.14abc');

        $this->assertSame(3.14, $result);
    }

    public function testBoolReturnsTrueForTruthyValues(): void
    {
        $this->assertTrue($this->sanitizer->bool('1'));
        $this->assertTrue($this->sanitizer->bool('true'));
        $this->assertTrue($this->sanitizer->bool('yes'));
    }

    public function testBoolReturnsFalseForFalsyValues(): void
    {
        $this->assertFalse($this->sanitizer->bool('0'));
        $this->assertFalse($this->sanitizer->bool('false'));
        $this->assertFalse($this->sanitizer->bool(''));
    }

    public function testKeySanitizesToLowercase(): void
    {
        $result = $this->sanitizer->key('My-Key_123');

        $this->assertSame('my-key_123', $result);
    }

    public function testSanitizeAppliesRulesToFields(): void
    {
        $data = [
            'name' => '<b>John</b>',
            'email' => 'john@example.com',
            'age' => '30',
        ];

        $result = $this->sanitizer->sanitizeMany($data, [
            'name' => 'text',
            'email' => 'email',
            'age' => 'int',
        ]);

        $this->assertStringNotContainsString('<b>', $result['name']);
        $this->assertSame('john@example.com', $result['email']);
        $this->assertSame(30, $result['age']);
    }
}
