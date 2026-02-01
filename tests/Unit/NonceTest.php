<?php

declare(strict_types=1);

namespace WPZylos\Framework\Security\Tests\Unit;

use PHPUnit\Framework\TestCase;
use WPZylos\Framework\Core\Contracts\ContextInterface;
use WPZylos\Framework\Security\Nonce;

/**
 * Tests for Nonce class.
 */
class NonceTest extends TestCase
{
    private ContextInterface $context;
    private Nonce $nonce;

    protected function setUp(): void
    {
        $this->context = $this->createMock(ContextInterface::class);
        $this->context->method('hook')
            ->willReturnCallback(fn($name) => 'test_' . $name);

        $this->nonce = new Nonce($this->context);
    }

    public function testCreateReturnsNonceString(): void
    {
        $token = $this->nonce->create('save_settings');

        $this->assertNotEmpty($token);
        $this->assertIsString($token);
    }

    public function testVerifyReturnsTrueForValidNonce(): void
    {
        $token = $this->nonce->create('save_settings');

        $this->assertTrue($this->nonce->verify($token, 'save_settings'));
    }

    public function testVerifyReturnsFalseForInvalidNonce(): void
    {
        $this->assertFalse($this->nonce->verify('invalid', 'save_settings'));
    }

    public function testVerifyReturnsFalseForWrongAction(): void
    {
        $token = $this->nonce->create('save_settings');

        $this->assertFalse($this->nonce->verify($token, 'delete_settings'));
    }
}
