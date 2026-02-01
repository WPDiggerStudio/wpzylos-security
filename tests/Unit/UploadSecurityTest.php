<?php

declare(strict_types=1);

namespace WPZylos\Framework\Security\Tests\Unit;

use PHPUnit\Framework\TestCase;
use WPZylos\Framework\Core\Contracts\ContextInterface;
use WPZylos\Framework\Security\Gate;
use WPZylos\Framework\Security\Nonce;
use WPZylos\Framework\Security\UploadSecurity;

/**
 * Tests for UploadSecurity class.
 */
class UploadSecurityTest extends TestCase
{
    private ContextInterface $context;
    private Nonce $nonce;
    private Gate $gate;
    private UploadSecurity $uploader;

    protected function setUp(): void
    {
        $GLOBALS['test_user_caps'] = ['upload_files' => true];
        $_POST['_wpnonce'] = 'valid_nonce';

        $this->context = $this->createMock(ContextInterface::class);
        $this->context->method('textDomain')->willReturn('test-domain');

        $this->nonce = $this->createMock(Nonce::class);
        // Default: nonce verification passes
        $this->nonce->method('verify')->willReturn(true);

        $this->gate = new Gate();

        $this->uploader = new UploadSecurity(
            $this->context,
            $this->nonce,
            $this->gate,
            ['jpg|jpeg' => 'image/jpeg', 'png' => 'image/png']
        );
    }

    protected function tearDown(): void
    {
        unset($_POST['_wpnonce']);
    }

    public function testHandleDeniesWithoutCapability(): void
    {
        $GLOBALS['test_user_caps'] = ['upload_files' => false];
        $gate = new Gate();

        $nonce = $this->createMock(Nonce::class);
        $nonce->method('verify')->willReturn(true);

        $uploader = new UploadSecurity(
            $this->context,
            $nonce,
            $gate
        );

        $file = [
            'name' => 'test.jpg',
            'type' => 'image/jpeg',
            'tmp_name' => '/tmp/test.jpg',
            'error' => UPLOAD_ERR_OK,
            'size' => 1024,
        ];

        $result = $uploader->handle($file, 'upload_action');

        $this->assertInstanceOf(\WP_Error::class, $result);
        $this->assertSame('permission_denied', $result->get_error_code());
    }

    public function testHandleRejectsUploadErrors(): void
    {
        $file = [
            'name' => 'test.jpg',
            'type' => 'image/jpeg',
            'tmp_name' => '/tmp/test.jpg',
            'error' => UPLOAD_ERR_NO_FILE,
            'size' => 0,
        ];

        $result = $this->uploader->handle($file, 'upload_action');

        $this->assertInstanceOf(\WP_Error::class, $result);
        $this->assertSame('upload_error', $result->get_error_code());
    }

    public function testHandleRejectsOversizedFiles(): void
    {
        $nonce = $this->createMock(Nonce::class);
        $nonce->method('verify')->willReturn(true);

        $uploader = new UploadSecurity(
            $this->context,
            $nonce,
            $this->gate,
            ['jpg|jpeg' => 'image/jpeg'],
            1024 // 1KB limit
        );

        $file = [
            'name' => 'test.jpg',
            'type' => 'image/jpeg',
            'tmp_name' => '/tmp/test.jpg',
            'error' => UPLOAD_ERR_OK,
            'size' => 2048, // 2KB - over limit
        ];

        $result = $uploader->handle($file, 'upload_action');

        $this->assertInstanceOf(\WP_Error::class, $result);
        $this->assertSame('file_too_large', $result->get_error_code());
    }

    public function testHandleRejectsInvalidNonce(): void
    {
        $nonce = $this->createMock(Nonce::class);
        $nonce->method('verify')->willReturn(false);

        $uploader = new UploadSecurity(
            $this->context,
            $nonce,
            $this->gate
        );

        $file = [
            'name' => 'test.jpg',
            'type' => 'image/jpeg',
            'tmp_name' => '/tmp/test.jpg',
            'error' => UPLOAD_ERR_OK,
            'size' => 1024,
        ];

        $result = $uploader->handle($file, 'upload_action');

        $this->assertInstanceOf(\WP_Error::class, $result);
        $this->assertSame('nonce_failed', $result->get_error_code());
    }

    public function testMaxSizeCanBeChanged(): void
    {
        $this->uploader->maxSize(10485760); // 10MB

        // Verify the object is returned for chaining
        $this->assertInstanceOf(UploadSecurity::class, $this->uploader);
    }

    public function testAllowMimesCanBeChanged(): void
    {
        $result = $this->uploader->allowMimes(['pdf' => 'application/pdf']);

        $this->assertInstanceOf(UploadSecurity::class, $result);
    }
}
