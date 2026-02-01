<?php

declare(strict_types=1);

namespace WPZylos\Framework\Security;

use WPZylos\Framework\Core\Contracts\ContextInterface;

/**
 * Secure file upload handler.
 *
 * Wraps WordPress upload functions with nonce verification,
 * capability checks, and file type validation.
 *
 * @package WPZylos\Framework\Security
 */
class UploadSecurity
{
    /**
     * @var ContextInterface Plugin context
     */
    private ContextInterface $context;

    /**
     * @var Nonce Nonce manager
     */
    private Nonce $nonce;

    /**
     * @var Gate Capability gate
     */
    private Gate $gate;

    /**
     * @var array<string, string> Allowed MIME types
     */
    private array $allowedMimes;

    /**
     * @var int Maximum file size in bytes
     */
    private int $maxSize;

    /**
     * Create upload security handler.
     *
     * @param ContextInterface $context Plugin context
     * @param Nonce $nonce Nonce manager
     * @param Gate $gate Capability gate
     * @param array<string, string> $allowedMimes Allowed MIME types
     * @param int $maxSize Maximum file size (default: 5MB)
     */
    public function __construct(
        ContextInterface $context,
        Nonce $nonce,
        Gate $gate,
        array $allowedMimes = [],
        int $maxSize = 5242880
    ) {
        $this->context = $context;
        $this->nonce = $nonce;
        $this->gate = $gate;
        $this->allowedMimes = $allowedMimes ?: $this->defaultMimes();
        $this->maxSize = $maxSize;
    }

    /**
     * Handle a file upload securely.
     *
     * @param array{name: string, type: string, tmp_name: string, error: int, size: int} $file $_FILES array entry
     * @param string $nonceAction Nonce action name
     * @param string $capability Required capability (default: upload_files)
     * @return array{file: string, url: string, type: string}|\WP_Error Upload result or error
     */
    public function handle(
        array $file,
        string $nonceAction,
        string $capability = 'upload_files'
    ): array|\WP_Error {
        // Verify nonce
        $nonceValue = $_POST['_wpnonce'] ?? $_REQUEST['_wpnonce'] ?? '';
        if (!$this->nonce->verify($nonceValue, $nonceAction)) {
            return new \WP_Error(
                'nonce_failed',
                __('Security verification failed. Please refresh and try again.', $this->context->textDomain())
            );
        }

        // Verify capability
        if (!$this->gate->can($capability)) {
            return new \WP_Error(
                'permission_denied',
                __('You do not have permission to upload files.', $this->context->textDomain())
            );
        }


        // Check for upload errors
        if ($file['error'] !== UPLOAD_ERR_OK) {
            return new \WP_Error(
                'upload_error',
                $this->getUploadErrorMessage($file['error'])
            );
        }

        // Validate file size
        if ($file['size'] > $this->maxSize) {
            return new \WP_Error(
                'file_too_large',
                sprintf(
                    /* translators: %s: Maximum file size */
                    __('File exceeds maximum size of %s.', $this->context->textDomain()),
                    size_format($this->maxSize)
                )
            );
        }

        // Validate file type using WordPress
        $validated = wp_check_filetype_and_ext(
            $file['tmp_name'],
            $file['name'],
            $this->allowedMimes
        );

        if (!$validated['ext'] || !$validated['type']) {
            return new \WP_Error(
                'invalid_type',
                __('File type is not allowed.', $this->context->textDomain())
            );
        }

        // Additional security: check real MIME type
        if (function_exists('finfo_file')) {
            $finfo = finfo_open(FILEINFO_MIME_TYPE);
            $realMime = finfo_file($finfo, $file['tmp_name']);
            finfo_close($finfo);

            if (!in_array($realMime, $this->allowedMimes, true)) {
                return new \WP_Error(
                    'mime_mismatch',
                    __('File content does not match its extension.', $this->context->textDomain())
                );
            }
        }

        // Handle the upload
        $overrides = [
            'test_form' => false,
            'mimes' => $this->allowedMimes,
            'unique_filename_callback' => [$this, 'generateFilename'],
        ];

        $result = wp_handle_upload($file, $overrides);

        if (isset($result['error'])) {
            return new \WP_Error('upload_failed', $result['error']);
        }

        return $result;
    }

    /**
     * Handle multiple file uploads.
     *
     * @param array $files $_FILES array with multiple files
     * @param string $nonceAction Nonce action name
     * @param string $capability Required capability
     * @return array<int, array|\WP_Error> Array of results
     */
    public function handleMultiple(
        array $files,
        string $nonceAction,
        string $capability = 'upload_files'
    ): array {
        $results = [];

        // Normalize $_FILES array structure
        $normalized = $this->normalizeFilesArray($files);

        foreach ($normalized as $file) {
            $results[] = $this->handle($file, $nonceAction, $capability);
        }

        return $results;
    }

    /**
     * Set allowed MIME types.
     *
     * @param array<string, string> $mimes Extension => MIME type map
     * @return static
     */
    public function allowMimes(array $mimes): static
    {
        $this->allowedMimes = $mimes;
        return $this;
    }

    /**
     * Set maximum file size.
     *
     * @param int $bytes Maximum size in bytes
     * @return static
     */
    public function maxSize(int $bytes): static
    {
        $this->maxSize = $bytes;
        return $this;
    }

    /**
     * Generate unique filename.
     *
     * @param string $dir Upload directory
     * @param string $name Original filename
     * @param string $ext File extension
     * @return string Unique filename
     */
    public function generateFilename(string $dir, string $name, string $ext): string
    {
        $name = sanitize_file_name($name);
        $unique = wp_unique_filename($dir, $name . $ext);
        return $unique;
    }

    /**
     * Get default allowed MIME types.
     *
     * @return array<string, string>
     */
    private function defaultMimes(): array
    {
        return [
            'jpg|jpeg|jpe' => 'image/jpeg',
            'gif' => 'image/gif',
            'png' => 'image/png',
            'webp' => 'image/webp',
            'pdf' => 'application/pdf',
            'doc' => 'application/msword',
            'docx' => 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
        ];
    }

    /**
     * Get human-readable upload error message.
     *
     * @param int $error PHP upload error code
     * @return string Translated error message
     */
    private function getUploadErrorMessage(int $error): string
    {
        $messages = [
            UPLOAD_ERR_INI_SIZE => __('File exceeds server upload limit.', $this->context->textDomain()),
            UPLOAD_ERR_FORM_SIZE => __('File exceeds form upload limit.', $this->context->textDomain()),
            UPLOAD_ERR_PARTIAL => __('File was only partially uploaded.', $this->context->textDomain()),
            UPLOAD_ERR_NO_FILE => __('No file was uploaded.', $this->context->textDomain()),
            UPLOAD_ERR_NO_TMP_DIR => __('Missing temporary folder.', $this->context->textDomain()),
            UPLOAD_ERR_CANT_WRITE => __('Failed to write file to disk.', $this->context->textDomain()),
            UPLOAD_ERR_EXTENSION => __('A PHP extension stopped the upload.', $this->context->textDomain()),
        ];

        return $messages[$error] ?? __('Unknown upload error.', $this->context->textDomain());
    }

    /**
     * Normalize $_FILES array for multiple uploads.
     *
     * @param array $files Raw $_FILES array
     * @return array Normalized file arrays
     */
    private function normalizeFilesArray(array $files): array
    {
        $normalized = [];

        // Check if this is a standard $_FILES structure for multiple files
        if (isset($files['name']) && is_array($files['name'])) {
            $count = count($files['name']);
            for ($i = 0; $i < $count; $i++) {
                $normalized[] = [
                    'name' => $files['name'][$i],
                    'type' => $files['type'][$i],
                    'tmp_name' => $files['tmp_name'][$i],
                    'error' => $files['error'][$i],
                    'size' => $files['size'][$i],
                ];
            }
        } else {
            // Already normalized or single file
            $normalized[] = $files;
        }

        return $normalized;
    }
}
