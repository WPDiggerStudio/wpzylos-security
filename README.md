# WPZylos Security

[![PHP Version](https://img.shields.io/badge/php-%5E8.0-blue)](https://php.net)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![GitHub](https://img.shields.io/badge/GitHub-WPDiggerStudio-181717?logo=github)](https://github.com/WPDiggerStudio/wpzylos-security)

Security primitives (Nonce, Gate, Sanitizer, Escaper) for WPZylos framework.

📖 **[Full Documentation](https://wpzylos.com)** | 🐛 **[Report Issues](https://github.com/WPDiggerStudio/wpzylos-security/issues)**

---

## ✨ Features

- **Nonce** — WordPress nonce generation and verification
- **Gate** — Capability-based authorization
- **Sanitizer** — Input sanitization helpers
- **Escaper** — Output escaping helpers
- **CSRF Protection** — Cross-site request forgery prevention

---

## 📋 Requirements

| Requirement | Version |
| ----------- | ------- |
| PHP         | ^8.0    |
| WordPress   | 6.0+    |

---

## 🚀 Installation

```bash
composer require wpdiggerstudio/wpzylos-security
```

---

## 📖 Quick Start

```php
use WPZylos\Framework\Security\Nonce;
use WPZylos\Framework\Security\Gate;

// Nonce handling
$nonce = Nonce::create('my_action');
if (Nonce::verify($_POST['nonce'], 'my_action')) {
    // Valid nonce
}

// Authorization
if (Gate::allows('edit_posts')) {
    // User can edit posts
}
```

---

## 🏗️ Core Features

### Nonce Management

```php
use WPZylos\Framework\Security\Nonce;

// Create nonce
$nonce = Nonce::create('save_settings');

// Create nonce field
echo Nonce::field('save_settings');

// Verify nonce
if (Nonce::verify($_POST['_wpnonce'], 'save_settings')) {
    // Valid
}
```

### Authorization Gate

```php
use WPZylos\Framework\Security\Gate;

// Check capability
if (Gate::allows('manage_options')) {
    // Admin only
}

// Deny access
if (Gate::denies('edit_posts')) {
    wp_die('Unauthorized');
}

// Check with post ID
if (Gate::allows('edit_post', $post_id)) {
    // Can edit specific post
}
```

### Input Sanitization

```php
use WPZylos\Framework\Security\Sanitizer;

$email = Sanitizer::email($_POST['email']);
$title = Sanitizer::text($_POST['title']);
$content = Sanitizer::html($_POST['content']);
$url = Sanitizer::url($_POST['url']);
```

### Output Escaping

```php
use WPZylos\Framework\Security\Escaper;

echo Escaper::html($userInput);
echo Escaper::attr($attribute);
echo Escaper::url($url);
echo Escaper::js($jsString);
```

---

## 📦 Related Packages

| Package                                                                    | Description            |
| -------------------------------------------------------------------------- | ---------------------- |
| [wpzylos-core](https://github.com/WPDiggerStudio/wpzylos-core)             | Application foundation |
| [wpzylos-validation](https://github.com/WPDiggerStudio/wpzylos-validation) | Input validation       |
| [wpzylos-scaffold](https://github.com/WPDiggerStudio/wpzylos-scaffold)     | Plugin template        |

---

## 📖 Documentation

For comprehensive documentation, tutorials, and API reference, visit **[wpzylos.com](https://wpzylos.com)**.

---

## ☕ Support the Project

If you find this package helpful, consider buying me a coffee! Your support helps maintain and improve the WPZylos ecosystem.

<a href="https://www.paypal.com/donate/?hosted_button_id=66U4L3HG4TLCC" target="_blank">
  <img src="https://img.shields.io/badge/Donate-PayPal-blue.svg?style=for-the-badge&logo=paypal" alt="Donate with PayPal" />
</a>

---

## 📄 License

MIT License. See [LICENSE](LICENSE) for details.

---

## 🤝 Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

---

**Made with ❤️ by [WPDiggerStudio](https://github.com/WPDiggerStudio)**
