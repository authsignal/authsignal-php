<img width="1070" alt="Authsignal" src="https://raw.githubusercontent.com/authsignal/authsignal-php/main/.github/images/authsignal.png">

# Authsignal PHP SDK

[![License](https://img.shields.io/packagist/l/authsignal/authsignal-php.svg)](https://github.com/authsignal/authsignal-php/blob/main/LICENSE)

The official Authsignal PHP library for server-side applications. Use this SDK to easily integrate Authsignal's multi-factor authentication (MFA) and passwordless features into your PHP backend.

## Installation

Using Composer:
```bash
composer require authsignal/authsignal-php
```

## Getting Started

Initialize the Authsignal client with your secret key from the [Authsignal Portal](https://portal.authsignal.com/) and the API URL for your region.

```php
use Authsignal;

// Initialize the client
Authsignal::setApiSecretKey(getenv('AUTHSIGNAL_SECRET_KEY'));
Authsignal::setApiUrl(getenv('AUTHSIGNAL_API_URL')); // Use region-specific URL
```

### API URLs by Region

| Region      | API URL                          |
| ----------- | -------------------------------- |
| US (Oregon) | https://api.authsignal.com/v1    |
| AU (Sydney) | https://au.api.authsignal.com/v1 |
| EU (Dublin) | https://eu.api.authsignal.com/v1 |

## License

This SDK is licensed under the [MIT License](LICENSE).

## Documentation

For more information and advanced usage examples, refer to the official [Authsignal Server-Side SDK documentation](https://docs.authsignal.com/sdks/server/overview).
