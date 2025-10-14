<img width="1070" alt="Authsignal" src="https://raw.githubusercontent.com/authsignal/authsignal-php/main/.github/images/authsignal.png">

# Authsignal Server PHP SDK

The official Authsignal PHP library for server-side applications. Use this SDK to easily integrate Authsignal's multi-factor authentication (MFA) and passwordless features into your PHP backend.

## Installation

1. Add Authsignal's library to your project using Composer:

   ```bash
   composer require authsignal/authsignal-php
   ```

2. Run `composer update` to install the dependencies.
3. Authsignal will now be autoloaded into your project.

## Initialization

Initialize the Authsignal SDK, ensuring you do not hard code the Authsignal Secret Key, always keep this safe.

```php
Authsignal::setApiSecretKey('secretKey');
```

You can find your `secretKey` in the [Authsignal Portal](https://portal.authsignal.com/organisations/tenants/api).

## Region selection

Authsignal has multiple api hosting regions. To view your hostname for your tenant, find it in the [Authsignal Portal](https://portal.authsignal.com/organisations/tenants/api).

| Region      | Base URL                            |
| ----------- | ----------------------------------- |
| US (Oregon) | https://signal.authsignal.com/v1    |
| AU (Sydney) | https://au.signal.authsignal.com/v1 |
| EU (Dublin) | https://eu.signal.authsignal.com/v1 |

You can set the hostname via the following code. If the `setApiUrl` function is not called, the api call defaults to the main Authsignal US region hostname `https://signal.authsignal.com`

An example setting the client to use the AU region.

```php
Authsignal::setApiUrl("https://au.signal.authsignal.com/v1");
```

Alternatively, an environment variable can be used to set the API URL:

```bash
AUTHSIGNAL_API_URL=https://au.signal.authsignal.com/v1
```

## Usage

Authsignal's server side signal API has five main calls `track`, `getAction`, `getUser`, `enrollVerifiedAuthenticator`, `verifyChallenge`

For more details on these api calls, refer to our [official PHP SDK docs](https://docs.authsignal.com/sdks/server/php#trackaction).

### Response & Error handling

Example:

```php
$result = Authsignal::updateAction(
   userId: $userId,
   action: $action,
   idempotencyKey: "invalidKey",
   attributes: ['state' => 'CHALLENGE_FAILED']
);

# PHP Fatal error: Uncaught AuthsignalNotFoundError: 404 - not_found
```

## License

The library is available as open source under the terms of the [MIT License](https://opensource.org/licenses/MIT).

## Documentation

For more information and advanced usage examples, refer to the official [Authsignal Server-Side SDK documentation](https://docs.authsignal.com/sdks/server/overview).